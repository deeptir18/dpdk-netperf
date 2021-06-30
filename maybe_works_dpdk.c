/*
 * Credit: This code is derived from Gerry Wan's. The original code
 * can be found here: https://github.com/thegwan/rx-skeleton/tree/896dbcd016fecf8056f29f8b18f8ad8b3c690e42/c/count-dpdk
 * 
 * This is a multithreaded DPDK server that counts the number of packets received. 
 */


#include <signal.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_timer.h>
#include <rte_lcore.h>

#define PORT_ID 0
#define CAPACITY 65535
#define CACHE_SIZE 512
#define NB_RX_DESC 4096
#define NB_TX_DESC 4096
#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define BURST_SIZE 32
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define MBUF_BUF_SIZE RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM
#define NUM_MBUFS 8191

static volatile bool force_quit;
struct rte_mempool *mbufpool;
static int zero_copy_mode = 0;
static void *payload_to_copy = NULL;
struct rte_mempool *mbuf_pool;

enum {
    MEM_DPDK = 0,
    MEM_EXT,
    MEM_EXT_MANUAL,
    MEM_EXT_MANUAL_DPDK
};

struct tx_pktmbuf_priv
{
    int32_t lkey;
    int32_t field2; // needs to be atleast 8 bytes large
};

const struct rte_ether_addr ether_broadcast = {
    .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

uint8_t sym_rss_key[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,  // 1518 
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = sym_rss_key,
            .rss_key_len = 40,
            .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
        },
    },
};

uint32_t
wrapsum(uint32_t sum)
{
	sum = ~sum & 0xFFFF;
	return htons(sum);
}

uint32_t
checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum)
{
	unsigned int	 i;

	/* Checksum all the pairs of bytes first. */
	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < nbytes) {
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Signal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static void mbufpool_init()
{
    char name[16];
    snprintf(name, sizeof(name), "mbufpool0");
    mbufpool = rte_pktmbuf_pool_create(name,
        CAPACITY, CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);

    if (mbufpool == NULL)
        rte_exit(EXIT_FAILURE, "Failed to create mbufpool.\n");
}

static void port_init()
{
    int ret;
    int lcore_id, q;
    int nb_workers = rte_lcore_count() - 1;

//    port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;

    // 1 queue per core
    ret = rte_eth_dev_configure(PORT_ID, nb_workers, nb_workers, &port_conf);
    if (ret < 0) 
        rte_exit(EXIT_FAILURE, "Port configuration failed.\n");

    // Set up receiving queues
    q = 0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eth_rx_queue_setup(PORT_ID, q, NB_RX_DESC, 
            rte_eth_dev_socket_id(PORT_ID), NULL, mbufpool);
        q++;
    }
     
    // Set up transmitting queues
    q = 0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eth_tx_queue_setup(PORT_ID, q, NB_TX_DESC, 
            rte_eth_dev_socket_id(PORT_ID), NULL);
        q++;
    }     
}

static int parse_packet(struct sockaddr_in *src,
                        struct sockaddr_in *dst,
                        void **payload,
                        size_t *payload_len,
                        struct rte_mbuf *pkt)
{
    // packet layout order is (from outside -> in):
    // ether_hdr
    // ipv4_hdr
    // udp_hdr
    // client timestamp
    uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    struct rte_ether_hdr * const eth_hdr = (struct rte_ether_hdr *)(p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    struct rte_ether_addr mac_addr = {};

    rte_eth_macaddr_get(PORT_ID, &mac_addr);
    if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->d_addr)
        && !rte_is_same_ether_addr(&ether_broadcast, &eth_hdr->d_addr)) {
        printf("Bad MAC NOT SAME MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1],
			eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes[3],
			eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);
        printf("Bad MAC NOT SAME MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1],
			eth_hdr->s_addr.addr_bytes[2], eth_hdr->s_addr.addr_bytes[3],
			eth_hdr->s_addr.addr_bytes[4], eth_hdr->s_addr.addr_bytes[5]);
        printf("Reference MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
			mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
			mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
            // printf("Bad MAC NOT SAME MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			//    " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            // mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
			// mac_addr[4], mac_addr[5]);
        return 1;
    }
    printf("[rte_eth_tx_burst_] Src MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1],
            eth_hdr->s_addr.addr_bytes[2], eth_hdr->s_addr.addr_bytes[3],
            eth_hdr->s_addr.addr_bytes[4], eth_hdr->s_addr.addr_bytes[5]);
    if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        printf("Bad ether type");
        return 1;
    }

    // check the IP header
    struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *)(p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    // In network byte order.
    in_addr_t ipv4_src_addr = ip_hdr->src_addr;
    in_addr_t ipv4_dst_addr = ip_hdr->dst_addr;

    if (IPPROTO_UDP != ip_hdr->next_proto_id) {
        printf("Bad next proto_id\n");
        return 1;
    }
    
    src->sin_addr.s_addr = ipv4_src_addr;
    dst->sin_addr.s_addr = ipv4_dst_addr;

    // check udp header
    struct rte_udp_hdr * const udp_hdr = (struct rte_udp_hdr *)(p);
    p += sizeof(*udp_hdr);
    header += sizeof(*udp_hdr);

    // In network byte order.
    in_port_t udp_src_port = udp_hdr->src_port;
    in_port_t udp_dst_port = udp_hdr->dst_port;

    src->sin_port = udp_src_port;
    dst->sin_port = udp_dst_port;
    src->sin_family = AF_INET;
    dst->sin_family = AF_INET;
    
    *payload_len = pkt->pkt_len - header;
    *payload = (void *)p;

    printf("End of parse packets!\n");
    return 0;
}

static inline struct tx_pktmbuf_priv *tx_pktmbuf_get_priv(struct rte_mbuf *buf)
{
	return (struct tx_pktmbuf_priv *)(((char *)buf)
			+ sizeof(struct rte_mbuf));
}

/* Individually count number of 
   received packets, immediately 
   free rte_mbuf */
static int recv_thread()
{
    printf("Receive thread!\n");
    uint16_t nb_rx, n_to_tx, nb_tx, i, q;
    int lcore_id = rte_lcore_id();
    
    q = lcore_id - 1;
    printf("Starting RX from core %u (queue %u)...\n", lcore_id, q);

    uint64_t total = 0;
    struct rte_mbuf *rx_bufs[BURST_SIZE];
    struct rte_mbuf *tx_bufs[BURST_SIZE];
    struct rte_mbuf *secondary_tx_bufs[BURST_SIZE];
    struct rte_mbuf *rx_buf;
    struct rte_ether_hdr *rx_ptr_mac_hdr;
    struct rte_ether_hdr *tx_ptr_mac_hdr;
    struct rte_ipv4_hdr *rx_ptr_ipv4_hdr;
    struct rte_ipv4_hdr *tx_ptr_ipv4_hdr;
    struct rte_udp_hdr *rx_rte_udp_hdr;
    struct rte_udp_hdr *tx_rte_udp_hdr;
    uint64_t *tx_buf_id_ptr;
    uint64_t *rx_buf_id_ptr;
    while (!force_quit) {
        n_to_tx = 0;
        nb_rx = rte_eth_rx_burst(PORT_ID, q, rx_bufs, BURST_SIZE);
        for (i = 0; i < nb_rx; i++) {
            struct sockaddr_in src, dst;
            void *payload = NULL;
            size_t payload_length = 0;
            int valid = parse_packet(&src, &dst, &payload, &payload_length, rx_bufs[i]);
            /*rte_mbuf: A type describing a particular segment of the scattered packet*/
            struct rte_mbuf* secondary = NULL;
            if (valid == 0) {
                rx_buf = rx_bufs[i];
                size_t header_size = rx_buf->pkt_len - (payload_length);
                payload_length -= 8;
                header_size += 8;
                // echo the packet back
                // normal DPDK memory
                tx_bufs[n_to_tx] = rte_pktmbuf_alloc(mbuf_pool);
                char *pkt_buf = (char *)(rte_pktmbuf_mtod_offset(tx_bufs[n_to_tx], char *, sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN + 8));
                rte_memcpy(pkt_buf, (char *)(payload_to_copy), payload_length);
                struct rte_mbuf* tx_buf = tx_bufs[n_to_tx];
                secondary = secondary_tx_bufs[n_to_tx];
                if (tx_buf == NULL) {
                    printf("Error first allocating tx mbuf\n");
                    return -EINVAL;
                }
                /* swap src and dst ether addresses */
                rx_ptr_mac_hdr = rte_pktmbuf_mtod(rx_buf, struct rte_ether_hdr *);
                tx_ptr_mac_hdr = rte_pktmbuf_mtod(tx_buf, struct rte_ether_hdr *);
                rte_ether_addr_copy(&rx_ptr_mac_hdr->s_addr, &tx_ptr_mac_hdr->d_addr);
                rte_ether_addr_copy(&rx_ptr_mac_hdr->d_addr, &tx_ptr_mac_hdr->s_addr);
                // rte_ether_addr_copy(&src_addr, &ptr_mac_hdr->d_addr);
                tx_ptr_mac_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

                /* swap src and dst ip addresses */
                //src_ip_addr = rx_ptr_ipv4_hdr->src_addr;
                rx_ptr_ipv4_hdr = rte_pktmbuf_mtod_offset(rx_buf, struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
                tx_ptr_ipv4_hdr = rte_pktmbuf_mtod_offset(tx_buf, struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
                tx_ptr_ipv4_hdr->src_addr = rx_ptr_ipv4_hdr->dst_addr;
                tx_ptr_ipv4_hdr->dst_addr = rx_ptr_ipv4_hdr->src_addr;

                uint32_t ipv4_checksum = wrapsum(checksum((unsigned char *)tx_ptr_ipv4_hdr, sizeof(struct rte_ipv4_hdr), 0));
                printf("Checksum is %u\n", (unsigned)ipv4_checksum);
                tx_ptr_ipv4_hdr->hdr_checksum = ipv4_checksum;
                tx_ptr_ipv4_hdr->version_ihl = IP_VHL_DEF;
                tx_ptr_ipv4_hdr->type_of_service = 0;
                tx_ptr_ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload_length);
                tx_ptr_ipv4_hdr->packet_id = 0;
                tx_ptr_ipv4_hdr->fragment_offset = 0;
                tx_ptr_ipv4_hdr->time_to_live = IP_DEFTTL;
                tx_ptr_ipv4_hdr->next_proto_id = IPPROTO_UDP;
                /* offload checksum computation in hardware */
                // tx_ptr_ipv4_hdr->hdr_checksum = 0;
                // printf("Segfault 5\n");
                /* Swap UDP ports */
                rx_rte_udp_hdr = rte_pktmbuf_mtod_offset(rx_buf, struct rte_udp_hdr *, RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr));
                tx_rte_udp_hdr = rte_pktmbuf_mtod_offset(tx_buf, struct rte_udp_hdr *, RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr));
                //tmp_port = rte_udp_hdr->src_port;
                tx_rte_udp_hdr->src_port = rx_rte_udp_hdr->dst_port;
                tx_rte_udp_hdr->dst_port = rx_rte_udp_hdr->src_port;
                tx_rte_udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_length);
                uint16_t udp_cksum =  rte_ipv4_udptcp_cksum(tx_ptr_ipv4_hdr, (void *)tx_rte_udp_hdr);
                printf("Udp checksum is %u\n", (unsigned)udp_cksum);
                tx_rte_udp_hdr->dgram_cksum = udp_cksum;

                /* Set packet id */
                tx_buf_id_ptr = rte_pktmbuf_mtod_offset(tx_buf, uint64_t *, sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN);
                rx_buf_id_ptr = rte_pktmbuf_mtod_offset(rx_buf, uint64_t *, sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN);
                *tx_buf_id_ptr = *rx_buf_id_ptr;

                /* Set metadata */
                tx_buf->l2_len = RTE_ETHER_HDR_LEN;
                tx_buf->l3_len = sizeof(struct rte_ipv4_hdr);
                tx_buf->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4;
                tx_buf->data_len = header_size + payload_length;
                tx_buf->pkt_len = header_size + payload_length;
                tx_buf->nb_segs = 1;
                n_to_tx++;
                printf("Segfault 6\n");
                rte_pktmbuf_free(rx_bufs[i]);
                total += 1;
                printf("Core %u total RX: %lu\n", lcore_id, total);
                continue;
            } else {
                rte_pktmbuf_free(rx_bufs[i]);
            }
        }
        if (n_to_tx > 0) {
            nb_tx = rte_eth_tx_burst(PORT_ID, q, tx_bufs, n_to_tx);
            if (nb_tx != n_to_tx && nb_tx != 0) {
                printf("error: %u queue could not transmit all %u pkts, transmitted %u\n", q, n_to_tx, nb_tx);
                n_to_tx -= nb_tx;
            }
        }
        // }
    }
}

static int
lcore_launch(__rte_unused void *arg)
{
    printf("Hello core %d! We are about to receive a thread!\n", rte_lcore_id());
    recv_thread();
    return 0;
}

static int main_thread()
{
    printf("In main_thread!\n");
}

static void disp_eth_stats(void) 
{
    struct rte_eth_stats eth_stats;
    uint16_t q, port_id;
    int ret;
    
    memset(&eth_stats, 0, sizeof(eth_stats));
    ret = rte_eth_stats_get(port_id, &eth_stats);
    uint64_t total, sent_total = 0;
    if (!ret) {
        total += (eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors);
        sent_total += (eth_stats.opackets - eth_stats.oerrors);
        printf("\tTotal packets received by port (sum): %lu\n", total);
        printf("\tTotal packets sent by port (sum): %lu\n", sent_total);
        printf("\tSuccessfully received packets: %lu\n", eth_stats.ipackets);
        printf("\tSuccessfully transmitted packets: %lu\n", eth_stats.opackets);
        printf("\tPackets dropped by HW due to RX queue full: %lu\n", eth_stats.imissed);
        printf("\tError packets (received): %lu\n", eth_stats.ierrors);
        printf("\tError packets (transmitted): %lu\n", eth_stats.oerrors);
        printf("\tNum RX mbuf allocation failures: %lu\n", eth_stats.rx_nombuf);

        for (q = 0; q < rte_lcore_count() - 1; q++) {
            printf("\tQueue %u successfully received packets: %lu\n", q, eth_stats.q_ipackets[q]);
            printf("\tQueue %u successfully transmitted packets: %lu\n", q, eth_stats.q_opackets[q]);
            printf("\tQueue %u packets dropped by HW: %lu\n", q, eth_stats.q_errors[q]);
        }
    }
    printf("Capture rate: %lf\n", (float)eth_stats.ipackets / total);
}

/* 
 * Single socket, single port
 * Immediately free mbuf upon receive, count number of successfully received
 */
int main(int argc, char **argv)
{
    int ret, i;
    uint16_t nb_ports;
    uint16_t port_id = 0;
    

    printf("C rx-skeleton\n");

    struct sigaction sa;

    printf("Initializing EAL...\n");
    rte_eal_init(argc, argv);

    argc -= ret;
    argv += ret;

    force_quit = false;
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No available ports found.\n");

    if (nb_ports != 1)
        printf("INFO: %u ports detected, only using port %u\n", nb_ports, PORT_ID);

    printf("Initializing mbufpool on socket 0...\n");
    mbufpool_init();

    printf("Initializing port 0...\n");
    port_init();

    ret = rte_eth_promiscuous_enable(PORT_ID);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to set promiscuous.\n");

    printf("Starting port 0...\n");
    rte_eth_dev_start(PORT_ID);
    mbuf_pool = rte_pktmbuf_pool_create(
                                "mbuf_pool",
                                NUM_MBUFS * nb_ports,
                                CACHE_SIZE,
                                sizeof(struct tx_pktmbuf_priv),
                                MBUF_BUF_SIZE,
                                rte_socket_id());
    payload_to_copy = malloc(8000);
    memset(payload_to_copy, 'E', 8000);
    if (payload_to_copy == NULL) {
        printf("Could not initialize payload to copy\n.");
        return 1;
    }
    rte_eal_mp_remote_launch(lcore_launch, NULL, SKIP_MASTER);
    main_thread();
    rte_eal_mp_wait_lcore();

    disp_eth_stats();

    printf("Stopping port 0...\n");
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID); 

    return 0;
}
