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

static volatile bool force_quit;
struct rte_mempool *mbufpool;

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

    port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;

    // 1 queue per core
    ret = rte_eth_dev_configure(PORT_ID, nb_workers, 0, &port_conf);
    if (ret < 0) 
        rte_exit(EXIT_FAILURE, "Port configuration failed.\n");

    q = 0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eth_rx_queue_setup(PORT_ID, q, NB_RX_DESC, 
            rte_eth_dev_socket_id(PORT_ID), NULL, mbufpool);
        q++;
    }
       
}

/* Individually count number of received packets, immediately free rte_mbuf */
static void recv_thread()
{
    struct rte_mbuf *mbufs[32];
    uint16_t i, q, nb_rx;
    int lcore_id = rte_lcore_id();
    
    q = lcore_id - 1;
    printf("Starting RX from core %u (queue %u)...\n", lcore_id, q);

    
    uint64_t total = 0;

    while (!force_quit) {
        nb_rx = rte_eth_rx_burst(PORT_ID, q, mbufs, 32);
        if (nb_rx != 0) printf("nb_rx = %d\n", nb_rx);
        for (i = 0; i < nb_rx; i++) {
            total += 1;
            rte_pktmbuf_free(mbufs[i]);
        }
    }

    printf("Core %u total RX: %lu\n", lcore_id, total);
    
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
    uint64_t total = 0;
    if (!ret) {
        total += (eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors);
        printf("\tTotal packets received by port (sum): %lu\n", total);
        printf("\tSuccessfully received packets: %lu\n", eth_stats.ipackets);
        printf("\tPackets dropped by HW due to RX queue full: %lu\n", eth_stats.imissed);
        printf("\tError packets: %lu\n", eth_stats.ierrors);
        printf("\tNum RX mbuf allocation failures: %lu\n", eth_stats.rx_nombuf);

        for (q = 0; q < rte_lcore_count() - 1; q++) {
            printf("\tQueue %u successfully received packets: %lu\n", q, eth_stats.q_ipackets[q]);
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

    rte_eal_mp_remote_launch(lcore_launch, NULL, SKIP_MASTER);
    main_thread();
    rte_eal_mp_wait_lcore();

    disp_eth_stats();

    printf("Stopping port 0...\n");
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID); 

    return 0;
}