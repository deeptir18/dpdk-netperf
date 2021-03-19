# Simple DPDK netperf application for Latency Benchmarks
Note that code is taken from both [Shenango's netperf
app](https://github.com/shenango/shenango/tree/master/apps/dpdk_netperf) and
[Demikernel's lwip stack](https://github.com/demikernel/demikernel).

## Compilation and setup:
1. Make sure DPDK is compiled. This application has been tested with DPDK
   version 19.08, and should be compatible with any 19 versions.
2. Similar to running the DPDK helloworld application, please define the RTE_SDK
   environment variable with the path to DPDK:
```
export RTE_SDK=/path/to/dpdk
```

3. Export the RTE_TARGET environment variable with the name of your target
   architecture. This has only been tested on an x86 64 bit target.
```
export RTE_TARGET=x86_64-native-linuxapp-gcc
```
4. Run `make` to compile the netperf application, which will be compiled to
   build/netperf.
5. Make sure huge pages are initialized; otherwise the application will fail.
6. Both the server and client must be run as root.
7. This currently depends on a patch to DPDK to try out manual memory
   registration. The patch is included in this repo.
8. I have also tried copy pasting this folder into the applications folder within a DPDK 20 repository (which uses ninja and meson for compilation), and with minimal changes, it will also work there.

## Running the server:
The server command line should look something like:
```
sudo build/netperf <DPDK_EAL_INIT> -- --mode=SERVER --ip=<server_ip> --memory=<DPDK,MANUAL,EXTERNAL,MANUAL_DPDK> --num_mbufs=<1,2> --zero-copy
```
Here is an example (and the command line we have been using) :
``` 
sudo build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=SERVER --ip=198.19.200.1 --memory=MANUAL --num_mbufs=2
```

Here is a breakdown of the different optional options:
```
--memory=<DPDK,MANUAL,EXTERNAL,MANUAL_DPDK>: What kind of memory to use in the
memory pools.
```
The default is DPDK.
1. DPDK is regular memory. Works with 1 or 2 buffers.
2. MANUAL is manually registered external memory (depends on a patch to DPDK 19 for mellanox), that has been registered with the NIC to avoid btree lookups for the lkey for a particular memory region. Works with only 2 buffers.
3. EXTERNAL is external memory that is externally registered for I/O with DPDK
   using the DPDK external memory buffer APIs. Works with 2 buffers.
4. MANUAL manually attaches memory (without the rte_pktmbuf_attach_extbuf api),
   to ANOTHER mbuf (to see whether the problem is with external vs. dpdk
allocated memory). Works with 2 buffers.
```
--num_mbufs=<1,2>
```
This specifies whether the NIC sends 1 buffer or a linked list of 2 buffers.
Not all memory modes work with 1 or 2 buffers.
```
--zero-copy
```
This is only relevant in the `--memory=DPDK` case, where it will pre-initialize
the payload in all of the mbufs, to avoid copying costs.


## Running the client:
The client command line should look something like:
```
sudo build/netperf <DPDK_EAL_INIT> -- --mode=CLIENT --ip=<client_ip> -- server_ip=<server_ip> --server_mac=<server_mac> --port=<port> --message_size=<message_size> --time=<time_in_seconds> --rate=<rate_in_pkts_per_s>
```
Here is an example
```
sudo build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=CLIENT -server_ip=198.19.200.1 --ip=198.19.200.2 --server_mac=b2:43:65:89:af:40 --rate=120000 --message_size=1024 --time=10
```

