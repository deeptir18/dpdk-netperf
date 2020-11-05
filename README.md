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

## Running the server:
The server command line should look something like:
```
sudo build/netperf <DPDK_EAL_INIT> -- --mode=SERVER --ip=<server_ip>
```
Here is an example (and the command line we have been using):
``` 
sudo build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=SERVER --ip=198.19.200.1
```

## Running the client:
The client command line should look something like:
```
sudo build/netperf <DPDK_EAL_INIT> -- --mode=CLIENT --ip=<client_ip> -- server_ip=<server_ip> --server_mac=<server_mac> --port=<port> --message_size=<message_size> --time=<time_in_seconds> --rate=<rate_in_pkts_per_s>
```
Here is an example
```
sudo build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=CLIENT -server_ip=198.19.200.1 --ip=198.19.200.2 --server_mac=b2:43:65:89:af:40 --rate=50000
```

## Issues:
I expect that when the client is pinging the server at low load, the average and median latency of the client should be in the range of 5-7 us (for example, for a 1000 byte message, at rate=5000 packets per second). However, I see latencies of ~50 to ~200 to even ~2000 us. The only fix (which brings latency back to the range of 5-7 us) is if, both at the client and the server, I set the MLX5_SHUT_UP_BF flag:
```
# server:
sudo MLX5_SHUT_UP_BF='1' build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=SERVER --ip=198.19.200.1

#client:
sudo MLX5_SHUT_UP_BF='1' build/netperf -c 0xff -n 4 -w 0000:37:00.0 --proc-type=auto -- --mode=CLIENT -server_ip=198.19.200.1 --ip=198.19.200.2 --server_mac=b2:43:65:89:af:40 --rate=50000
```

### Questions:
1. Why do we see such bad performance at low load? Is there anything wrong with our configuration or code?
2. WHy does setting this flag make such a difference? We've read the docs and understand that this flag causes the doorbell register to be write combining or not, and setting it makes the configuration more latency optimized, but does it make such a big difference?


