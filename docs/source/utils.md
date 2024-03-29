# Utility applications

## Introduction

hicn-ping-server, hicn-ping-client and hiperf are three utility applications
for testing and benchmarking stack.

## Using hICN utils applications

### Dependencies

Build dependencies:

- C++14 (clang++ / g++)
- CMake 3.4

Basic dependencies:

- OpenSSL
- pthreads
- libevent
- libhicntransport

## Executables

The utility applications are a set of binary executables consisting of a
client/server ping applications (hicn-ping-server and hicn-ping-client) and
a hicn implementation of iPerf (hiperf).

### hicn-ping-server

The command `hicn-ping-server` runs the server side ping application.
`hicn-ping-server` can be executed with the following options:

```bash
usage: hicn-ping-server [options]

Options:
-s <content_size>           = object content size (default 1350B)
-n <hicn_name>              = hicn name (default b001::/64)
-f                          = set tcp flags according to the flag received (default false)
-l <lifetime>               = data lifetime
-r                          = always reply with a reset flag (default false)
-t <ttl>                    = set ttl (default 64)
-d                          = daemon mode
-H                          = help
```

Example:

```bash
hicn-ping-server -n c001::/64
```

### hicn-ping-client

The command `hicn-ping-client` runs the client side ping application.
`hicn-ping-client` can be executed with the following options:

```bash
usage: hicn-ping-client [options]

Options:
-i <ping_interval>          = ping interval in microseconds (default 1000000ms)
-m <max_pings>              = maximum number of pings to send (default 10)
-s <source_port>            = source port (default 9695)
-d <destination_port>       = destination port (default 8080)
-t <ttl>                    = set packet ttl (default 64)
-O                          = open tcp connection (three way handshake) (default false)
-S                          = send always syn messages (default false)
-A                          = send always ack messages (default false)
-n <hicn_name>              = hicn name (default b001::1)
-l <lifetime>               = interest lifetime in milliseconds (default 500ms)
-H                          = help
```

Example:
```
hicn-ping-client -n c001::1
```

### hiperf

The command `hiperf` is a tool for performing network throughput measurements
with hicn. It can be executed as server or client using the following options:

```bash
HIPERF - Instrumentation tool for performing active networkmeasurements with hICN
usage: hiperf [-S|-C] [options] [prefix|name]

SERVER OR CLIENT:
-D                                      Run as a daemon
-R                                      Run RTC protocol (client or server)
-f      <filename>                      Log file
-z      <io_module>                     IO module to use. Default: hicnlightng_module
-F      <conf_file>                     Path to optional configuration file for libtransport
-a                                      Enables data packet aggregation. Works only in RTC mode
-X      <param>                         Set FEC params. Options are Rely_K#_N# or RS_K#_N#

SERVER SPECIFIC:
-A      <content_size>                  Sends an application data unit in bytes that is published once before exit
-s      <packet_size>                   Data packet payload size.
-r                                      Produce real content of <content_size> bytes
-m      <manifest_capacity>             Produce transport manifest
-l                                      Start producing content upon the reception of the first interest
-K      <keystore_path>                 Path of p12 file containing the crypto material used for signing packets
-k      <passphrase>                    String from which a 128-bit symmetric key will be derived for signing packets
-p      <password>                      Password for p12 keystore
-y      <hash_algorithm>                Use the selected hash algorithm for computing manifest digests (default: SHA256)
-x                                      Produces application data units of size <content_size> without resetting the name suffix to 0.
-B      <bitrate>                       RTC producer data bitrate, to be used with the -R option.
-I                                      Interactive mode, start/stop real time content production by pressing return. To be used with the -R option
-T      <filename>                      Trace based mode, hiperf takes as input a file with a trace. Each line of the file indicates the timestamp and the size of the packet to generate. To be used with the -R option. -B and -I will be ignored.
-E                                      Enable encrypted communication. Requires the path to a p12 file containing the crypto material used for the TLS handshake
-G      <port>                          Input stream from localhost at the specified port

CLIENT SPECIFIC:
-b      <beta_parameter>                RAAQM beta parameter
-d      <drop_factor_parameter>         RAAQM drop factor parameter
-L      <interest lifetime>             Set interest lifetime.
-u      <delay>                         Set max lifetime of unverified packets.
-M      <input_buffer_size>             Size of consumer input buffer. If 0, reassembly of packets will be disabled.
-W      <window_size>                   Use a fixed congestion window for retrieving the data.
-i      <stats_interval>                Show the statistics every <stats_interval> milliseconds.
-c      <certificate_path>              Path of the producer certificate to be used for verifying the origin of the packets received.
-k      <passphrase>                    String from which is derived the symmetric key used by the producer to sign packets and by the consumer to verify them.
-t                                      Test mode, check if the client is receiving the correct data. This is an RTC specific option, to be used with the -R (default: false)
-P                                      Prefix of the producer where to do the handshake
-j      <relay_name>                    Publish received content under the name relay_name.This is an RTC specific option, to be used with the -R (default: false)
-g      <port>                          Output stream to localhost at the specified port
-e      <strategy>                      Enance the network with a realiability strategy. Options 1: unreliable, 2: rtx only, 3: fec only, 4: delay based, 5: low rate, 6: low rate and best path 7: low rate and replication, 8: low rate and best path/replication(default: 2 = rtx only)
-H                                      Disable periodic print headers in stats report.
-n      <nb_iterations>                 Print the stats report <nb_iterations> times and exit.
                                        This option limits the duration of the run to <nb_iterations> * <stats_interval> milliseconds.
```

Example:
```
hiperf -S b001::/64
hiperf -C b001::
```

## Client/Server benchmarking using `hiperf`

### hicn-light-daemon

This tutorial will explain how to configure a simple client-server topology and
retrieve network measurements using the hiperf utility.

We consider this simple topology, consisting on two linux VM which are able to
communicate through an IP network (you can also use containers or physical
machines):

```
|client (10.0.0.1/24; 9001::1/64)|======|server (10.0.0.2/24; 9001::2/64)|
```

Install the hICN suite on two linux VM. This tutorial makes use of Ubuntu 18.04,
but it could easily be adapted to other platforms.
You can either install the hICN stack using binaries or compile the code. In
this tutorial we will build the code from source.

```bash
apt-get update && apt-get install -y curl
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
apt-get install -y git \
                   cmake \
                   build-essential \
                   libasio-dev \
                   libcurl4-openssl-dev \
                   --no-install-recommends
mkdir hicn-suite && cd hicn-suite
git clone https://github.com/FDio/hicn.git hicn-src
mkdir hicn-build && cd hicn-build
cmake ../hicn-src -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../hicn-install -DBUILD_APPS=ON
make -j4 install
export HICN_ROOT=${PWD}/../hicn-install
```

It should install the hICN suite under hicn-install.

#### hicn-light forwarder with UDP faces

##### Server configuration

Create a configuration file for the hicn-light forwarder. Here we are
configuring UDP faces.

```bash
server$ mkdir -p ${HICN_ROOT}/etc
server$ LOCAL_IP="10.0.0.1" # Put here the actual IPv4 of the local interface
server$ LOCAL_PORT="12345"
server$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener udp list0 ${LOCAL_IP} ${LOCAL_PORT}
EOF
```

Start the hicn-light forwarder:

```bash
server$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 0 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

We set the forwarder capacity to 0 because we want to measure the end-to-end
performance without retrieving any data packet from intermediate caches.

Run the [hiperf](#hiperf) server:

```bash
server$ ${HICN_ROOT}/bin/hiperf -S b001::/64
```

The hiperf server will register the prefix b001::/64 on the local forwarder and
will reply with pre-allocated data packet. In this test we won't consider
segmentation and reassembly cost.

##### Client configuration

Create a configuration file for the hicn-light forwarder at the client. Here we
are configuring UDP faces.

```bash
client$ mkdir -p ${HICN_ROOT}/etc
client$ LOCAL_IP="10.0.0.2" # Put here the actual IPv4 of the local interface
client$ LOCAL_PORT="12345"
client$ REMOTE_IP="10.0.0.1" # Put here the actual IPv4 of the remote interface
client$ REMOTE_PORT="12345"
client$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener udp list0 ${LOCAL_IP} ${LOCAL_PORT}
add connection udp conn0 ${REMOTE_IP} ${REMOTE_PORT} ${LOCAL_IP} ${LOCAL_PORT}
add route conn0 b001::/16 1
EOF
```

Run the hicn-light forwarder:

```bash
client$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

Run the [hiperf](#hiperf) client:

```bash
client$ ${HICN_ROOT}/bin/hiperf -C b001::1 -W 50
EOF
```

This will run the client with a fixed window of 50 interests.

#### hicn-light forwarder with hICN faces

For sending hICN packets directly over the network, using hicn faces, change
the configuration of the two forwarders and restart them.

#### Server

```bash
server$ mkdir -p ${HICN_ROOT}/etc
server$ LOCAL_IP="9001::1"
server$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener hicn lst 0::0
add punting lst b001::/16
add listener hicn list0 ${LOCAL_IP}
EOF
```

#### Client

```bash
client$ mkdir -p ${HICN_ROOT}/etc
client$ LOCAL_IP="9001::2"
client$ REMOTE_IP="9001::1"
client$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener hicn lst 0::0
add punting lst b001::/16
add listener hicn list0 ${LOCAL_IP}
add connection hicn conn0 ${REMOTE_IP} ${LOCAL_IP}
add route conn0 b001::/16 1
EOF
```

### VPP based hicn-plugin

In this example we will do a local hiperf client-server communication. First,
we need to compile the hicn stack and enable [VPP](https://github.com/FDio/vpp)
support:

```bash
apt-update && apt-get install -y curl
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
apt-get install -y git \
                   cmake \
                   build-essential \
                   libasio-dev \
                   vpp vpp-dev vpp-plugin-core libvppinfra \
                   libmemif libmemif-dev \
                   python3-ply \
                   --no-install-recommends
mkdir hicn-suite && cd hicn-suite
git clone https://github.com/FDio/hicn.git hicn-src
mkdir hicn-build && cd hicn-build
cmake ../hicn-src -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_APPS=ON -DBUILD_HICNPLUGIN=ON
sudo make -j 4 install
export HICN_ROOT=${PWD}/../hicn-install
```

Make sure vpp is running:

```bash
sudo systemctl restart vpp
```

Run the hicn-plugin:

```bash
vppctl hicn control start
```

Run hiperf server:

```bash
hiperf -S b001::/64
```

Run hiperf client:

```bash
hiperf -C b001::1 -W 300
```
