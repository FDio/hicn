# Utility applications

## Introduction

hicn-ping-server, hicn-ping-client and hiperf are three utility applications for testing and benchmarking stack.

## Using hICN Utils applications

### Platforms

hicn-light has been tested in:

- Ubuntu 16.04 / 18.04 (x86_64)
- Debian Testing
- Centos 7
- MacOSX 10.12
- Android
- iOS

### Dependencies

Build dependencies:

- c++14 ( clang++ / g++ )
- CMake 3.4

Basic dependencies:

- ppenSSL
- pthreads
- libevent
- libparc
- libhicntransport

## Executables

The utility applications are a set of binary executables consisting of a client/server ping applications (hicn-ping-server and hicn-ping-client) and a hicn implementation of hicn (hiperf).

### hicn-ping-server

The command `hicn-ping-server` runs the server side ping application. hicn-ping-server can be executed
with the following options:

```
usage: hicn-ping-server [options]

Options:
-s <content_size>           = object content size (default 1350B)
-n <hicn_name>              = hicn name (default b001::/64)
-f                          = set tcp flags according to the flag received (default false)
-l <lifetime>               = data lifetime
-r                          = always reply with a reset flag (default false)
-t <ttl>                    = set ttl (default 64)
-V                          = verbose, prints statistics about the messagges sent and received (default false)
-D                          = dump, dumps sent and received packets (default false)
-q                          = quite, not prints (default false)
-d                          = daemon mode
-H                          = help

Example:
hicn-ping-server -n c001::/64
```

### hicn-ping-client

The command `hicn-ping-client` runs the client side ping application. hicn-ping-client can be executed
with the following options:

```
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
-V                          = verbose, prints statistics about the messagges sent and received (default false)
-D                          = dump, dumps sent and received packets (default false)
-q                          = quiet, not prints (default false)
-H                          = help

Example:
hicn-ping-client -n c001::1
```

### hiperf

The command `hiperf` is a tool for performing network throughput measurements with hicn. It can be executed as server or client using the following options:

```
usage: hiperf [-S|-C] [options] [prefix|name]

Options:
-D                          = run as a daemon
-R                          = run RTC protocol (client or server)
-f <ouptup_log_file>        = output log file path

Server specific:
-A <download_size>          = size of the content to publish. This is not the size of the packet (see -s for it)
-s <payload_size>           = size of the payload of each data packet
-r                          = produce real content of content_size bytes
-m                          = produce transport manifest
-l                          = start producing content upon the reception of the first interest
-k <keystore_path>          = path of p12 file containing the crypto material used for signing the packets
-y <hash_algorithm>         = use the selected hash algorithm for calculating manifest digests
-p <password>               = password for p12 keystore
-x                          = produce a content of <download_size>, then after downloading it produces a new content of
					          <download_size> without resetting the suffix to 0
-B	<bitrate>			          = bitrate for RTC producer, to be used with the -R option, in kbps (example: 64kbps)

Client specific:
-b <beta_parameter>         = RAAQM beta parameter
-d <drop_factor_parameter>  = RAAQM drop factor parameter
-M                          = store the content downloaded (default false)
-W <window_size>            = use a fixed congestion window for retrieving the data
-c <certificate_path>       = path of the producer certificate to be used for verifying the origin of the packets received
-i <stats_interval>         = show the statistics every <stats_interval> milliseconds
-v                          = Enable verification of received data

Example:
hiperf -S c001::/64
```

## How To Benchmark Client-Server Throughput using hiperf

### hicn-light-daemon

This tutorial will explain how to configure a simple client-server topology and retrieve network measurements using the hiperf utility.

We consider this simple topology, consisting on two linux VM which are able to communicate through an IP network (you can also use containers or physical machines):

```text
|client (10.0.0.1/24; 9001::1/64)|======|server (10.0.0.2/24; 9001::2/64)|
```

Install the hICN suite on two linux VM. This tutorial makes use of Ubuntu 18.04, but it could easily be adapted to other platforms.
You can either install the hICN stack using binaries or compile the code. In this tutorial we will build the code from source.

```bash
$ curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
$ apt-get install -y git \
                    cmake \
                    build-essential \
                    libasio-dev \
                    libcurl4-openssl-dev \
                    libparc-dev \
                    --no-install-recommends

$ mkdir hicn-suite && cd hicn-suite
$ git clone https://github.com/FDio/hicn hicn-src
$ mkdir hicn-build && cd hicn-build
$ cmake ../hicn-src -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../hicn-install -DBUILD_APPS=ON
$ make -j 4 install
$ export HICN_ROOT=${PWD}/../hicn-install
```

It should install the hICN suite under hicn-install.

#### hICN stack based on hicn-light forwarder with UDP faces

##### Server Configuration

Create a configuration file for the hicn-light forwarder. Here we are configuring UDP faces.

```bash
server$ mkdir -p ${HICN_ROOT}/etc
server$ LOCAL_IP="10.0.0.1" # Put here the actual IPv4 of the local interface
server$ LOCAL_PORT="12345"
server$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener udp list0 ${LOCAL_IP} ${LOCAL_PORT}
EOF
```

Start the hicn-light forwarder

```bash
server$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 0 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

We set the forwarder capacity to 0 because we want to measure the end-to-end performance without retrieving any data packet from intermediate caches.

Run the [hiperf](#hiperf) server.

```bash
server$ ${HICN_ROOT}/bin/hiperf -S b001::/64
```

The hiperf server will register the prefix b001::/64 on the local forwarder and will reply with pre-allocated data packet.  In this test we won't consider segmentation and reassembly cost.

##### Client Configuration

Create a configuration file for the hicn-light forwarder at the client. Here we are configuring UDP faces.

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

Run the hicn-light forwarder

```bash
client$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

Run the [hiperf](#hiperf) client:

```bash
client$ ${HICN_ROOT}/bin/hiperf -C b001::1 -W 50
EOF
```

This will run the client with a fixed window of 50 interests.

#### Using hicn-light forwarder with hICN faces

For sending hICN packets directly over the network, using hicn faces, change the configuration of the two forwarders and restart them.

##### Server Configuration

```bash
server$ mkdir -p ${HICN_ROOT}/etc
server$ LOCAL_IP="9001::1"
server$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener hicn lst 0::0
add punting lst b001::/16
add listener hicn list0 ${LOCAL_IP}
EOF
```

#### Client Configuration

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

### vpp based hicn-plugin

Compile the hicn stack enabling the [vpp](https://github.com/FDio/vpp) support.

In this example we will do a local hiperf client-server communication.

```bash
$ curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
$ apt-get install -y git \
                    cmake \
                    build-essential \
                    libasio-dev \
                    libcurl4-openssl-dev \
                    libparc-dev \
                    vpp libvppinfra vpp-plugin-core vpp-dev python3-ply python python-ply \
                    --no-install-recommends

$ mkdir hicn-suite && cd hicn-suite
$ git clone https://github.com/FDio/hicn hicn-src
$ mkdir hicn-build && cd hicn-build
$ cmake ../hicn-src -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_APPS=ON -DBUILD_HICNPLUGIN=ON
$ sudo make -j 4 install
$ export HICN_ROOT=${PWD}/../hicn-install
```

Make sure vpp is running:

```bash
$ sudo systemctl restart vpp
```

Run the hicn-plugin:

```bash
$ vppctl hicn control start
```

Run hiperf server:

```bash
$ hiperf -S b001::/64
```

Run hiperf client:

```bash
$ hiperf -C b001::1 -W 300
```

## License

This software is distributed under the following license:

```
Copyright (c) 2017-2019 Cisco and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
