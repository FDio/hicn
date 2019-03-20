Application examples using hicn stack
==================

## Introduction ##

hicn-ping-server, hicn-ping-client and hiperf are three application utilities that use hicn stack.

## Using hICN Utils application ##

### Platforms ###

The hICN application Examples have been tested in:

- Ubuntu 16.04 (x86_64)
- Debian Testing
- MacOSX 10.12

Other platforms and architectures may work.

### Dependencies ###

Build dependencies:

- c++14 ( clang++ / g++ )
- CMake 3.4

Basic dependencies:

- OpenSSL
- pthreads
- Libevent
- Libparc

## Executables ##

The application utilities are a set of binary executables that are used to run a clinet/server ping applications (hicn-ping-server and hicn-ping-client) and a hicn implementation of hicn (hiperf).

### hicn-ping-server ###

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
```

### hicn-ping-client ###

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
```

### hiperf ###

The command `hiperf` is a  tool for performing network throughput measurements with hicn. It can be executed as server or client. hiperf can be executed
with the following options:

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
-x                          = produce a content of <download_size>, then after downloading it produce a new content of
					          <download_size> without resetting the suffix to 0
-B	<bitrate>			    = bitrate for RTC producer, to be used with the -R option

Client specific:
-b <beta_parameter>         = RAAQM beta parameter
-d <drop_factor_parameter>  = RAAQM drop factor parameter
-M                          = store the content downloaded (default false)
-W <window_size>            = use a fixed congestion window for retrieving the data
-c <certificate_path>       = path of the producer certificate to be used for verifying the origin of the packets received
-i <stats_interval>         = show the statistics every <stats_interval> milliseconds
-v                          = Enable verification of received data
```

## License ##

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
