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
-s <value>                  = object content size (default 1350B)
-n <value>                  = hicn name (default b001::/64)
-f <true/false>             = set tcp flags according to the flag received (default false)
-l <value>                  = data lifetime
-r <true/false>             = always reply with a reset flag (default false)
-t <value>                  = set ttl (default 64)
-V                          = verbose, prints statistics about the messagges sent and received (default false)
-D <true/false>             = dump, dumps sent and received packets (default false)
-q <true/false>             = quite, not prints (default false)
-d                          = daemon mode
-H                          = help
```

### hicn-ping-client ###

The command `hicn-ping-client` runs the client side ping application. hicn-ping-client can be executed
with the following options:

```
usage: hicn-ping-client [options]

Options:
-i <value>                  = ping interval in microseconds (default 1000000ms)
-m <value>                  = maximum number of pings to send (default 10)
-s <value>                  = source port (default 9695)
-d <value>                  = destination port (default 8080)
-t <value>                  = set packet ttl (default 64)
-O <true/false>             = open tcp connection (three way handshake) (default false)
-S <true/false>             = send always syn messages (default false)
-A <true/false>             = send always ack messages (default false)
-n <value>                  = hicn name (default b001::1)
-l <value>                  = interest lifetime in milliseconds (default 500ms)
-V                          = verbose, prints statistics about the messagges sent and received (default false)
-D <true/false>             = dump, dumps sent and received packets (default false)
-q <true/false>             = quiet, not prints (default false)
-H                          = help
```

### hicn-ping-client ###

The command `hicn-ping-client` runs the client side ping application. hicn-ping-client can be executed
with the following options:

```
usage: hicn-ping-client [options]

Options:
-i <value>                  = ping interval in microseconds (default 1000000ms)
-m <value>                  = maximum number of pings to send (default 10)
-s <value>                  = source port (default 9695)
-d <value>                  = destination port (default 8080)
-t <value>                  = set packet ttl (default 64)
-O <true/false>             = open tcp connection (three way handshake) (default false)
-S <true/false>             = send always syn messages (default false)
-A <true/false>             = send always ack messages (default false)
-n <value>                  = hicn name (default b001::1)
-l <value>                  = interest lifetime in milliseconds (default 500ms)
-V                          = verbose, prints statistics about the messagges sent and received (default false)
-D <true/false>             = dump, dumps sent and received packets (default false)
-q <true/false>             = quiet, not prints (default false)
-H                          = help
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
