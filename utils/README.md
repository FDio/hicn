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
-H                          = prints this message

```

### hicn-ping-client ###

The command `hicn-ping-client` runs the client side ping application. ping_server can be executed
with the following options:

```
hicn-http-server [OPTIONS]

Options:
-p <value>                = path to root foot folder
-f <value>                = configuration file path
-o <value>                = tcp listener port
-l <value>                = webserver prefix
-x <value>                = tcp proxy prefix
-z <value>                = hicn proxy prefix
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
