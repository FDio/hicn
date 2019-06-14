Application examples using hicn stack
==================

## Introduction ##

higet and hicn-http-server are two application examples that use hicn stack.

## Using hICN Application Examples ##

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
- Libcurl

## Executables ##

The application examples are a set of binary executables that are used to run a simple http client (higet) and a simple http server (hicn-http-server).

### higet ###

The command `higet` runs the higet application. higet can be executed
with the following options:

```
higet [option]... [url]...
Options:
-O <output_path>            = write documents to <output_file>
-S                          = print server response
```

### hicn-http-server ###

`hicn-http-server` is a web server able to publish content and generate http responses over TCP/HICN
The command can be executed in the following way:

```
hicn-http-server [OPTIONS]

Options:
-p <root_folder_path>       = path to root folder
-f <coniguration_path>      = configuration file path
-o <tcp_port>               = tcp listener port
-l <webserver_prefix>       = webserver prefix
-x <tcp_proxy_prefix>       = tcp proxy prefix
-z <hicn_proxy_prefix>      = hicn proxy prefix
```

### hicn-http-proxy ###

`hicn-http-proxy` is a reverse proxy which can be used for augmenting the performance of a legacy HTTP/TCP server
by making use of hICN. It performs the following operations:

- Receives a HTTP request over hICN
- Forwards it to a HTTP server over TCP
- Receives the response from the server and publishes it

Subsequently, other hICN client asking for the same HTTP message can retrieve it directly
through hICN, by retrieving it either from the forwarder caches or directly from the `hicn-http-proxy`.

The proxy uses hICN names for performing the multiplexing of http requests, allowing a single
hICN proxy with a single producer socket to serve multiple consumers asking for the same content. Conversely, a normal
TCP proxy still needs to open one TCP connection per client.

```
hicn-http-proxy [HTTP_PREFIX] [OPTIONS]

HTTP_PREFIX: The prefix used for building the hicn names.

Options:
-a <server_address>   = origin server address
-p <server_port>      = origin server port
-c <cache_size>       = cache size of the proxy, in number of hicn data packets

Example:
./hicn-http-proxy http://webserver -a 127.0.0.1 -p 8080 -c 10000
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
