Application examples using hICN stack
==================

## Introduction ##

higet and hicn-http-server are two application examples that use hICN stack.

## Using hICN Application Examples ##

### Dependencies ###

Build dependencies:

- c++14 ( clang++ / g++ )
- CMake 3.5 or higher

Basic dependencies:

- OpenSSL
- pthreads
- Libevent
- Libparc
- Libcurl
- Libhicntransport

## Executables ##

### hicn-http-proxy ###

`hicn-http-proxy` is a reverse proxy which can be used for augmenting the performance of a legacy HTTP/TCP server
by making use of hICN. It performs the following operations:

- Receives a HTTP request from a hICN client
- Forwards it to a HTTP server over TCP
- Receives the response from the server and send it back to the client

```
hicn-http-proxy [HTTP_PREFIX] [OPTIONS]

HTTP_PREFIX: The prefix used for building the hicn names.

Options:
-a <server_address>   = origin server address
-p <server_port>      = origin server port
-c <cache_size>       = cache size of the proxy, in number of hicn data packets
-m <mtu>              = mtu of hicn packets
-P <prefix>           = first 16 bits of hicn prefix

Example:
./hicn-http-proxy http://webserver -a 127.0.0.1 -p 8080 -c 10000 -m 1200 -P b001
```


### higet ###

Higet is a non-interactive HTTP client working on top oh hICN.

```
higet [option]... [url]
Options:
-O <output_path>            = write documents to <output_file>. Use '-' for stdout.
-S                          = print server response.
-P                          = optional hICN prefix to use. It must be 16 bit long.
```

The url must be in the form http://

### hicn-http-server ###

`hicn-http-server` is a web server able to publish content and generate http responses over TCP/HICN
The command can be executed in the following way:

```
hicn-http-server [OPTIONS]

Options:
-p <root_folder_path>        = path to root folder
-f <configuration_path>      = configuration file path
-o <tcp_port>                = tcp listener port
-l <webserver_prefix>        = webserver prefix
-x <tcp_proxy_prefix>        = tcp proxy prefix
-z <hicn_proxy_prefix>       = hicn proxy prefix
```

## Tutorials ##

### How To Setup A Simple HTTP Client-Server Scenario using the hicn-http-proxy

We consider the following topology, consisting on two linux VM which are able to communicate through an IP network (you can also use containers or physical machines):

```
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

Open a new terminal on the machine where you want to run the HTTP server and install apache2 http server:

```bash
server$ sudo apt-get install -y apache2
server$ sudo systemctl start apache2
```

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
server$ ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

Run the [hicn-http-proxy](#hicn-http-proxy). Assuming the http origin is listening on port 80:

```bash
server$ ${HICN_ROOT}/bin/hicn-http-proxy -a 127.0.0.1 -p 80 -c 10000 -m 1200 -P c001 http://webserver
```

##### Client Configuration

Create a configuration file for the hicn-light forwarder. Here we are configuring UDP faces.

```bash
client$ mkdir -p ${HICN_ROOT}/etc
client$ LOCAL_IP="10.0.0.2" # Put here the actual IPv4 of the local interface
client$ LOCAL_PORT="12345"
client$ REMOTE_IP="10.0.0.1" # Put here the actual IPv4 of the remote interface
client$ REMOTE_PORT="12345"
client$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener udp list0 ${LOCAL_IP} ${LOCAL_PORT}
add connection udp conn0 ${REMOTE_IP} ${REMOTE_PORT} ${LOCAL_IP} ${LOCAL_PORT}
add route conn0 c001::/16 1
EOF
```

Run the hicn-light forwarder

```bash
client$ ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
```

Run the http client [higet](#higet) and print the http response on stdout:

```bash
client$ ${HICN_ROOT}/bin/higet -O - http://webserver/index.html -P c001
EOF
```

#### Using hicn-light forwarder with hICN faces

For sending hICN packets directly over the network, using hicn faces, change the configuration of the two forwarders and restart them.

##### Server Configuration

```bash
server$ mkdir -p ${HICN_ROOT}/etc
server$ LOCAL_IP="9001::1"
server$ cat << EOF > ${HICN_ROOT}/etc/hicn-light.conf
add listener hicn lst 0::0
add punting lst c001::/16
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
add punting lst c001::/16
add listener hicn list0 ${LOCAL_IP}
add connection hicn conn0 ${REMOTE_IP} ${LOCAL_IP}
add route conn0 c001::/16 1
EOF
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
