# Application examples using hICN stack

## Introduction

higet and hicn-http-proxy are two application examples that use hicn stack.

## Using hICN Application Examples

### Dependencies

Build dependencies:

- c++14 ( clang++ / g++ )
- CMake 3.5 or higher

Basic dependencies:

- OpenSSL
- pthreads
- libevent
- libparc
- libcurl
- libhicntransport

## Executables

### hicn-http-proxy

`hicn-http-proxy` is a reverse proxy which can be used for augmenting the performance of a legacy HTTP/TCP server
by making use of hICN. It performs the following operations:

- Receives a HTTP request from a hICN client
- Forwards it to a HTTP server over TCP
- Receives the response from the server and send it back to the client

```bash
hicn-http-proxy [HTTP_PREFIX] [OPTIONS]

HTTP_PREFIX: The prefix used for building the hicn names.

Options:
-a <server_address>   = origin server address
-p <server_port>      = origin server port
-c <cache_size>       = cache size of the proxy, in number of hicn data packets
-m <mtu>              = mtu of hicn packets
-P <prefix>           = optional most significant 16 bits of hicn prefix, in hexadecimal format

Example:
./hicn-http-proxy http://webserver -a 127.0.0.1 -p 8080 -c 10000 -m 1200 -P b001
```

The hICN names used by the hicn-http-proxy for naming the HTTP responses are composed in the following way,
starting from the most significant byte:

- The first 2 bytes are the prefix specified in the -P option
- The next 6 bytes are the hash (Fowler–Noll–Vo non-crypto hash) of the locator (in the example `webserver`, without the `http://` part)
- The last 8 bytes are the hash (Fowler–Noll–Vo non-crypto hash) of the http request corresponding to the response being forwarded back to the client.

### higet

Higet is a non-interactive HTTP client working on top oh hICN.

```bash
higet [option]... [url]
Options:
-O <output_path>            = write documents to <output_file>. Use '-' for stdout.
-S                          = print server response.
-P                          = optional first 16 bits of hicn prefix, in hexadecimal format

Example:
./higet -P b001 -O - http://webserver/index.html
```

The hICN names used by higet for naming the HTTP requests are composed the same way as described in [hicn-http-proxy](#hicn-http-proxy).

### How To Setup A Simple HTTP Client-Server Scenario using the hicn-http-proxy

We consider the following topology, consisting on two linux VM which are able to communicate through an IP network (you can also use containers or physical machines):

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
server$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
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
client$ sudo ${HICN_ROOT}/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HICN_ROOT}/hicn-light.log --config ${HICN_ROOT}/etc/hicn-light.conf
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

#### hICN stack based on vpp forwarder plugin with UDP faces

The hicn plugin for the vpp forwarder is the preferred and supported choice be use at the server side.

For installing the hicn-plugin at the server there are two main alternatives:

- Use docker
- Use deb packages

Keep in mind that on the same system the stack based on vpp forwarder cannot coexist with the stack based on hicn light.

##### Docker

Install docker in the server VM:

```bash
server$ sudo apt-get update
server$ sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common

server$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
server$ sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
server$ sudo apt-get update
server$ sudo apt-get install docker-ce docker-ce-cli containerd.io
```

Run the hicn-http-proxy container. Here we use a public server [www.ovh.net](www.ovh.net) as origin, and we expose port 50000 for creating udp faces with external nodes:

```bash
server$ docker run -e ORIGIN_ADDRESS=example.com    \
             -e ORIGIN_PORT=80                \
             -e CACHE_SIZE=10000              \
             -e HICN_MTU=1200                 \
             -e FIRST_IPV6_WORD=c001          \
             -e HICN_PREFIX=http://webserver  \
             --privileged                     \
             --name vhttpproxy                \
             -d icnteam/vhttpproxy
```

Create a hicn private network:

```bash
GATEWAY=192.168.0.254
server$ docker network create --subnet 192.168.0.0/24 --gateway ${GATEWAY} hicn-network
```

Connect the proxy container to the hicn network:

```bash
server$ docker network connect hicn-network vhttpproxy
```

Connect the hicn network to the vpp forwarder:

```bash
server$ IP_ADDRESS=$(docker inspect -f "{{with index .NetworkSettings.Networks \"hicn-network\"}}{{.IPAddress}}{{end}}" vhttpproxy)
server$ INTERFACE=$(docker exec -it vhttpproxy ifconfig | grep -B 1 ${IP_ADDRESS} | awk 'NR==1 {gsub(":","",$1); print $1}')
server$ docker exec -it vhttpproxy ip addr flush dev ${INTERFACE}
server$ docker exec -it vhttpproxy ethtool -K ${INTERFACE} tx off rx off ufo off gso off gro off tso off
server$ docker exec -it vhttpproxy vppctl create host-interface name ${INTERFACE}
server$ docker exec -it vhttpproxy vppctl set interface state host-${INTERFACE} up
server$ docker exec -it vhttpproxy vppctl set interface ip address host-${INTERFACE} ${IP_ADDRESS}/24
server$ docker exec -it vhttpproxy vppctl ip route add 10.0.0.0/24 via ${GATEWAY} host-eth1
```

Set the punting:

```bash
server$ PORT=12345
server$ docker exec -it vhttpproxy vppctl hicn punting add prefix c001::/16 intfc host-${INTERFACE} type udp4 src_port ${PORT} dst_port ${PORT}
```

Docker containers are cool, but sometimes they do not allow you to do simple operations like expose ports while the container is already running. But we have a workaround for this :)

```bash
server$ sudo iptables -t nat -A DOCKER -p udp --dport ${PORT} -j DNAT --to-destination ${IP_ADDRESS}:${PORT}
server$ sudo iptables -t nat -A POSTROUTING -j MASQUERADE -p udp --source ${IP_ADDRESS} --destination ${IP_ADDRESS} --dport ${PORT}
$ sudo iptables -A DOCKER -j ACCEPT -p udp --destination ${IP_ADDRESS} --dport ${PORT}
```

In the client, create a connection towards the server where the container is running. Here we will use the same configuration file used [here](#Client-Configuration). If the configuration changed you need to restart the hicn-light-daemon.

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

Download a web page from the client:

```bash
client$ ${HICN_ROOT}/bin/higet -O - http://webserver/index.html -P c001
```

## License

This software is distributed under the following license:

```text
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
