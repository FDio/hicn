# Application examples using hICN stack

## Introduction

higet and hicn-http-proxy are two application examples that use hicn stack.

## Using hICN Application Examples

### Dependencies

Build dependencies:

- C++14 ( clang++ / g++ )
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
You can either install the hICN stack using binaries or compile the code. In this tutorial we will make use of docker container and binaries packages.

The client will use of the hicn-light forwarder, which is lightweight and tailored for devices such as android and laptops.
The server will use the hicn-plugin of vpp, which guarantees better performances and it is the best choice for server applications.

Keep in mind that on the same system the stack based on vpp forwarder cannot coexist with the stack based on hicn light.

For running the hicn-plugin at the server there are two main alternatives:

- Use a docker container
- Run the hicn-plugin directly in a VM or Bare Metal Server

#### Docker

Install docker in the server VM:

```bash
server$ curl get.docker.com | bash
```

Run the hicn-http-proxy container. Here we use a public server [example.com](example.com) as origin:

```bash
server$ docker run -e ORIGIN_ADDRESS=example.com    \
             -e ORIGIN_PORT=80                      \
             -e CACHE_SIZE=10000                    \
             -e HICN_MTU=1200                       \
             -e FIRST_IPV6_WORD=c001                \
             -e HICN_PREFIX=http://webserver        \
             --privileged                           \
             --name vhttpproxy                      \
             -d icnteam/vhttpproxy
```

Create a hicn private network:

```bash
server$ GATEWAY=192.168.0.254
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
server$ sudo iptables -A DOCKER -j ACCEPT -p udp --destination ${IP_ADDRESS} --dport ${PORT}
```

In the client, install the hicn stack:

```bash
client$ sudo apt-get install -y hicn-light hicn-apps
```

Create a configuration file for the hicn-light forwarder. Here we are configuring UDP faces:

```bash
client$ mkdir -p ${HOME}/etc
client$ LOCAL_IP="10.0.0.2" # Put here the actual IPv4 of the local interface
client$ LOCAL_PORT="12345"
client$ REMOTE_IP="10.0.0.1" # Put here the actual IPv4 of the remote interface
client$ REMOTE_PORT="12345"
client$ cat << EOF > ${HOME}/etc/hicn-light.conf
add listener udp list0 ${LOCAL_IP} ${LOCAL_PORT}
add connection udp conn0 ${REMOTE_IP} ${REMOTE_PORT} ${LOCAL_IP} ${LOCAL_PORT}
add route conn0 c001::/16 1
EOF
```

Run the hicn-light forwarder

```bash
client$ sudo /usr/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HOME}/hicn-light.log --config ${HOME}/etc/hicn-light.conf
```

Run the http client [higet](#higet) and print the http response on stdout:

```bash
client$ /usr/bin/higet -O - http://webserver/index.html -P c001
```

#### Host/VM

You can install the hicn-plugin of vpp on your VM and directly use DPDK compatible nics, forwarding hicn packets directly over the network. DPDK compatible nics can be used inside a container as well.

```bash
server$ sudo apt-get install -y hicn-plugin vpp-plugin-dpdk hicn-apps-memif
```

It will install all the required deps (vpp, hicn apps and libraries compiled for communicating with vpp using shared memories). Configure VPP following the steps described [here](https://github.com/FDio/hicn/blob/master/hicn-plugin/README.md#configure-vpp).

This tutorial assumes you configured two interfaces in your server VM:

- One interface which uses the DPDK driver, to be used by VPP
- One interface which is still owned by the kernel

The DPDK interface will be used for connecting the server with the hicn client, while the other interface will guarantee connectivity to the applications running in the VM, including the hicn-http-proxy. If you run the commands:

```bash
server$ sudo systemctl restart vpp
server$ vppctl show int
```

The output must show the dpdk interface owned by VPP:

```text
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
GigabitEthernetb/0/0              1     down         9000/0/0/0
local0                            0     down          0/0/0/0
```

If the interface is down, bring it up and assign the correct ip address to it:

```bash
server$ vppctl set int state GigabitEthernetb/0/0 up
server$ vppctl set interface ip address GigabitEthernetb/0/0 9001::1/64
```

Take care of replacing the interface name (`GigabitEthernetb/0/0`) with the actual name of your interface.

Now enable the hicn plugin and set the punting for the hicn packets:

```bash
server$ vppctl hicn control start
server$ vppctl hicn punting add prefix c001::/16 intfc GigabitEthernetb/0/0 type ip
```

Run the hicn-http-proxy app:

```bash
server$ sudo /usr/bin/hicn-http-proxy -a example.com -p 80 -c 10000 -m 1200 -P c001 http://webserver
```

Configure the client for sending hicn packets without any udp encapsulation:

```bash
client$ mkdir -p ${HOME}/etc
client$ LOCAL_IP="9001::2"
client$ REMOTE_IP="9001::1"
client$ cat << EOF > ${HOME}/etc/hicn-light.conf
add listener hicn lst 0::0
add punting lst c001::/16
add listener hicn list0 ${LOCAL_IP}
add connection hicn conn0 ${REMOTE_IP} ${LOCAL_IP}
add route conn0 c001::/16 1
EOF
```

Restart the forwarder:

```bash
client$ sudo killall -INT hicn-light-daemon
client$ sudo /usr/bin/hicn-light-daemon --daemon --capacity 1000 --log-file ${HOME}/hicn-light.log --config ${HOME}/etc/hicn-light.conf
```

Retrieve a web page:

```bash
client$ /usr/bin/higet -O - http://webserver/index.html -P c001
```
