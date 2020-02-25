# Applications

The open source distribution provides a few application examples: a MPEG-DASH
video player, a HTTP reverse proxy, a command line HTTP GET client.

hICN sockets have been successfully used to serve HTTP, RTP and RSockets
application protocols.

## Dependencies

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

`hicn-http-proxy` is a reverse proxy which can be used for augmenting the
performance of a legacy HTTP/TCP server by making use of hICN. It performs
the following operations:

- Receive a HTTP request from a hICN client
- Forward it to a HTTP server over TCP
- Receive the response from the server and send it back to the client

```bash
hicn-http-proxy [HTTP_PREFIX] [OPTIONS]

HTTP_PREFIX: The prefix used for building the hicn names.

Options:
-a <server_address>   = origin server address
-p <server_port>      = origin server port
-c <cache_size>       = cache size of the proxy, in number of hicn data packets
-m <mtu>              = mtu of hicn packets
-P <prefix>           = optional most significant 16 bits of hicn prefix, in hexadecimal format
```

Example:
```bash
./hicn-http-proxy http://webserver -a 127.0.0.1 -p 8080 -c 10000 -m 1200 -P b001
```

The hICN names used by the hicn-http-proxy for naming the HTTP responses are
composed in the following way, starting from the most significant byte:

- The first 2 bytes are the prefix specified in the -P option
- The next 6 bytes are the hash (Fowler–Noll–Vo non-crypto hash) of the locator
  (in the example `webserver`, without the `http://` part)
- The last 8 bytes are the hash (Fowler–Noll–Vo non-crypto hash) of the http
  request corresponding to the response being forwarded back to the client.

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

The hICN names used by higet for naming the HTTP requests are composed the
way described in [hicn-http-proxy](#hicn-http-proxy).

## HTTP Client-Server with hicn-http-proxy

We consider the following topology, consisting on two linux VMs which are able
to communicate through an IP network (you can also use containers or physical
machines):

```text
|client (10.0.0.1/24; 9001::1/64)|======|server (10.0.0.2/24; 9001::2/64)|
```

Install the hICN suite on two linux VM. This tutorial makes use of Ubuntu 18.04,
but it could easily be adapted to other platforms. You can either install the hICN
stack using binaries or compile the code. In this tutorial we will make use of
docker container and binaries packages.

The client will use of the hicn-light forwarder, which is lightweight and tailored
for devices such as android and laptops. The server will use the hicn-plugin of vpp,
which guarantees better performances and it is the best choice for server applications.

Keep in mind that on the same system the stack based on vpp forwarder cannot
coexist with the stack based on hicn light.

For running the hicn-plugin at the server there are two main alternatives:

- Use a docker container
- Run the hicn-plugin directly in a VM or Bare Metal Server

### Docker VPP hICN proxy

Install docker in the server VM:

```bash
server$ curl get.docker.com | bash
```

Run the hicn-http-proxy container. Here we use a public server at `localhost` as
origin and HTTP traffic is server with an IPv6 name prefix `b001`.

```bash
#!/bin/bash

# http proxy options
ORIGIN_ADDRESS=${ORIGIN_ADDRESS:-"localhost"}
ORIGIN_PORT=${ORIGIN_PORT:-"80"}
CACHE_SIZE=${CACHE_SIZE:-"10000"}
DEFAULT_CONTENT_LIFETIME=${DEFAULT_CONTENT_LIFETIME:-"7200"}
HICN_MTU=${HICN_MTU:-"1300"}
FIRST_IPV6_WORD=${FIRST_IPV6_WORD:-"b001"}
USE_MANIFEST=${USE_MANIFEST:-"true"}
HICN_PREFIX=${HICN_PREFIX:-"http://webserver"}

# udp punting
HICN_LISTENER_PORT=${HICN_LISTENER_PORT:-33567}
TAP_ADDRESS_VPP=192.168.0.2
TAP_ADDRESS_KER=192.168.0.1
TAP_ADDRESS_NET=192.168.0.0/24
TAP_ID=0
TAP_NAME=tap${TAP_ID}

vppctl create tap id ${TAP_ID}
vppctl set int state ${TAP_NAME} up
vppctl set interface ip address tap0 ${TAP_ADDRESS_VPP}/24
ip addr add ${TAP_ADDRESS_KER}/24 brd + dev ${TAP_NAME}

# Redirect the udp traffic on port 33567 (The one used for hicn) to vpp
iptables -t nat -A PREROUTING -p udp --dport ${HICN_LISTENER_PORT} -j DNAT \
                   --to-destination ${TAP_ADDRESS_VPP}:${HICN_LISTENER_PORT}
# Masquerade all the traffic coming from vpp
iptables -t nat -A POSTROUTING -j MASQUERADE --src ${TAP_ADDRESS_NET} ! \
                                 --dst ${TAP_ADDRESS_NET} -o eth0
# Add default route to vpp
vppctl ip route add 0.0.0.0/0 via ${TAP_ADDRESS_KER} ${TAP_NAME}
# Set UDP punting
vppctl hicn punting add prefix ${FIRST_IPV6_WORD}::/16 intfc ${TAP_NAME}\
                                type udp4 dst_port ${HICN_LISTENER_PORT}

# Run the http proxy
PARAMS="-a ${ORIGIN_ADDRESS} "
PARAMS+="-p ${ORIGIN_PORT} "
PARAMS+="-c ${CACHE_SIZE} "
PARAMS+="-m ${HICN_MTU} "
PARAMS+="-P ${FIRST_IPV6_WORD} "
PARAMS+="-l ${DEFAULT_CONTENT_LIFETIME} "
if [ "${USE_MANIFEST}" = "true" ]; then
  PARAMS+="-M "
fi

hicn-http-proxy ${PARAMS} ${HICN_PREFIX}
```

Docker images of the example above are available at
<https://hub.docker.com/r/icnteam/vhttpproxy>.
Images can be pulled using the following tags.

```bash
docker pull icnteam/vhttpproxy:amd64
docker pull icnteam/vhttpproxy:arm64
```

#### Client side

Run the hicn-light forwarder:

```bash
client$ sudo /usr/bin/hicn-light-daemon --daemon --capacity 1000 --log-file \
                   ${HOME}/hicn-light.log --config ${HOME}/etc/hicn-light.conf
```

Run the http client [higet](#higet) and print the http response on stdout:

```bash
client$ /usr/bin/higet -O - http://webserver/index.html -P c001
```

### Host/VM

You can install the hicn-plugin of vpp on your VM and directly use DPDK
compatible nics, forwarding hicn packets directly over the network. DPDK
compatible nics can be used inside a container as well.

```bash
server$ sudo apt-get install -y hicn-plugin vpp-plugin-dpdk hicn-apps-memif
```

It will install all the required deps (vpp, hicn apps and libraries compiled for
communicating with vpp using shared memories). Configure VPP following the steps
described [here](https://github.com/FDio/hicn/blob/master/hicn-plugin/README.md#configure-vpp).

This tutorial assumes you configured two interfaces in your server VM:

- One interface which uses the DPDK driver, to be used by VPP
- One interface which is still owned by the kernel

The DPDK interface will be used for connecting the server with the hicn client,
while the other interface will guarantee connectivity to the applications running
in the VM, including the hicn-http-proxy. If you run the commands:

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

Take care of replacing the interface name (`GigabitEthernetb/0/0`) with the
actual name of your interface.

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
