VPP plugin
==============================

The hICN-plugin forwarder

## Introduction ##

A high-performance Hybrid ICN forwarder as a plugin to VPP.

The plugin provides the following functionalities:

 - Fast packet processing
 - Interest aggregation
 - Content caching
 - Forwarding strategies

## Quick Start ##
```
From the code tree root

(VPP installed with DEB pkg)
$ cd hicn-plugin
$ mkdir -p build
$ cd build
$ cmake .. -DCMAKE_INSTALL_PREFIX=/usr
$ make
$ sudo make install

(VPP source code -- build type RELEASE)
$ cd hicn-plugin
$ mkdir -p build
$ cd build
$ cmake .. -DVPP_HOME=<vpp dir>/build-root/install-vpp-native/vpp -DCMAKE_INSTALL_PREFIX=<vpp src>/build-root/install-vpp-native/vpp
$ make
$ sudo make install

(VPP source code -- build type DEBUG)
$ cd hicn-plugin
$ mkdir -p build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=DEBUG -DVPP_HOME=<vpp dir>/build-root/install-vpp_debug-native/vpp -DCMAKE_INSTALL_PREFIX=<vpp src>/build-root/install-vpp_debug-native/vpp
$ make
$ sudo make install

CMAKE variables:
- CMAKE_INSTALL_PREFIX -- set the install directory for the hicn-plugin. This is the common path to the lib folder containing vpp_plugins and vpp_api_test_plugins folders. Default is /usr/local.
- VPP_HOME -- set the directory containing the include and lib directories of vpp.
```

## Using hICN plugin ##

### Platforms ###

hICN-plugin has been tested in:

- Ubuntu 16.04 LTS (x86_64)
- Ubuntu 18.04 LTS (x86_64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7


### Dependencies ###

Build dependencies:

- VPP 19.08
  - DEB packages (can be found https://packagecloud.io/fdio/release/install):
  - vpp
  - libvppinfra-dev
  - vpp-dev

Runtime dependencies:

- VPP 19.08
  - DEB packages (can be found https://packagecloud.io/fdio/release/install):
  - vpp
  - vpp-plugin-core
  - vpp-plugin-dpdk (only to use DPDK compatible nics)

Hardware support (not mandatory):

- [DPDK](http://DPDK.org/) compatible nics

## Getting started ##
In order to start, the hICN plugin requires a running instance of VPP
The steps required to successfully start hICN are:

- Setup the host to run VPP
- Configure VPP to use DPDK compatible nics
- Start VPP
- Configure VPP interfaces
- Configure and start hICN

Detailed information for configuring VPP can be found at [https://wiki.fd.io/view/VPP](https://wiki.fd.io/view/VPP).

### Setup the host for VPP ###

Hugepages must be enabled in the system

```
$ sudo sysctl -w vm.nr_hugepages=1024
```

In order to use a DPDK interface, the `uio` and `uio_pci_generic` or `vfio_pci` modules need to be loaded in the kernel

```
$ sudo modprobe uio
$ sudo modprobe uio_pci_generic
$ sudo modprobe vfio_pci
```

If the DPDK interface we want to assign to VPP is up, we must bring it down

```
$ sudo ifconfig <interface_name> down
```
or
```
$ sudo ip link set <interface_name> down
```

### Configure VPP ###
The file /etc/VPP/startup.conf contains a set of parameters to setup VPP at startup.
The following example sets up VPP to use a DPDK interfaces:

``` shell
unix {
  nodaemon
  log /tmp/vpp.log
  full-coredump
}

api-trace {
  on
}

api-segment {
  gid vpp
}

dpdk {
  dev 0000:08:00.0
}

plugins {
        ## Disable all plugins by default and then selectively enable specific plugins
        plugin default { disable }
        plugin dpdk_plugin.so { enable }
        plugin acl_plugin.so { enable }
        plugin memif_plugin.so { enable }
        plugin hicn_plugin.so { enable }

        ## Enable all plugins by default and then selectively disable specific plugins
        # plugin dpdk_plugin.so { disable }
        # plugin acl_plugin.so { disable }
}
```
Where `0000:08:00.0` must be replaced with the actual PCI address of the DPDK interface

### Start VPP ###

VPP can be started as a process or a service:

``` shell
Start VPP as a service in Ubuntu 16.04
$ sudo systemctl start vpp

Start VPP as a process in both 16.04
$ sudo vpp -c /etc/vpp/startup.conf

```

### Configure hICN plugin ###
The hICN plugin can be configured either using the VPP command-line interface (CLI), through a configuration file or through the VPP binary api

#### hICN plugin CLI ####

The CLI commands for the hICN plugin start all with the hicn keyword. To see the full list of command available type:

``` shell
$ sudo vppctl
vpp# hicn ?
```

`hicn control param`: configures the internal parameter of the hICN plugin. This command must be run before hicn control start.

```
hicn control param { pit { size <entries> | { dfltlife | minlife | maxlife } <seconds> } | cs {size <entries> | app <portion to reserved to app>} }
  <entries>                     :set the maximum number of entry in the PIT or CS. Default for PIT is 131072, for CS is 4096. CS size cannot be grater than PIT size. Moreover CS size must be smaller than (# of vlib buffer - 8196). 
  <seconds>                     :set the default, maximum or minimum lifetime of pit entries. Default value 2s (default), 0.2s (minumum), 20s (maximum)
  <portion to reserved to app>  :set the portion of CS to reserve to application running locally on the forwarder. Default is 30% of the cs size.
```

`hicn control start`: starts the hICN plugin in VPP.

`hicn control stop` : stops the hICN plugin in VPP. Currently not supported.

`hicn face app` : manipulates producer and consumer application faces in the forwarder.

```
hicn face app {add intfc <sw_if> {prod prefix <hicn_prefix> cs_size <size_in_packets>} {cons}} | {del <face_id>}
  <sw_if>                     :software interface existing in vpp on top of which to create an application face
  <hicn_prefix>               :prefix to bound to the producer application face. Only content matching the prefix will be allowed through such face.
  <size_in_packets>           :content store size associated to the producer face.
  <face_id>                   :id of the face to remove

```

`hicn face ip`: manipulates ip application faces in the forwarder.

```
hicn face ip {add [local <src_address>] remote <dst_address> intfc <sw_if>} | {del id <face_id>}
  <src_address>               :the IPv4 or IPv6 local IP address to bind to (not mandatory, if not specified the local address is one of the address assigned to sw_if)
  <dst_address>               :the IPv4 or IPv6 address of the remote system
  <sw_if>                     :software interface on thop of which we create the face
  <face_id>                   :id of the face to remove
```


`hicn face show`: list the available faces in the forwarder.

```
hicn face show [<face_id>| type <ip/udp>]
  <face_id>                   :face id of which we want to display the informations
  <ip/udp>                    :shows all the ip or udp faces available
```

`hicn face udp`: manipulates udp application faces in the forwarder.

```
hicn face udp {add src_addr <src_address> port <src_port > dst_addr <dst_address> port <dst_port>} intfc <sw_if> | {del id <face_id>}
  <src_address>             :the IPv4 or IPv6 local IP address to bind to
  <src_port>                :the local UDP port
  <dst_address>             :the IPv4 or IPv6 address of the remote system
  <dst_port>                :the remote UDP port
  <sw_if>                   :software interface on thop of which we create the face
  <face_id>                 :id of the face to remove

```

`hicn fib`: manipulates hicn fib entries.

```
hicn fib {{add | delete } prefix <prefix> face <face_id> } | set strategy <strategy_id> prefix <prefix>
  <prefix>                  :prefix to add to the FIB
  <face_id>                 :face id to add as nexto hop in the FIB entry
  <strategy_id>             :set a strategy for the corresponding prefix
```

`hicn pgen client`: set an vpp forwarder as an hicn packet generator client

```
hicn pgen client fwd <ip|hicn> src <addr> n_ifaces <n_ifaces> name <prefix> lifetime <interest-lifetime> intfc <data in-interface> max_seq <max sequence number> n_flows <number of flows>
  <ip|hicn>                 :set if the underlying forwarder is configured as ip or hicn
  <src_addr>                :source address to use in the interests, i.e., the locator for routing the data packet back
  <n_ifaces>                :set the number of ifaces (consumer faces) to emulate. If more than one, each interest is sent <n_ifaces> times, each of it with a different source address calculated from <src_addr>
  <prefix>                  :prefix to use to generate hICN names
  <interest-lifetime>       :lifetime of the interests
  <data in-interface>       :interface through which the forwarder receives data
  <max sequence number>     :max the sequence number to use in the interest. Cycling between 0 and this value
  <number of flows>         :emulate multiple flows downloaded in parallel
```

`hicn pgen server`: set an vpp forwarder as an hicn packet generator client

```
hicn pgen server fwd <ip|hicn> name <prefix> intfc <interest in-interface> size <payload_size>
  <ip|hicn>                     :set if the underlying forwarder is configured as ip or hicn
  <prefix>                      :prefix to use to reply to interest
  <interest in-interface>       :interface through which the forwarder receives interest
  <payload_size>                :size of the data payload
```

`hicn punting`: manipulates punting rules

```
hicn punting {add|delete} prefix <prefix> intfc <sw_if> {type ip | type <udp4|udp6> src_port <src_port> dst_port <dst_port>}
  <prefix>                      :prefix to punt to the hICN plugin
  <sw_if>                       :software interface where to apply the punting
  <ip|udp4|udp6>                :creates a punting rule for hICN packet encapsulated into a ip4/6|udp tunnel or for regular hicn packet
  <src_port>                    :source port of the udp4/6 tunnel
  <dst_port>                    :destination port of the udp4/6 tunnel
```

`hicn show`: show forwarder information.
```
hicn show [detail] [strategies]
  <detail>                      :shows additional details as pit,cs entries allocation/deallocation
  <strategies>                  :shows only the available strategies int he forwarder
```

`hicn strategy mw set`: set the weight for a face.

```
hicn strategy mw set prefix <prefix> face <face_id> weight <weight>
  <prefix>                      :prefix to which the strategy applies
  <face_id>                     :id of the face to set the weight
  <weight>                       :weight
```

#### hICN plugin configuration file ####

A configuration can be use to setup the hicn plugin when vpp starts. The configuration file is made of a list of CLI commands. In order to set vpp to read the configuration file, the file /etc/vpp/startup.conf needs to be modified as follows:

```
unix {
  nodaemon
  log /tmp/vpp.log
  full-coredump
  startup-config <path to configuration file>
}
```
#### hICN plugin binary api ####

The binary api, or the vapi, can be used as well to configure the hicn plugin. For each cli command there is a corresponding message in the binary api. The list of messages is available in the file hicn.api (located in hicn/hicn-plugin/src/)

### Example: consumer and producer Ping ###

In this example, we connect two vpp forwarders, A and B, each of them running the hicn plugin. On top of forwarder A we run the ping_client application, on top of forwarder B we run the ping_server application. Each application connects to the underlying forwarder through a memif-interface. The two forwarders are connected through a dpdk link.

#### Forwarder A ####

```shell
$ sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/0 2001::2/64
vpp# set interface state TenGigabitEtherneta/0/0 up
vpp# hicn control start
vpp# hicn face ip add local 2001::2 remote 2001::3 intfc TenGigabitEtherneta/0/0
vpp# hicn fib add prefix b002::1/64 face 0
vpp# hicn punting add prefix b002::1/64 intfc TenGigabitEtherneta/0/0 type ip
```

#### Forwarder B ####

```shell
$ sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/1 2001::3/64
vpp# set interface state TenGigabitEtherneta/0/1 up
vpp# hicn control start
vpp# hicn punting add prefix b002::1/64 intfc TenGigabitEtherneta/0/1 type ip
```

Once the two forwarder are started, run the ping_server application on the host where the forwarder B is running

```shell
$ sudo ping_server -n b002::1
```

and the client on the host where forwarder B is running

```shell
$ sudo ping_client -n b002::1
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
