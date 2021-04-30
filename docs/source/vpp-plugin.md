# VPP Plugin

## Introduction

A high-performance Hybrid ICN forwarder as a plugin to VPP.

The plugin provides the following functionalities:

- Fast packet processing
- Interest aggregation
- Content caching
- Forwarding strategies

## Quick start

All of these commands should be run from the code tree root.

VPP installed with DEB pkg:
```bash
cd hicn-plugin
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

VPP source code - build type `RELEASE`:
```bash
cd hicn-plugin
mkdir -p build
cd build
cmake .. -DVPP_HOME=<vpp dir>/build-root/install-vpp-native/vpp -DCMAKE_INSTALL_PREFIX=<vpp src>/build-root/install-vpp-native/vpp
make
sudo make install
```

VPP source code - build type `DEBUG`:
```bash
cd hicn-plugin
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=DEBUG -DVPP_HOME=<vpp dir>/build-root/install-vpp_debug-native/vpp -DCMAKE_INSTALL_PREFIX=<vpp src>/build-root/install-vpp_debug-native/vpp
make
sudo make install
```

CMAKE variables:
- `CMAKE_INSTALL_PREFIX`: set the install directory for the hicn-plugin. This
  is the common path to the lib folder containing vpp_plugins and
  vpp_api_test_plugins folders. Default is /usr/local.
- `VPP_HOME`: set the directory containing the include and lib directories of vpp.

## Using hICN plugin

### Dependencies

Build dependencies:

- VPP 20.01
  - DEB packages (can be found <https://packagecloud.io/fdio/release/install):>
    - vpp
    - libvppinfra-dev
    - vpp-dev

Runtime dependencies:

- VPP 20.01
  - DEB packages (can be found <https://packagecloud.io/fdio/release/install):>
    - vpp
    - vpp-plugin-core
    - vpp-plugin-dpdk (only to use DPDK compatible nics)

Hardware support (not mandatory):

- [DPDK](http://DPDK.org/) compatible NICs

## Getting started

In order to start, the hICN plugin requires a running instance of VPP.
The steps required to successfully start hICN are:

- Setup the host to run VPP
- Configure VPP to use DPDK compatible nics
- Start VPP
- Configure VPP interfaces
- Configure and start hICN

Detailed information for configuring VPP can be found at
[https://wiki.fd.io/view/VPP](https://wiki.fd.io/view/VPP).

### Setup the host for VPP

Hugepages must be enabled in the system.

```bash
sudo sysctl -w vm.nr_hugepages=1024
```

In order to use a DPDK interface, the `uio` and `uio_pci_generic` or `vfio_pci`
modules need to be loaded in the kernel.

```bash
sudo modprobe uio
sudo modprobe uio_pci_generic
sudo modprobe vfio_pci
```

If the DPDK interface we want to assign to VPP is up, we must bring it down:

```bash
sudo ifconfig <interface_name> down
```

or

```bash
sudo ip link set <interface_name> down
```

### Configure VPP

The file `/etc/VPP/startup.conf` contains a set of parameters to setup VPP
at startup. The following example sets up VPP to use a DPDK interface:

```bash
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

`0000:08:00.0` must be replaced with the actual PCI address of the DPDK
interface.

### Start VPP

VPP can be started as a process or a service:

Start VPP as a service in Ubuntu 16.04+:
```bash
sudo systemctl start vpp
```

Start VPP as a process:
```bash
sudo vpp -c /etc/vpp/startup.conf
```

### Configure hICN plugin

The hICN plugin can be configured either using the VPP command-line interface
(CLI), through a configuration file or through the VPP binary API.

#### hICN plugin CLI

The CLI commands for the hICN plugin start all with the `hicn` keyword.
To see the full list of command available type:

```bash
sudo vppctl
vpp# hicn ?
```

`hicn face show`: list the available faces in the forwarder.

```bash
hicn face show [<face_id>| type <ip/udp>]
  <face_id>                   :face id of which we want to display the informations
  <ip/udp>                    :shows all the ip or udp faces available
```

`hicn pgen client`: set an vpp forwarder as an hicn packet generator client.

```bash
hicn pgen client src <addr> n_ifaces <n_ifaces> name <prefix> lifetime <interest-lifetime> intfc <data in-interface> max_seq <max sequence number> n_flows <number of flows>
  <src_addr>                :source address to use in the interests, i.e., the locator for routing the data packet back
  <n_ifaces>                :set the number of ifaces (consumer faces) to emulate. If more than one, each interest is sent <n_ifaces> times, each of it with a different source address calculated from <src_addr>
  <prefix>                  :prefix to use to generate hICN names
  <interest-lifetime>       :lifetime of the interests
  <data in-interface>       :interface through which the forwarder receives data
  <max sequence number>     :max the sequence number to use in the interest. Cycling between 0 and this value
  <number of flows>         :emulate multiple flows downloaded in parallel
```

`hicn pgen server`: set an vpp forwarder as an hicn packet generator client.

```bash
hicn pgen server name <prefix> intfc <interest in-interface> size <payload_size>
  <prefix>                      :prefix to use to reply to interest
  <interest in-interface>       :interface through which the forwarder receives interest
  <payload_size>                :size of the data payload
```

`hicn show`: show forwarder information.

```bash
hicn show [detail] [strategies]
  <detail>                      :shows additional details as pit,cs entries allocation/deallocation
  <strategies>                  :shows only the available strategies int he forwarder
```

`hicn strategy mw set`: set the weight for a face.

```bash
hicn strategy mw set prefix <prefix> face <face_id> weight <weight>
  <prefix>                      :prefix to which the strategy applies
  <face_id>                     :id of the face to set the weight
  <weight>                       :weight
```

`hicn enable`: enable hICN forwarding pipeline for an ip prefix.

```bash
hicn enable <prefix>
  <prefix>                      :prefix for which the hICN forwarding pipeline is enabled
```

`hicn disable`: disable hICN forwarding pipeline for an ip prefix.

```bash
hicn enable <prefix>
  <prefix>                      :prefix for which the hICN forwarding pipeline is disable
```


#### hICN plugin configuration file

A configuration can be use to setup the hicn plugin when vpp starts.
The configuration file is made of a list of CLI commands. In order to set vpp
to read the configuration file, the file `/etc/vpp/startup.conf` needs to be
modified as follows:

```bash
unix {
  nodaemon
  log /tmp/vpp.log
  full-coredump
  startup-config <path to configuration file>
}
```

#### hICN plugin binary API

The binary api, or the vapi, can be used as well to configure the hicn plugin.
For each CLI command there is a corresponding message in the binary api.
The list of messages is available in the file hicn.api (located in
`hicn/hicn-plugin/src/`).

### Example: consumer and producer ping

In this example, we connect two vpp forwarders, A and B, each of them running
the hicn plugin. On top of forwarder A we run the `ping_client` application,
on top of forwarder B we run the `ping_server` application. Each application
connects to the underlying forwarder through a memif-interface. The two
forwarders are connected through a dpdk link.

#### Forwarder A (client)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/0 2001::2/64
vpp# set interface state TenGigabitEtherneta/0/0 up
vpp# ip route add b002::1/64 via remote 2001::3 TenGigabitEtherneta/0/0
vpp# hicn enable b002::1/64
```

#### Forwarder B (server)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/1 2001::3/64
vpp# set interface state TenGigabitEtherneta/0/1 up
```

Once the two forwarder are started, run the `ping_server` application on the
host where the forwarder B is running:

```bash
sudo ping_server -n b002::1
```

Then `ping_client` on the host where forwarder B is running:

```bash
sudo ping_client -n b002::1
```

### Example: packet generator

The packet generator can be used to test the performace of the hICN plugin, as
well as a tool to inject packet in a forwarder or network for other test use
cases It is made of two entities, a client that inject interest into a vpp
forwarder and a server that replies to any interest with the corresponding
data. Both client and server can run on a vpp that is configured to forward
interest and data as if they were regular ip packet or exploiting the hICN
forwarding pipeline (through the hICN plugin). In the following examples we show
how to configure the packet generator in both cases. We use two forwarder A and
B as in the previous example. However, both the client and server packet
generator can run on the same vpp forwarder is needed.


#### IP Forwarding

##### Forwarder A (client)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/0 2001::2/64
vpp# set interface state TenGigabitEtherneta/0/0 up
vpp# ip route add b001::/64 via 2001::3 TenGigabitEtherneta/0/0
vpp# ip route add 2001::3 via TenGigabitEtherneta/0/0
vpp# hicn pgen client src 2001::2 name b001::1/64 intfc TenGigabitEtherneta/0/0
vpp# exec /<path_to>pg.conf
vpp# packet-generator enable-stream hicn-pg
```

Where the file pg.conf contains the description of the stream to generate
packets.  In this case the stream sends 10 millions packets at a rate of 1Mpps

```bash
packet-generator new {
  name hicn-pg
  limit 10000000
  size 74-74
  node hicnpg-interest
  rate 1e6
  data {
    TCP: 5001::2 -> 5001::1
    hex 0x000000000000000050020000000001f4
    }
}
```

##### Forwarder B (server)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/1 2001::3/64
vpp# set interface state TenGigabitEtherneta/0/1 up
vpp# hicn pgen server name b001::1/64 intfc TenGigabitEtherneta/0/1
```

#### hICN Forwarding

##### Forwarder A (client)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/0 2001::2/64
vpp# set interface state TenGigabitEtherneta/0/0 up
vpp# ip route add b001::/64 via 2001::3 TenGigabitEtherneta/0/0
vpp# hicn enable b001::/64
vpp# create loopback interface
vpp# set interface state loop0 up
vpp# set interface ip address loop0 5002::1/64
vpp# ip neighbor loop0 5002::2 de:ad:00:00:00:00
vpp# hicn pgen client src 5001::2 name b001::1/64 intfc TenGigabitEtherneta/0/0
vpp# exec /<path_to>pg.conf
vpp# packet-generator enable-stream hicn-pg
```

The file pg.conf is the same showed in the previous example

##### Forwarder B (server)

```bash
sudo vppctl
vpp# set interface ip address TenGigabitEtherneta/0/1 2001::3/64
vpp# set interface state TenGigabitEtherneta/0/1 up
vpp# create loopback interface
vpp# set interface state loop0 up
vpp# set interface ip address loop0 2002::1/64
vpp# ip neighbor loop1 2002::2 de:ad:00:00:00:00
vpp# ip route add b001::/64 via 2002::2 loop0
vpp# hicn enable b001::/64
vpp# hicn pgen server name b001::1/64 intfc loop0
```
