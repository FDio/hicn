# Control plane support

Control plane functionalities are provides via SDN controllers or via standard
IP routing protocols. SDN support is provided by using the NETCONF/YANG protocol
for network management, control and telemetry.

Routing is supported via synchronization of the IP FIB and the IP RIB as implemented
by one of the routing protocols in FRR. Without loss of generality we have reported
below one example of IGP routing via OSPF for IPv6.

The VPP IP FIB can be controlled and updated by one FRR routing protocol which
is used for routing over locators and also over hICN name prefixes.

## NETCONF/YANG

### Getting started

NETCONF/YANG support is provided via several external components such as
libyang, sysrepo, libnetconf and netopeer.
The hicn project provides a sysrepo plugin and a YANG model for two devices:
the VPP based hicn virtual switch and the portable forwarder.
The YANG model for the VPP based hICN vSwitch is based the full hICN C API
exported by the VPP plugin with the addition of some VPP APIs such as
interface and FIB management which are required by the hICN plugin.

To install libyang, sysrepo, libnetconf and netopeer2 for Ubuntu18 amd64/arm64
or CentOS 7 and ad-hoc repository is available and maintained in bintray
at <https://dl.bintray.com/icn-team/apt-hicn-extras>.

For instance in Ubuntu 18 LTS:

Install the sysrepo YANG data store and a NETCONF server:

```bash
echo "deb [trusted=yes] https://dl.bintray.com/icn-team/apt-hicn-extras bionic main" \
                                            | tee -a /etc/apt/sources.list
apt-get update && apt-get install -y libyang sysrepo libnetconf2 netopeer2-server
```

Install the VPP based hICN virtual switch:

```bash
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
apt-get update && apt-get install -y hicn-plugin vpp-plugin-dpdk hicn-sysrepo-plugin
```

The hICN YANG models are installed under `/usr/lib/$(uname -m)-linux-gnu/modules_yang`.

Configure the NETCONF/YANG components:

```bash
bash /usr/bin/setup.sh sysrepoctl /usr/lib/$(uname -m)-linux-gnu/modules_yang root
bash /usr/bin/merge_hostkey.sh sysrepocfg openssl
bash /usr/bin/merge_config.sh sysrepocfg genkey
```

You can manually install the yang model using the following bash script:

```bash
EXIT_CODE=0
command -v sysrepoctl > /dev/null
if [ $? != 0 ]; then
    echo "Could not find command \"sysrepoctl\"."
     exit ${EXIT_CODE}
else
sysrepoctl --install --yang=path_to_hicn_yang_model
fi
```

### YANG model

hicn.yang can be found in the yang-model. It consists of two container nodes:

```text
|--+ hicn-conf: holds the configuration data;
|  |--+ params: contains all configuration parameters;
|--+ hicn-state: provides the state data
|  |--+ state,
|  |--+ strategy,
|  |--+ strategies,
|  |--+ route,
|  |--+ face-ip-params
and corresponding leaves.
```

A controller can configure these parameters through the edit-config RPC
call. This node can be used to enable and to initialize the hicn-plugin in VPP
instance. hicn-state container is used to provide the state data to the
controller. It consists of state, strategy, strategies, route, and face-ip-params
nodes with the corresponding leaves. In the hicn model a variety of RPCs are provided
to allow controller to communicate with the hicn-plugin as well as update the state
data in hicn-state.

### Example

To setup the startup configuration you can use the following script:

```bash
EXIT_CODE=0
command -v sysrepocfg > /dev/null
if [ $? != 0 ]; then
    echo "Could not find command \"sysrepocfg\"."
     exit ${EXIT_CODE}
else
sysrepocfg -d startup -i path_to_startup_xml -f xml hicn
fi
```

startup.xml is placed in the yang-model. Here you can find the content:

```xml
<hicn-conf  xmlns="urn:sysrepo:hicn">
<params>
    <enable_disable>false</enable_disable>
    <pit_max_size>-1</pit_max_size>
    <cs_max_size>-1</cs_max_size>
    <cs_reserved_app>-1</cs_reserved_app>
    <pit_dflt_lifetime_sec>-1</pit_dflt_lifetime_sec>
    <pit_max_lifetime_sec>-1</pit_max_lifetime_sec>
    <pit_min_lifetime_sec>-1</pit_min_lifetime_sec>
</params>
</hicn-conf>
```

It contains the leaves of the parameters in hicn-conf node which is
used as the startup configuration. This configuration can be changed through the
controller by subscribing which changes the target to the running state. hicn
yang model provides a list of RPCs which allows controller to communicate
directly with the hicn-plugin. This RPCs may also cause the modification in
state data.

In order to run different RPCs from controller you can use the examples in the
controler_rpcs_instances.xml in the yang-model. Here you can find the content:

```xml
<node-params-get xmlns="urn:sysrepo:hicn"/>

<node-stat-get xmlns="urn:sysrepo:hicn"/>

<strategy-get xmlns="urn:sysrepo:hicn">
    <strategy_id>0</strategy_id>
</strategy-get>

<strategies-get xmlns="urn:sysrepo:hicn"/>

<route-get xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
</route-get>

<route-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
</route-del>

<route-nhops-add xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <face_ids0>40</face_ids0>
    <face_ids1>50</face_ids1>
    <face_ids2>60</face_ids2>
    <face_ids3>70</face_ids3>
    <face_ids4>80</face_ids4>
    <face_ids5>90</face_ids5>
    <face_ids6>100</face_ids6>
    <n_faces>110</n_faces>
</route-nhops-add>

<route-nhops-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <faceid>40</faceid>
</route-nhops-del>

<face-ip-params-get xmlns="urn:sysrepo:hicn">
    <faceid>10</faceid>
</face-ip-params-get>

<face-ip-add xmlns="urn:sysrepo:hicn">
    <nh_addr0>10</nh_addr0>
    <nh_addr1>20</nh_addr1>
    <swif>30</swif>
</face-ip-add>

<face-ip-del xmlns="urn:sysrepo:hicn">
    <faceid>0</faceid>
</face-ip-del>

<punting-add xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <swif>40</swif>
</punting-add>

<punting-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <swif>40</swif>
</punting-del>
```

#### Run the plugin

Firstly, verify the plugin and binary libraries are located correctly, then run
the vpp through (service vpp start). Next, run the sysrepo daemon (sysrepod),
for debug mode: sysrepo -d -l 4 which runs with high verbosity. Then, run the
sysrepo plugin (sysrepo-plugind), for debug mode: sysrep-plugind -d -l 4 which
runs with high verbosity. Now, the hicn sysrepo plugin is loaded. Then, run the
netopeer2-server which serves as NETCONF server.

#### Connect from netopeer2-cli

In order to connect through the netopeer client run the netopeer2-cli. Then,
follow these steps:

- connect --host XXX --login XXX
- get (you can get the configuration and operational data)
- get-config (you can get the configuration data)
- edit-config --target running --config

You can modify the configuration but it needs an xml configuration input.

```xml
<hicn-conf  xmlns="urn:sysrepo:hicn">
<params>
    <enable_disable>false</enable_disable>
    <pit_max_size>-1</pit_max_size>
    <cs_max_size>-1</cs_max_size>
    <cs_reserved_app>-1</cs_reserved_app>
    <pit_dflt_lifetime_sec>-1</pit_dflt_lifetime_sec>
    <pit_max_lifetime_sec>-1</pit_max_lifetime_sec>
    <pit_min_lifetime_sec>-1</pit_min_lifetime_sec>
</params>
</hicn-conf>
```

- user-rpc (you can call one of the rpc proposed by hicn model but it needs an xml input)

#### Connect from OpenDaylight (ODL) controller

In order to connect through the OpenDaylight follow these procedure:

- run karaf distribution (./opendayligh_installation_folder/bin/karaf)
- install the required feature list in DOL (feature:install odl-netconf-server
  odl-netconf-connector odl-restconf-all odl-netconf-topology or
  odl-netconf-clustered-topology)
- run a rest client program (e.g., postman or RESTClient)
- mount the remote netopeer2-server to the OpenDaylight by the following REST API:

  ```
  PUT <http://localhost:8181/restconf/config/network-topology:network-topology/topology/topology-netconf/node/hicn-node>`
  ```
  with the following body:

  ```xml
  <node xmlns="urn:TBD:params:xml:ns:yang:network-topology">
    <node-id>hicn-node</node-id>
    <host xmlns="urn:opendaylight:netconf-node-topology">Remote_NETCONF_SERVER_IP</host>
    <port xmlns="urn:opendaylight:netconf-node-topology">830</port>
    <username xmlns="urn:opendaylight:netconf-node-topology">username</username>
    <password xmlns="urn:opendaylight:netconf-node-topology">password</password>
    <tcp-only xmlns="urn:opendaylight:netconf-node-topology">false</tcp-only>
    <keepalive-delay xmlns="urn:opendaylight:netconf-node-topology">1</keepalive-delay>
  </node>
  ```

  Note that the header files must be set to `Content-Type: application/xml, Accept: application/xml`.

- send the operation through the following REST API:

POST <http://localhost:8181/restconf/operations/network-topology:network-topology/topology/topology-netconf/node/hicn-node/yang-ext:mount/ietf-netconf:edit-config>

The body can be used the same as edit-config in netopeer2-cli.

#### Connect from Cisco Network Services Orchestrator (NSO)

To connect NSO to the netopeer2-server, first, you need to write a NED package
for your device. The procedure to create NED for hicn is explained in the
following:

Place hicn.yang model in a folder called hicn-yang-model, and follow these steps:

- ncs-make-package --netconf-ned ./hicn-yang-model ./hicn-nso
- cd hicn-nso/src; make
- ncs-setup --ned-package ./hicn-nso --dest ./hicn-nso-project
- cd hicn-nso-project
- ncs
- ncs_cli -C -u admin
- configure
- devices authgroups group authhicn default-map remote-name user_name remote-password password
- devices device hicn address IP_device port 830 authgroup authhicn device-type netconf
- state admin-state unlocked
- commit
- ssh fetch-host-keys

At this point, we are able to connect to the remote device.

## Release note

The current version is compatible with the 20.01 VPP stable and sysrepo devel.

## Configure VPP and FRRouting for OSPF4
This document describes how to configure the VPP with hicn_router plugin and FRR to enable the OSPF protocol. The VPP and FRR
are configured in a docker file.

### DPDK configuration on host machine:
```
- Install and configure dpdk
    - make install T=x86_64-native-linux-gcc && cd x86_64-native-linux-gcc && sudo make install
    - modprobe uio
    - modprobe uio_pci_generic
    - dpdk-devbind --status
    - the PCIe number of the desired device can be observed ("xxx")
    - sudo dpdk-devbind -b uio_pci_generic "xxx"
```
### VPP configuration:
```
- Run and configure the VPP (hICN router plugin is required to be installed in VPP)
    - set int state TenGigabitEtherneta/0/0 up
    - set int ip address TenGigabitEtherneta/0/0 10.0.10.1/24
    - enable tap-inject  # This creates the taps by router plugin
    - show tap-inject # This shows the created taps
    - ip mroute add 224.0.0.4/32 via local Forward
    - ip mroute add 224.0.0.4/32 via TenGigabitEtherneta/0/0 Accept

- Setup the tap interface
    - ip addr add 10.0.10.1/24 dev vpp0
    - ip link set dev vpp0 up
```
### FRR configuration:
```
- Run and configure FRRouting (ospf)
    - /usr/lib/frr/frrinit.sh start &
    - vtysh
    - configure terminal
    - router ospf
    - network 10.0.10.1/24 area 0.0.0.0
    - end
    - wr
```
After the following configuration, the traffic over tap interface can be observered through "tcpdump- i vpp0".

## Routing plugin for VPP and FRRouting for OSPF6

This document describes how to configure the VPP with hicn_router
plugin and FRR to enable the OSPF protocol. The VPP and FRR
are configured in a docker file.

### DPDK configuration on host machine

Install and configure DPDK:
```bash
make install T=x86_64-native-linux-gcc && cd x86_64-native-linux-gcc && sudo make install
modprobe uio
modprobe uio_pci_generic
dpdk-devbind --status
the PCIe number of the desired device can be observed ("xxx")
sudo dpdk-devbind -b uio_pci_generic "xxx"
```

### VPP configuration

Run and configure the VPP (hICN router plugin is required to be installed in VPP):
```bash
vpp# set int state TenGigabitEtherneta/0/0 up
vpp# set int ip address TenGigabitEtherneta/0/0 a001::1/24
vpp# create loopback interface
vpp# set interface state loop0 up
vpp# set interface ip address loop0 b001::1/128
vpp# enable tap-inject  # This creates the taps by router plugin
vpp# show tap-inject # This shows the created taps
vpp# ip mroute add ff02::/64 via local Forward  # ff02:: is multicast ip address
vpp# ip mroute add ff02::/64 via TenGigabitEtherneta/0/0 Accept
vpp# ip mroute add ff02::/64 via loop0 Accept
```

Setup the tap interface:
```bash
ip addr add a001::1/24 dev vpp0
ip addr add b001::1/128 dev vpp1
ip link set dev vpp0 up
ip link set dev vpp1 up
```

### FRR configuration

Install FRR in Ubuntu 18 LTS:
<http://docs.frrouting.org/projects/dev-guide/en/latest/building-frr-for-ubuntu1804.html>

Run and configure FRRouting (ospf):
```text
/usr/lib/frr/frrinit.sh start &
vtysh
configure terminal
router ospf6
area 0.0.0.0 range a001::1/24
area 0.0.0.0 range b001::1/128
interface vpp0 area 0.0.0.0
interface vpp1 area 0.0.0.0
end
wr
add  "no ipv6 nd suppress-ra" to the first configuration part of the /etc/frr/frr.conf
```

After the following configuration, the traffic over tap interface can be observed
via `tcpdump- i vpp1`. The neighborhood and route can be seen with the
`show ipv6 ospf6 neighbor/route` command.

## Configure VPP and FRRouting for BGP
This document describes how to configure the VPP with hicn_router plugin and FRR to enable the BGP protocol. The VPP and FRR
are configured in a docker file.

### DPDK configuration on host machine:
```
- Install and configure dpdk
    - make install T=x86_64-native-linux-gcc && cd x86_64-native-linux-gcc && sudo make install
    - modprobe uio
    - modprobe uio_pci_generic
    - dpdk-devbind --status
    - the PCIe number of the desired device can be observed ("xxx")
    - sudo dpdk-devbind -b uio_pci_generic "xxx"
```
### VPP configuration:

```
- Run and configure the VPP (hICN router plugin is required to be installed in VPP)
    - set int state TenGigabitEtherneta/0/0 up
    - set int ip address TenGigabitEtherneta/0/0 10.0.10.1/24
    - enable tap-inject  # This creates the taps by router plugin
    - show tap-inject # This shows the created taps

- Setup the tap interface
    - ip addr add 10.0.10.1/24 dev vpp0
    - ip link set dev vpp0 up
```
### FRR configuration:
Assume there are two nodes with 1234,5678 AS numbers. This is the configuration of node A with AS number 1234

                                             (1234)A(2001::1) ====== (2001::2)B(5678)
```
   - /usr/lib/frr/frrinit.sh start &
   - vtysh
   - configure terminal
   - router bgp 1234
   - neighbor 2001::2 remote-as 5678
   - address-family ipv6 unicast
   - neighbor 2001::2 activate
   - exit-address-family
```
