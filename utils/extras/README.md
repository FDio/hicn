# Configure VPP and FRRouting for OSPF6
This document describes how to configure the VPP with hicn_router plugin and FRR to enable the OSPF protocol. The VPP and FRR
are configured in a docker file.

## DPDK configuration on host machine:

- Install and configure dpdk
    - make install T=x86_64-native-linux-gcc && cd x86_64-native-linux-gcc && sudo make install
    - modprobe uio
    - modprobe uio_pci_generic
    - dpdk-devbind --status
    - the PCIe number of the desired device can be observed ("xxx")
    - sudo dpdk-devbind -b uio_pci_generic "xxx"
## VPP configuration:

- Run and configure the VPP (hICN router plugin is required to be installed in VPP)
    - set int state TenGigabitEtherneta/0/0 up
    - set int ip address TenGigabitEtherneta/0/0 a001::1/24
    - create loopback interface
    - set interface state loop0 up
    - set interface ip address loop0 b001::1/128
    - enable tap-inject  # This creates the taps by router plugin
    - show tap-inject # This shows the created taps
    - ip mroute add ff02::/64 via local Forward  # ff02:: is multicast ip address
    - ip mroute add ff02::/64 via TenGigabitEtherneta/0/0 Accept
    - ip mroute add ff02::/64 via loop0 Accept

- Setup the tap interface
    - ip addr add a001::1/24 dev vpp0
    - ip addr add b001::1/128 dev vpp1
    - ip link set dev vpp0 up
    - ip link set dev vpp1 up

## FRR configuration:

- Run and configure FRRouting (ospf)
    - /usr/lib/frr/frrinit.sh start &
    - vtysh
    - configure terminal
    - router ospf6
    - area 0.0.0.0 range a001::1/24
    - area 0.0.0.0 range b001::1/128
    - interface vpp0 area 0.0.0.0
    - interface vpp1 area 0.0.0.0
    - end
    - wr
    - add  "no ipv6 nd suppress-ra" to the first configurtion part of the /etc/frr/frr.conf
After the following configuration, the traffic over tap interface can be observered through "tcpdump- i vpp1".
The neighborhood and route can be seen by the "show ipv6 ospf6 neighbor/route".
