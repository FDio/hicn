Hybrid ICN project: VPP plugin
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
- HICN_API_TEST_HEADER_FILES -- set the install directory for the header files. Default is <vpp install dir>/include/vpp_plugins/hicn
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

- VPP 19.01
  - DEB packages:
  - vpp
  - vpp-lib
  - vpp-dev
  - vpp-plugins

Hardware support:

- [DPDK](http://DPDK.org/) compatible nic

### Getting started ###
In order to start, the hICN plugin requires a running instance of VPP
The steps required to successfully start hICN are:

- Setup the host to run VPP
- Configure VPP to use DPDK compatible nics
- Start VPP
- Configure VPP interfaces
- Configure and start hICN

Detailed information for configuring VPP can be found at [https://wiki.fd.io/view/VPP](https://wiki.fd.io/view/VPP).

##### Setup the host for VPP #####

Hugepages must be enabled in the system

```
$ sudo sysctl -w vm.nr_hugepages=1024
```

In order to use a DPDK interface, the package vpp-dpdk-dkms must be installed in the system and the `uio` and `igb_uio` modules need to be loaded in the kernel

```
$ sudo apt install vpp-dpdk-dkms
$ sudo modprobe uio
$ sudo modprobe igb_uio
```

If the DPDK interface we want to assign to VPP is up, we must bring it down

```
$ sudo ifconfig <interface_name> down
```

##### Configure VPP #####
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
```
Where `0000:08:00.0` must be replaced with the actual PCI address of the DPDK interface

##### Start VPP #####

VPP can be started as a process or a service:

``` shell
Start VPP as a service in Ubuntu 16.04
$ sudo systemctl start vpp

Start VPP as a process in both 16.04
$ sudo vpp -c /etc/vpp/startup.conf

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
