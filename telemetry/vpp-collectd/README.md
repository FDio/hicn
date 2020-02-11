Hybrid ICN project: Telemetry
==============================

Tools to collect telemetry measurements from hICN forwarders.

## Introduction ##

The project containes two plugins for [collectd](https://github.com/collectd/collectd):
* vpp: to collect statistics for VPP
* vpp-hicn: to collect statistics for [hICN](https://github.com/FDio/hicn)


Currently the two plugins provide the followign funtionalities:

* VPP: statistics (rx/tx bytes and packets) for each available interface.
* HICN-VPP: statistics (rx/tx bytes and packets) for each available face.

## Quick Start ## 

```
From the code tree root

$ cd telemetry
$ mkdir -p build
$ cd build
$ cmake .. -DCMAKE_INSTALL_PREFIX=/usr
$ make
$ sudo make install
```

## Using hICN collectd plugins ##

### Platforms ###

hICN collectd plugins have been tested in:

- Ubuntu 16.04 LTS (x86_64)
- Ubuntu 18.04 LTS (x86_64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7


### Dependencies ###

Build dependencies:

- VPP 20.01
  - DEB packages (can be found https://packagecloud.io/fdio/release/install):
  - vpp
  - libvppinfra-dev
  - vpp-dev
  - hicn-plugin-dev

## Getting started ##

Collectd needs to be configured in order to use the hICN collectd plugins.
The configuration can be achieved editing the file '/etc/collectd/collectd.conf' and adding the following lines:

```
LoadPlugin vpp
LoadPlugin vpp_hicn
```

Before running collectd, a vpp forwarder must be started. If the vpp-hicn plugin is used, the hicn-plugin must be available in the vpp forwarder

### Example: use rrdtool and csv plugin to store statistics from vpp and vpp-hicn plugins

Edit the configuration file as the following:

```
######################################################################
# Global                                                             #
######################################################################
FQDNLookup true
BaseDir "/collectd"
Interval 2

######################################################################
# Logging                                                            #
######################################################################
LoadPlugin logfile

<Plugin logfile>
  LogLevel "info"
  File "/var/log/collectd.log"
  Timestamp true
  PrintSeverity true
</Plugin>

######################################################################
# Plugins                                                            #
######################################################################
LoadPlugin csv
LoadPlugin rrdtool
LoadPlugin vpp
LoadPlugin vpp_hicn

######################################################################
# Plugin configuration                                               #
######################################################################
<Plugin csv>
  DataDir "/collectd/csv" # the folder under which statistics are written in csv
  StoreRates true
</Plugin>

<Plugin rrdtool>
  DataDir "/collectd/rrd" # the folder under which statistics are written in csv
</Plugin>
```

Run vpp and collectd

```
$ systemctl start vpp
$ systemctl start collectd
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
distributed under the License is distributed on an "AS IS" BASIS,ls
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
