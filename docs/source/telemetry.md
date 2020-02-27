# Telemetry

Tools to collect telemetry from hICN forwarders.

## Introduction

The project contains two plugins for [collectd](https://github.com/collectd/collectd):
* vpp: to collect statistics for VPP
* vpp-hicn: to collect statistics for [hICN](https://github.com/FDio/hicn)

Currently the two plugins provide the following functionalities:
* vpp: statistics (rx/tx bytes and packets) for each available interface.
* vpp-hicn: statistics (rx/tx bytes and packets) for each available face.

## Quick start

From the code tree root:

```bash
cd telemetry
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

## Using hICN collectd plugins

### Platforms

hICN collectd plugins have been tested in:

- Ubuntu 16.04 LTS (x86_64)
- Ubuntu 18.04 LTS (x86_64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7

### Dependencies

Build dependencies:

- VPP 20.01 - DEB packages (can be found on [packagecloud](https://packagecloud.io/fdio/release/install)):
  - vpp
  - libvppinfra-dev
  - vpp-dev
  - hicn-plugin-dev
- `collectd`: `sudo apt install collectd`

## Getting started

Collectd needs to be configured in order to use the hICN plugins.
To enable the plugins, add the following lines to `/etc/collectd/collectd.conf`:

```
LoadPlugin vpp
LoadPlugin vpp_hicn
```

Before running collectd, a vpp forwarder must be started. If the vpp-hicn plugin
is used, the hicn-plugin must be available in the vpp forwarder.

### Example: storing statistics from vpp and vpp-hicn

We'll use the rrdtool and csv plugins to store statistics from vpp and vpp-hicn.

Edit the configuration file as the following:

```html
######################################################################
# Global                                                             #
######################################################################
FQDNLookup true
BaseDir "/collectd"
Interval 1

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
  DataDir "/collectd/rrd" # the folder under which statistics are written in rrd
</Plugin>
```

Run vpp and collectd:

```
systemctl start vpp
systemctl start collectd
```
