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

- VPP 20.01, Debian packages can be found on [packagecloud](https://packagecloud.io/fdio/release/install):
  - vpp
  - libvppinfra-dev
  - vpp-dev
  - hicn-plugin-dev
- `collectd` and `collectd-dev`: `sudo apt install collectd collectd-dev`

## Getting started

Collectd needs to be configured in order to use the hICN plugins.
To enable the plugins, add the following lines to `/etc/collectd/collectd.conf`:

```
LoadPlugin vpp
LoadPlugin vpp_hicn
```

Before running collectd, a vpp forwarder must be started. If the vpp-hicn plugin
is used, the hicn-plugin must be available in the vpp forwarder.

If you need the custom types that the two plugins define, they are present in
`telemetry/custom_types.db`. It is useful if you are using InfluxDB as it requires
the type database for multi-value metrics
(see [CollectD protocol support in InfluxDB](https://docs.influxdata.com/influxdb/v1.7/supported_protocols/collectd/)).

## Plugin options
`vpp` and `vpp-hicn` have the same two options:
- `Verbose` enables additional statistics. You can check the sources to have an exact list of available metrics.
- `Tag` tags the data with the given string. Useful for identifying the context in which the data was retrieved in InfluxDB for instance. If the tag value is `None`, no tag is applied.

### Example: storing statistics from vpp and vpp-hicn

We'll use the rrdtool and csv plugins to store statistics from vpp and vpp-hicn.
Copy the configuration below in a file called `collectd.conf` and move
it to `/etc/collectd`:

```
######################################################################
# Global                                                             #
######################################################################
FQDNLookup true
BaseDir "/var/lib/collectd"
Interval 1
# if you are using custom_types.db, you can specify it
TypesDB "/usr/share/collectd/types.db" "/etc/collectd/custom_types.db"

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
  DataDir "/var/lib/collectd/csv"  # the folder where statistics are stored in csv
  StoreRates true
</Plugin>

<Plugin rrdtool>
  DataDir "/var/lib/collectd/rrd"  # the folder where statistics are stored in rrd
</Plugin>

<Plugin vpp>
  Verbose true
  Tag "None"
</Plugin>

<Plugin vpp_hicn>
  Verbose true
  Tag "None"
</Plugin>
```

Run vpp and collectd:

```
systemctl start vpp
systemctl start collectd
```
