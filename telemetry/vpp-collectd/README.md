# vpp-collectd

Two plugins for [collectd](https://github.com/collectd/collectd) are present in this repository:
* vpp: statistics for VPP
* vpp-hicn: statistics for [hICN](https://github.com/FDio/hicn)

VPP must be running in order for the plugins to work.

## Installation
Run:
```sh
./install.sh
```

A minimal collectd configuration is also present in [collectd_docker.conf](collectd_docker.conf) for a docker container running [vServer](https://github.com/icn-team/vServer).
