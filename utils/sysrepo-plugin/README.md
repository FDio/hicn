# hICN plugin for sysrepo (2019)

This plugin serves as a data management agent that runs on the same host as a VPP instance. It provides yang models via NETCONF to allow the management of hicn-plugin that runs in VPP instance from out-of-box.

## Software Requirement

- VPP

- hicn-plugin

- sysrepo

## hICN yang model installation

You can install the yang model in the sysrepo as follows:

sysrepoctl --install --yang=hicn.yang

hicn.yang model can be found under plugin/yang/model/hicn.yang

To setup the startup configuration you can use the following:

sysrepocfg -d startup -i startup.xml -f xml hicn

startup.xml is placed under plugin/yang/startup.xml

In order to run different RPCs  from netconf client you can use the examples in the hicn_netconf_client.xml

## Release note

The current version is compatible with the 19.01 VPP stable and sysrepo 0.7.7.