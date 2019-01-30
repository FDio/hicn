Hybrid Information-Centric Networking (hICN)
========================

## Introduction
hicn is an open source implementation of Cisco's hICN. It includes a network
stack, that implements ICN forwarding path in IPv6, and a transport stack
that implements two main transport protocols and a socket API.
The transport protocols provide one reliable transport service implementaton
and a real-time transport service for audio/video media.

## Directory layout

| Directory name         | Description                                    |
| ---------------------- | ---------------------------------------------- |
|      lib               | Core support library                           |
|      hicn-plugin       | VPP plugin                                     |
|      hicn-light        | Lightweight packet forwarder                   |
|      libtransport      | Support library with transport layer and API   |
|      utils             | Tools for testing                              |
|      apps              | Application examples using hicn stack          |


## Supported platforms

- Ubuntu 16.04 LTS (x86_64)
- Ubuntu 18.04 LTS (x86_64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7
- Android 8
- iOS 12
- macOS 10.12
- Windows 10
