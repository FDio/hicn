Hybrid Information-Centric Networking (hICN)

## Introduction
hicn is an open source implementation of Cisco's hICN. It includes a network stack, that implements
ICN forwarding path in IPv6, and a transport stack that implements two main transport protocols and
a socket API. The transport protocols provide one reliable transport service implementaton and a
real-time transport service for audio/video media.

## Directory layout

| Directory name | Description                                               |
| -------------- | --------------------------------------------------------- |
| lib            | Core support library                                      |
| hicn-plugin    | VPP plugin                                                |
| hicn-light     | Lightweight packet forwarder                              |
| libtransport   | Support library with transport layer and API              |
| utils          | Tools for testing                                         |
| apps           | Application examples using hicn stack                     |
| ctrl           | Tools and libraries for network configuration and control |

hicn plugin is a VPP plugin that implement hicn packet processing as specified in
https://datatracker.ietf.org/doc/draft-muscariello-intarea-hicn/. The transport library is used to
implement the hicn host stack and makes use of libmemif as high performance connector between
transport and the network stack. The transport library makes use of VPP binary API to configure the
local namespace (local face management).
=======

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

## License ##

This software is distributed under the following license:

```
Copyright (c) 2017-2019 Cisco and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

## Release note
The current master branch provides the 19.08 release which is compatible with the 19.08 VPP stable.
No other VPP releases are supported nor maintained. At every new VPP release distribution hicn
master branch is updated to work with the latest stable release. All previous stable releases
are discontinued and not maintained. The user who is interested in a specific release can always
checkout the rigth code tree by searching the latest commit under a given git tag carrying the
release version.
