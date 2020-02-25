# Getting Started

## Introduction

hicn is an open source implementation of Cisco's hICN. It includes a network stack, that implements
ICN forwarding path in IPv6, and a transport stack that implements two main transport protocols and
a socket API. The transport protocols provide one reliable transport service implementation and a
real-time transport service for audio/video media.

## Directory Layout

```text
| Directory name | Description                                               |
| -------------- | --------------------------------------------------------- |
| lib            | Core support library                                      |
| hicn-plugin    | VPP plugin                                                |
| hicn-light     | Lightweight packet forwarder                              |
| libtransport   | Support library with transport layer and API              |
| utils          | Tools for testing                                         |
| apps           | Application examples using hicn stack                     |
| ctrl           | Tools and libraries for network management and control    |
```

hicn plugin is a VPP plugin that implement hicn packet processing as specified in
<https://datatracker.ietf.org/doc/draft-muscariello-intarea-hicn/.> The transport library is used to
implement the hicn host stack and makes use of libmemif as high performance connector between
transport and the network stack. The transport library makes use of VPP binary API to configure the
local namespace (local face management).

## Release note

The current master branch provides the latest release which is compatible with the latest VPP stable.
No other VPP releases are supported nor maintained. At every new VPP release distribution hicn
master branch is updated to work with the latest stable release. All previous stable releases
are discontinued and not maintained. The user who is interested in a specific release can always
checkout the right code tree by searching the latest commit under a given git tag carrying the
release version.

The Hybrid ICN software distribution can be installed for several platforms.
The network stack comes in two different implementations: one scalable based
on VPP and one portable based on IPC and sockets.

The transport stack is a unique library that is used for both the scalable
and portable network stacks.

## Supported Platforms

- Ubuntu 18.04 LTS (amd64, arm64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7
- Android 10 (amd64, arm64)
- iOS 13
- macOS 10.15
- Windows 10

Other platforms and architectures may work.
You can either use released packages, or compile hicn from sources.

### Ubuntu

```bash
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
```

### CentOS

```bash
curl -s https://packagecloud.io/install/repositories/fdio/release/script.rpm.sh | sudo bash
```

### macOS

```bash
brew install hicn
```

### Android

Install the applications via the Google Play Store
<https://play.google.com/store/apps/developer?id=ICN+Team>

### iOS

Coming soon.

### Windows

Coming soon.

### Docker

Several docker images are nightly built with the latest software  for Ubuntu 18 LTS (amd64/arm64),
and available on docker hub at  <https://hub.docker.com/u/icnteam>.

The following images are nightly built and maintained.

```bash
docker pull icnteam/vswitch:amd64
docker pull icnteam/vswitch:arm64

docker pull icnteam/vserver:amd64
docker pull icnteam/vserver:arm64

docker pull icnteam/vhttpproxy:amd64
docker pull icnteam/vhttpproxy:arm64
```

### Vagrant

Vagrant boxes for a virtual switch are available at
<https://app.vagrantup.com/icnteam>

```bash
vagrant box add icnteam/vswitch
```

Supported providers are libvirt, vmware and virtualbox.

## License

This software is distributed under the following license:

```bash
Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
