# Code structure

## Introduction

hicn is an open source implementation of Cisco's hICN. It includes a network
stack, that implements ICN forwarding path in IPv6, and a transport stack that
implements two main transport protocols and a socket API. The transport
protocols provide one reliable transport service implementation and a real-time
transport service for audio/video media.

## Directory layout


| Directory name | Description                                               |
| -------------- | --------------------------------------------------------- |
| lib            | Core support library                                      |
| hicn-plugin    | VPP plugin                                                |
| hicn-light     | Lightweight packet forwarder                              |
| libtransport   | Support library with transport layer and API              |
| utils          | Tools for testing                                         |
| apps           | Application examples using hicn stack                     |
| ctrl           | Tools and libraries for network management and control    |

hicn plugin is a VPP plugin that implement hicn packet processing as specified
in [1] The transport library is used to implement the hicn host stack and makes
use of libmemif as high performance connector between transport and the network
stack. The transport library makes use of VPP binary API to configure the local
namespace (local face management).

## Release note

The current master branch provides the latest release which is compatible with
the latest VPP stable. No other VPP releases are supported nor maintained. At
every new VPP release distribution hicn master branch is updated to work with
the latest stable release. All previous stable releases are discontinued and not
maintained. The user who is interested in a specific release can always checkout
the right code tree by searching the latest commit under a given git tag
carrying the release version.

The Hybrid ICN software distribution can be installed for several platforms. The
network stack comes in two different implementations: one scalable based on VPP
and one portable based on IPC and sockets.

The transport stack is a unique library that is used for both the scalable and
portable network stacks.

## Supported platforms

- Ubuntu 20.04 LTS (amd64, arm64)
- Android 10 (amd64, arm64)
- iOS 15
- macOS 12.3
- Windows 10

Other platforms and architectures may work.
You can either use released packages, or compile hicn from sources.

### Ubuntu

```bash
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
```

The following debian packages for Ubuntu are available dor amd64 and arm64

```bash
facemgr-dev
facemgr
hicn-apps-dev
hicn-apps
hicn-light
hicn-plugin-dev
hicn-plugin
libhicn-dev
libhicn
libhicnctrl-dev
libhicnctrl-modules
libhicnctrl
libhicntransport-dev
libhicntransport-io-modules
libhicntransport
```

### macOS

```bash
brew tap icn-team/hicn-tap
brew install hicn
```

or

```bash
git clone https://github.com/FDio/hicn.git
$ cd hicn
$ OPENSSL_ROOT_DIR=/usr/local/opt/openssl\@1.1 make build-release
```

### Android
hICN is built as a native library for the Android NDK which are packaged
as Android archives AAR and made available in a Maven repository in
Github Packages in

<https://github.com/orgs/icn-team/packages>

To build from sources, refer to the Android SDK in

<https://github.com/icn-team/android-sdk>

Install the applications via the Google Play Store

<https://play.google.com/store/apps/developer?id=ICN+Team>

### iOS

Clone this distro

```bash
git clone https://github.com/icn-team/ios-sdk.git
cd ios-sdk
```
Compile everything (dependencies and hICN modules)

```bash
make update
make all
```
Compile everything with Qt (dependencies, hICN modules and Viper dependencies)

```bash
make update
make all_qt
```

### Windows

Install vcpkg

```bash
git clone https://github.com/icn-team/windows-sdk
.\windows-sdk\scripts\init.bat
```


```bash
cd windows-sdk
make all
```

### Docker

Several docker images are nightly built with the latest software  for Ubuntu 18
LTS (amd64/arm64), and available on docker hub at
<https://hub.docker.com/u/icnteam>.

The following images are nightly built and maintained.

```bash
docker pull icnteam/vswitch:amd64
docker pull icnteam/vswitch:arm64

docker pull icnteam/vserver:amd64
docker pull icnteam/vserver:arm64

docker pull icnteam/vhttpproxy:amd64
docker pull icnteam/vhttpproxy:arm64
```

Other Dockerfiles are included in the main git repo for development.

### Vagrant

Vagrant boxes for a virtual switch are available at
<https://app.vagrantup.com/icnteam>

```bash
vagrant box add icnteam/vswitch
```

Supported providers are libvirt, vmware and virtualbox.

## References

Giovanna Carofiglio, Luca Muscariello, Jordan Augé, Michele Papalini, Mauro
Sardara, and Alberto Compagno. 2019. Enabling ICN in the Internet Protocol:
Analysis and Evaluation of the Hybrid-ICN Architecture. In Proceedings of the
6th ACM Conference on Information-Centric Networking (ICN '19). Association for
Computing Machinery, New York, NY, USA, 55–66.
DOI: https://doi.org/10.1145/3357150.3357394

## License

This software is distributed under the following license:

```bash
Copyright (c) 2019-2022 Cisco and/or its affiliates.
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
