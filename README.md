# Hybrid Information-Centric Networking (hICN)

## Introduction

This is an open source implementation of Cisco's hICN. It includes a network
stack, that implements ICN forwarding path in IPv6, and a transport stack that
implements reliable and unrelieable transport with congestion control and loss
management by ARQ or FEC. It supports applications such as reliable multicast
for ABR video, real-time video conferencing and on-line multiplayer games.
The client stack has been tested on iOS and Android over Wi-Fi, LTE and Ethernet
including multi-homing use cases.

## Directory layout

| Directory name | Description                                               |
| -------------- | --------------------------------------------------------- |
| lib            | Core support library                                      |
| hicn-plugin    | VPP plugin                                                |
| hicn-light     | Lightweight packet forwarder                              |
| libtransport   | Support library with transport layer and API              |
| apps           | Application examples using hicn stack and tools           |
| ctrl           | Tools and libraries for network configuration and control |

hicn plugin is a VPP plugin that implement hicn packet processing as specified
in https://datatracker.ietf.org/doc/draft-muscariello-intarea-hicn/. The
transport library is used to implement the hicn host stack and makes use of
libmemif as high performance connector between transport and the network stack.
The transport library makes use of VPP binary API to configure the local
namespace (local face management).

## Supported platforms

- Ubuntu 20.04 LTS (amd64, arm64)
- Android 10+
- iOS 13+
- macOS 10.15+
- Windows 10+

## Binaries

### Ubuntu (amd64, arm64)

<https://packagecloud.io/fdio/release>

### Docker

<https://hub.docker.com/u/icnteam>

### Release note

The current master branch provides the latest release which is compatible with
the latest VPP stable. No other VPP releases are supported nor maintained. At
every new VPP release distribution hicn master branch is updated to work with
the latest stable release. All previous stable releases are discontinued and not
maintained. The user who is interested in a specific release can always checkout
the right code tree by searching the latest commit under a given git tag
carrying the release version.
