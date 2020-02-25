# Core library

## Introduction

libhicn provides a support library coded in C designed to help developers embed
Hybrid ICN (hICN) functionalities in their applications (eg. forwarder, socket
API, etc.). Its purpose is to follow the hICN specification for which it
provides a reference implementation, abstracting the user from all internal
mechanisms, and offering an API independent of the packet format (eg. IPv4 or
IPv6). The library is designed to be portable across both desktop and
mobile platforms, and we currently aim at supporting Linux, Android, OSX and
iOS, by writing the necessary adapters to realize hICN functionality in
userspace according to the available APIs and permissions that each system
offers.

The library consists in several layers:

- the core library (hicn.h) provides a standard hICN packet format, as well as
an API allowing manipulation of packet headers;
- an hICN helper, allowing an hICN stack to be built in userspace in a portable
way, based on TUN devices and accessible though file descriptors;
- a network layer allow the sending an receiving of hICN packets on those file
descriptors, implementing both source and destination address translation as
required by the hICN mechanisms;
- finally, a "transport" API allows the forging of dummy interest and data
packets.

A commandline interface (hicnc) is also provided that uses the library and can
for instance be used as a test traffic generator. This interface can be run as
either a consumer, a producer, or a simple forwarder.

## Directory layout

```bash
.
+-- CMakeLists.txt          CMkake global build file
+-- doc                     Package documentation
+-- README.md               This file
+-- src
|   +-- base.h              Base definitions for hICN implementation
|   +-- CMakeLists.txt      CMake library build file
|   +-- common.{h,c}        Harmonization layer across supported platforms
|   +-- compat.{h,c}        Compatibility layer for former API
|   +-- error.{h,c}         Error management files
|   +-- header.h            hICN header definitions
|   +-- hicn.h              Master include file
|   +-- mapme.{h,c}         MAP-Me : anchorless producer mobility mechanisms
|   +-- name.{h,c}          hICN naming conventions and name processing + IP helpers
|   +-- ops.{h,c}           Protocol-independent hICN operations
|   +-- protocol/*          Protocol headers + protocol-dependent implementations
|   +-- protocol.h          Common file for protocols
```

## Using libhicn

### Dependencies

Build dependencies:

- C11 ( clang / gcc )
- CMake 3.4

Basic dependencies: None

## Installation

### Release mode

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

### Debug mode

```bash
mkdir debug
cd debug
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
sudo make install
```
