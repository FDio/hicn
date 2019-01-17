Libtransport: data transport library for hICN
====================================================

## Introduction ##

This library provides transport services and socket API for applications willing to communicate
using the hICN protocol stack.

Overview:

- Implementation of the hICN core objects (interest, data, name..) exploiting the API provided by [libhicn](../lib).
- Connectors for connecting the application to either the hicn-plugin or the hicn-light forwarder.
- Transport protocols (RAAQM, CBR, RTP)
- Transport services (authentication, integrity, segmentation, reassembly, naming)
- Interfaces for Applications (from low-level interfaces for interest-data interaction to high level interfaces for Application Data Unit interaction)

## Build Dependencies ##

- libparc
- libmemif (linux only, if compiling with VPP support)
- libasio

### Ubuntu 16.04 and Ubuntu 18.04 ###

```bash
 $ echo "deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.master.ubuntu.$(lsb_release -sc).main/ ./" \
          | sudo tee -a /etc/apt/sources.list.d/99fd.io.list
 $ sudo apt-get install libparc libasio-dev
```

If you wish to use the library for connecting to the vpp hicn-plugin, you will need to also install vpp, the vpp libraries and the libmemif libraries:

- DEB packages:
  - vpp
  - vpp-lib
  - vpp-dev

You can get them either from from the vpp packages ot the source code. Check the [VPP wiki](https://wiki.fd.io/view/VPP) for instructions.

Libmemif is in the vpp-lib and vpp-dev packages.

### Mac OSX ###

We recommend to use [HomeBrew](https://brew.sh/) for installing the libasio dependency:

```bash
 $ brew install asio
```

Download, compile and install libparc:

```bash
 $ git clone -b cframework/master https://gerrit.fd.io/r/cicn cframework && cd cframework
 $ mkdir -p libparc.build && cd libparc.build
 $ cmake ../libparc
 $ make
 $ make install
```

Libparc will be installed by default under `/usr/local/lib` and `/usr/local/include`.

Since VPP does not support MAC OS, the hicn-plugin connector is not built.

## Build The library ##

From the project root folder:

```bash
 $ cd libtransport
 $ mkdir build && cd build
 $ cmake ..
 $ make
```
### Compile options ###

The build process can be customized with the following options:

- `CMAKE_INSTALL_PREFIX`: The path where you want to install the library.
- `CMAKE_BUILD_TYPE`: The build configuration. Options: `Release`, `Debug`. Default is `Release`.
- `ASIO_HOME`: The folder containing the libasio headers.
- `LIBPARC_HOME`: The folder containing the libparc headers and libraries.
- `VPP_HOME`: The folder containing the installation of VPP.
- `LIBMEMIF_HOME`: The folder containing the libmemif headers and libraries.
- `BUILD_MEMIF_CONNECTOR`: On linux, set this value to `ON` for building the VPP connector.

An option can be set using cmake -D`OPTION`=`VALUE`.

Install the library
-------------------

For installing the library, from the cmake build folder:

```bash
 $ sudo make install
```

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

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```