HICN Plugin for Wireshark
===================

The `packethicn` plugin adds support to Wireshark to parse and dissect HICN traffic.

`packethicn` can be compiled and installed in two ways:

1. Alongside HICN, from the HICN root dir (see [Build with HICN](#Build-with-HICN))

2. As a standalone component (see [Standalone build](#Standalone-build))

The second one is preferred if HICN is already installed in the system.

# Supported platforms
`packethicn` has been tested in

- Ubuntu 18.04
- Ubuntu 20.04
- macOS 11.2

Other platforms and architectures may work.

# Installation 
## Build with HICN

### Dependencies

```bash
$ sudo add-apt-repository ppa:wireshark-dev/stable

$ sudo apt install -y build-essential cmake wireshark wireshark-dev libgcrypt-dev libgnutls28-dev

```

### Build and install

From the root HICN dir add the `-DBUILD_WSPLUGIN` flag to cmake.

```bash
$ cd hicn

$ mkdir build; cd build

$ cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl\@1.1 -DBUILD_APPS=ON -DBUILD_WSPLUGIN=ON ..

$ make -j`nproc`

$ sudo make install

```

## Standalone build
### Linux (Ubuntu)

#### Install dependencies
```bash
$ sudo add-apt-repository ppa:wireshark-dev/stable

$ curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash

$ sudo apt install -y build-essential cmake libhicn-dev wireshark wireshark-dev libgcrypt-dev libgnutls28-dev

```
#### Compile and install HICN plugin
```bash
$ cd packethicn

$ mkdir build; cd build

$ cmake ..

$ make

$ sudo make install
```


### macOS
If installing wireshark via brew use the `./install_macos.sh` script as shown below:

```bash
$ brew tap icn-team/hicn-tap

$ brew install hicn

$ brew install wireshark

$ brew install cask wireshark

$ cd packethicn

$ ./install_macos.sh
```

Otherwise (if wireshark was compiled from sources) you can follow the setup for Linux:

```bash
$ cd packethicn

$ mkdir build; cd build

$ cmake ..

$ make

$ sudo make install
```

# Usage

## Filters

| Filter | Description | Example |
| --- | --- | --- |
| `hicn`  | HICN traffic only  | *hicn* |
| `hicn.l3.src`  | Source address / Name Prefix (of data)  | *hicn.l3.src == b001::a8f:ae2a:bd5b:0:0* |
| `hicn.l3.dst`  | Destination address / Name Prefix (of interest)  | *hicn.l3.dst == b001::a8f:ae2a:bd5b:1111:0* |
| `hicn.l4.namesuffix `  | Name Suffix  | *hicn.l4.namesuffix == 0x21* |
| `hicn.l4.pathlabel `  | Path Label  | *hicn.l4.pathlabel == 0xbb* |
| `hicn.l4.timescale `  | Timescale  | *hicn.l4.timescale == 4* |
| `hicn.l4.flags `  | Flags  | *hicn.l4.flags == 0x42* |
| `hicn.l4.flags.id `  |  ID Flag | *hicn.l4.flags.<span></span>id == 1* |
| `hicn.l4.flags.man `  |  MAN Flag | *hicn.l4.flags.man == 0* |
| `hicn.l4.flags.sig `  | SIG Flag | *hicn.l4.flags.sig == 0* |
| `hicn.l4.ldr `  | Loss Detection and Recovery | *hicn.l4.ldr > 0* |
| `hicn.l4.csum `  | Checksum | *hicn.l4.csum > 0* |
| `hicn.l4.lifetime `  | Lifetime | *hicn.l4.lifetime == 1000* |
