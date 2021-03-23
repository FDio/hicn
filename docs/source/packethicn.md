HICN Plugin for Wireshark
===================

The `packethicn` plugin adds support to Wireshark to parse and dissect HICN traffic.

`packethicn` can be compiled and installed in two ways:

1. Alongside HICN, from the HICN root dir (see [Build with HICN](#Build-with-HICN))

2. As a standalone component (see [Standalone build](#Standalone-build))

The second one is preferred if `HICN` is already installed in the system.

# Build with HICN

## Dependencies

```bash
$ sudo add-apt-repository ppa:wireshark-dev/stable

$ sudo apt install -y build-essential cmake wireshark wireshark-dev libgcrypt-dev libgnutls28-dev

```

## Build and install

From the root HICN dir add the `-DBUILD_WSPLUGIN` flag to cmake.

```bash
$ cd hicn

$ mkdir build; cd build

$ cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl\@1.1 -DBUILD_APPS=ON -DBUILD_WSPLUGIN=ON ..

$ make -j`nproc`

$ sudo make install

```

# Standalone build
## Linux (Ubuntu)

### Install dependencies
```bash
$ sudo add-apt-repository ppa:wireshark-dev/stable

$ curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash

$ sudo apt install -y build-essential cmake libhicn-dev wireshark wireshark-dev libgcrypt-dev libgnutls28-dev

```
### Compile and install HICN plugin
```bash
$ cd packethicn

$ mkdir build; cd build

$ cmake ..

$ make

$ sudo make install
```


## macOS
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