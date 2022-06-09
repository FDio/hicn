## Introduction

The transport library provides transport services and socket API for
applications willing to communicate using the hICN protocol stack.

Overview:
- Implementation of the hICN core objects (interest, data, name..) exploiting
  the API provided by [libhicn](./lib.md).
- IO modules for seamlessly connecting the application to the hicn-plugin for [VPP](https://github.com/FDio/vpp) or the
  [hicn-light](./hicn-light.md) forwarder.
- Transport protocols (RAAQM, CBR, RTC)
- Transport services (authentication, integrity, segmentation, reassembly,
  naming)
- Interfaces for applications (from low-level interfaces for interest-data
  interaction to high level interfaces for Application Data Unit interaction)


## Build dependencies

### Ubuntu

```bash
sudo apt install libasio-dev libconfig++-dev libssl-dev
```

If you wish to use the library for connecting to the vpp hicn-plugin, you will
need to also install vpp and its libraries.

```bash
# Prevent vpp to set sysctl
export VPP_INSTALL_SKIP_SYSCTL=1
VPP_VERSION=$(cat "${VERSION_PATH}" | grep VPP_DEFAULT_VERSION | cut -d ' ' -f 2 | tr -d '"' | grep -Po '\d\d.\d\d')

curl -s https://packagecloud.io/install/repositories/fdio/${VPP_VERSION//./}/script.deb.sh | bash
curl -L https://packagecloud.io/fdio/${VPP_VERSION//./}/gpgkey | apt-key add -
sed -E -i 's/(deb.*)(\[.*\])(.*)/\1\3/g' /etc/apt/sources.list.d/fdio_${VPP_VERSION//./}.list
apt-get update

apt-get install -y \
  vpp-dev \
  libvppinfra-dev \
  vpp-plugin-core \
  vpp \
  libvppinfra
```

You can get them either from from the vpp packages or the source code. Check the
[VPP wiki](https://wiki.fd.io/view/VPP) for instructions.

### macOS

We recommend to use [HomeBrew](https://brew.sh/) for installing the libasio
dependency:

```bash
brew install asio libconfig openssl@1.1
```

Since VPP does not support macOS, the IO module memif is not built.


## Build the library

The library is built by default from the main CMakeLists.txt.
If you have all the dependencies installed, including [libhicn](./lib.md),
you can also build libtransport alone:

```bash
cd libtransport
mkdir build && cd build
cmake ..
cmake --build .
```

### Compile options

The build process can be customized with the following options:

- `CMAKE_INSTALL_PREFIX`: The path where you want to install the library.
- `CMAKE_BUILD_TYPE`: The build configuration. Options: `Release`, `Debug`.
  Default is `Release`.
- `ASIO_HOME`: The folder containing the libasio headers.
- `VPP_HOME`: The folder containing the installation of VPP.

An option can be set using cmake -D`OPTION`=`VALUE`.

### Install the library

For installing the library, from the cmake build folder:

```bash
cmake --build . -- install
```


## Usage

Examples on how to use the library can be found in the apps folder of the project.
In particular you can check the **hiperf** application, which demonstrates
how to use the API to interact with the hicn transport, both for consumer and producer.

### Configuration file

The transport can be configured using a configuration file. There are two ways
to tell libransport where to find the configuration file:

- programmatically - you set the configuration file path in your application:
```cpp
// Set conf file path
std::string conf_file = "/opt/hicn/etc/transport.config"
// Parse config file
transport::interface::global_config::parseConfigurationFile(conf_file);
```

- using the environment variable `TRANSPORT_CONFIG`:
```bash
export TRANSPORT_CONFIG=/opt/hicn/etc/transport.config
./hiperf -C b001::1
```

Here is an example of configuration file:

```
// Configuration for io_module
io_module = {
  path = [];
  name = "forwarder_module";
};

// Configuration for forwarder io_module
forwarder = {
  n_threads = 1;

  connectors = {
    c0 = {
      /* local_address and local_port are optional */
      local_address = "127.0.0.1";
      local_port = 33436;
      remote_address = "127.0.0.1";
      remote_port = 33436;
    }
  };

  listeners = {
    l0 = {
      local_address = "127.0.0.1";
      local_port = 33437;
    }
  };
};

// Logging
log = {
  // Log level (INFO (0), WARNING (1), ERROR (2), FATAL (3))
  minloglevel = 0;

  // Verbosity level for debug logs
  v= 2;

  // Log to stderr
  logtostderr = true;

  // Get fancy colored logs
  colorlogtostderr = true;

  // Log messages above this level also to stderr
  stderrthreshold = 2;

  // Set log prefix for each line log
  log_prefix = true;

  // Log dir
  log_dir = "/tmp";

  // Log only specific modules.
  // Example: "membuf=2,rtc=3"
  vmodule = "";

  // Max log size in MB
  max_log_size = 10;

  // Log rotation
  stop_logging_if_full_disk = true;
};
```


## Security

hICN has built-in authentication and integrity features by either:
* Cryptographically signing all packets using an asymmetric key (like RSA) or a
  symmetric one (like HMAC). The latter requires that all parties have prior
  access to the same key. Beware that this method is computationally expensive
  and impacts max throughput and CPU usage.
* Using manifests. Manifests are special packets that holds the digests of a
  group of data packets. Only the manifest needs to be signed and authenticated;
  other packets are authenticated simply by verifying that their digest is
  present in a manifest.

### Per-packet signatures

To enable per-packet signature with asymmetric signing:
* On the producer, disable manifests (which are ON by default):
  ```cpp
  producer_socket->setSocketOption(GeneralTransportOptions::MANIFEST_MAX_CAPACITY, 0u);
  ```
* On the producer, instantiate an `AsymmetricSigner` object by passing either an
  asymmetric pair of keys as
  [EVP_KEY](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html) object
  or a keystore path and password as strings:
  ```cpp
  std::shared_ptr<Signer> signer = std::make_shared<AsymmetricSigner>("./rsa.p12", "hunter2");
  ```
* Pass the signer object to libtransport:
  ```cpp
  producer_socket->setSocketOption(GeneralTransportOptions::SIGNER, signer);
  ```
* On the consumer, instantiate an `AsymmetricVerifer` object by passing either a
  certificate as a [X509](https://www.openssl.org/docs/man1.0.2/man3/x509.html)
  object, an asymmetric public key as a
  [EVP_KEY](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html) object
  or a certificate path as a string:
  ```cpp
  std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>("./rsa.crt");
  ```
* Pass the verifier object to libtransport:
  ```cpp
  consumer_socket->setSocketOption(GeneralTransportOptions::VERIFIER, verifier);
  ```

To enable per-packet signature with symmetric signing, follow the above steps
replacing `AsymmetricSigner` with `SymmetricSigner` and `AsymmetricVerifer` with
`SymmetricSigner`. A `SymmetricSigner` only has one constructor which expects a
`CryptoSuite` and a passphrase. A `SymmetricVerifier` also has a single
constructor which expects a passphrase:
```cpp
std::shared_ptr<Signer> signer = std::make_shared<SymmetricSigner>(CryptoSuite::HMAC_SHA256, "hunter2");
std::shared_ptr<Verifier> verifier = std::make_shared<SymmetricVerifier>("hunter2");
```

Check [Supported crypto suites](#supported-crypto-suites) for the list of
available suites.

### Enabling manifests

* Follow steps 2-5 in [Per-packet signatures](#per-packet-signatures).
* By default, a manifest has a maximum capacity `C_max` of 30 packets. To change
  this value:
  ```cpp
  producer_socket->setSocketOption(GeneralTransportOptions::MANIFEST_MAX_CAPACITY, 20u);
  ```

In the case of RTC, manifests are sent after the data they contain and on the
consumer side, data packets are immediately forwarded to the application, *even
if they weren't authenticated yet via a manifest*. This is to minimize latency.
The digest of incoming data packets are kept in a buffer while waiting for
manifests to arrive. When the buffer size goes above a threshold `T`, an alert
is raised by the verifier object. That alert threshold is computed as follows:
```
T = manifest_factor_alert * C_max
```

The value of `C_max` is passed by the producer to the consumer at the start of
the connection. `manifest_factor_alert` is a consumer socket option. It
basically acts on the resilience of manifests against networks losses and
reflects the application's tolerance to unverified packets: a higher value gives
the transport the time needed to recover from several manifest losses but
potentially allows a larger number of unverified packet to go the application
before alerts are triggered. It is set to `20` by default and should always be
`>= 1`. To change it:
```cpp
consumer_socket_->setSocketOption(GeneralTransportOptions::MANIFEST_FACTOR_ALERT, 10u);
```

The buffer does not keep unverified packets indefinitely. After a certain amount
of packets have been received and processed (and were verified or not), older
packets still unverified are flushed out. This is to prevent the buffer to grow
uncontrollably and to raise alerts for packets that are not relevant to the
application anymore. That threshold of relevance is computed as follows:
```
T = manifest_factor_relevant * C_max
```

`manifest_factor_relevant` is a consumer socket option. It is set to `100` by
default. Its value must be set so that `manifest_factor_relevant >
manifest_factor_alert >= 1`. If `manifest_factor_relevant <=
manifest_factor_alert`, no alert will ever be raised. To change it:
```cpp
consumer_socket_->setSocketOption(GeneralTransportOptions::MANIFEST_FACTOR_RELEVANT, 200u);
```

### Handling authentication failures

When a data packet fails authentication, or when the unverified buffer is full
in the case of RTC, an alert is triggered by the verifier object. By default
libtransport aborts the connection upon reception of that alert. You may want to
intercept authentication failures in your application:
* Define a callback with arguments an `uint32_t` integer, which will be set to
  the suffix of the faulty packet, and a `auth::VerificationPolicy`, which will
  be set to the action suggested by the verifier object. The callback must
  return another `auth::VerificationPolicy` which will be the actual action
  taken by libtransport:
  ```cpp
  auth::VerificationPolicy onAuthFailed(uint32_t suffix, auth::VerificationPolicy policy) {
    std::cout << "auth failed for packet " << suffix << std::endl;
    return auth::VerificationPolicy::ACCEPT;
  }
  ```
* Give that callback to your `Verifier` object as well as a list of
   `auth::VerificationPolicy` to intercept (if left empty, will be set by
   default to `{ABORT, DROP}`):
  ```cpp
  verifier->setVerificationFailedCallback(&onAuthFailed, {
    auth::VerificationPolicy::ABORT,
    auth::VerificationPolicy::DROP,
    auth::VerificationPolicy::UNKNOWN,
  });
  ```

### Supported crypto suites

The following `CryptoSuite` are supported by libtransport:
```
ECDSA_BLAKE2B512
ECDSA_BLAKE2S256
ECDSA_SHA256
ECDSA_SHA512
RSA_BLAKE2B512
RSA_BLAKE2S256
RSA_SHA256
RSA_SHA512
HMAC_BLAKE2B512
HMAC_BLAKE2S256
HMAC_SHA256
HMAC_SHA512
DSA_BLAKE2B512
DSA_BLAKE2S256
DSA_SHA256
DSA_SHA512
```


## Logging

Internally libtransport uses glog as logging library. If you want to have a more
verbose transport log when launching a test or an app, you can set environment
variables in this way:

```
GLOG_v=4 hiperf -S b001::/64
```

For a more exhaustive list of options, please check the instructions in the glog
[README](https://github.com/google/glog#setting-flags).

Useful options include enabling logging *per module*. Also you can compile out
useless messages in release builds.
