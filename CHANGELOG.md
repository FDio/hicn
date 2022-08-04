## v3.14.0 (2022-07-18)

### Feat

- release 3.14 of hicn
- move interest manifest inside libhicn to be reused by hicn-plugin
- include wrapper asio files
- include wrapper asio files
- rewrite new PCS, backed by clib_bihash

### Fix

- **lib**: install interest manifest header
- **hicn-light**: code style
- **hicn-light**: fix connection table issue
- **hicn-light**: fix connection table issue
- **hicn-light**: fix crash on connection close
- **hicn-light**: fix interest send on mac os
- **transport**: fix udp connector for mac os
- do not reuse vpp struct/macros in libhicn
- **ci/docker-build-ios.sh**: accept ios dockerfile eula
- **core**: add ifndef to compile on macos
- **pcs.h**: align PCS entry to 64 bytes in place of CLIB_CACHELINE

## v3.13.0 (2022-06-17)

## v3.13.0b0 (2022-06-16)

### Feat

- release 3.13 of hicn
- **transport**: codel style
- **transport**: imporve switch between RTX and FEC with variable RTT
- **transport**: improve fec for low rtt
- **aggregated-interests**: fix multipath with aggregated interests
- packet generator to assess performance
- **hicn-light-collectd**: add per-face stats in collectd plugin
- **hicn-light-collectd**: add per-face stats in forwarder
- **hicn-light-collectd**: update cmake for vpp collectd plugins
- **hicn-light-collectd**: modify kafka output collectd plugin to use influxdb format and do dispatching
- **hicn-light-collectd**: use input collectd plugin to retrieve stats from forwarder
- **hicn-light-collectd**: expose libhicnctrl api to retrieve hicn-light stats
- **hicn-light-collectd**: setup cmake for hicn-light and kafka plugins
- **transport**: set the expirtation time of the data packets using socket options
- **libtransport**: use microseconds to improve RTT precision
- **aggregated-interests**: enable aggregated interests at runtime
- **aggregated-interests**: add aggregated interest support in transport
- **hicn-plugin**: parse hicn packet only one time, as soon as it is received
- **transport**: modify delay in delay strategy
- **manifest**: improve encoding and decoding
- **aggregated-interests**: add signature to interest manifest
- **aggregated-interests**: add disaggregation and bitmap in interest manifest
- **libhicn**: move common data structures in lib
- **vector**: add missing api functions to vector data structure
- **libhicn**: use same map data structure between hicn-light and hicn-ctrl
- **libtransport**: remove all references to ntoh and hton
- **packet-cache**: add CS clear in hicn-light
- **portal.h**: modify PIT to register penging interests in both sides
- **libtransport**: add global module manager and library constructor
- multistream hiperf
- **libtransport**: add cache prefetch support and test to assess performance
- Add API to get/set ports in libhicn
- add enumeration for packet type in libhicn
- **pool**: remove unnecessary memset in pool and add script to test hiperf locally
- **packet-cache**: avoid double lookups when possible
- **packet-cache**: add two-level packet cache
- **hicn-ping**: add interest manifest support in hicn-ping
- sync build scripts with master-fdio
- **auth**: use membuf

### Fix

- **hiperf**: fix buffer contention when using multiple producers
- **manifest**: remove unnecessary debug assert
- better organize flags in hicn-plugin
- replace deprecated std::random_shuffle function
- **transport**: use constant var in recovery strategy baeds on delay
- **hiperf**: fix bandwidth computaton in hiperf
- **manifest**: compilation error
- **libhicnctrl**: fix name generation for new faces
- **libhicnctrl**: fix name generation for new faces
- fix memory corruption in msgbuf ids vector
- **hicn-light**: fix hardcoded limit on number of pending connections
- **hicn-light**: return error when not able to generate new connection name
- **transport**: fix forwarder io module in transport
- **auth**: invalid memory read in signer
- **libtransport**: pass all required callbacks when creating connectors
- fix htonll and ntohll in libhicn
- **packet-cache**: add missing data prefix caching on content packet received
- **production_protocol.h**: do not accept unvalid values of TRANSPORT_FEC_TYPE if environment variable is set
- use proper function to compare elements in listener and conenction table
- **docker**: do no use internal image in public dockerfile and remove old functional tests
- **fec**: correctly compute the transport header size of each packet
- **transport**: add rs fec header size also in the decoder
- **transport**: fix max packet size in producer socket
- **prod_protocol_rtc.cc**: check if fec_type is valid before using it
- **hicnctrl**: fix route command validation

### Perf

- **transport**: reduce cpu usage at RTC consumer socket for loss detection

### Refactor

- **tls**: remove support for TLS
- **manifest**: move decoding of manifest out of decoder constructor
- move interest manifest header to libhicn and update log
- refactor listener and connection table
- **manifest**: improve manifest verification and performance

## v3.12.2 (2022-06-01)

### Fix

- **lib/includes/hicn/util/bitmap.h**: correct include header

## v3.12.1 (2022-06-01)

### Fix

- **cmake**: wrong version number in hicn

## v3.12.0 (2022-05-31)

### Feat

- release 3.12 of hicn
- **aggregated-interests**: add signature to interest manifest
- **aggregated-interests**: add disaggregation and bitmap in interest manifest
- **libhicn**: move common data structures in lib
- **vector**: add missing api functions to vector data structure
- **libhicn**: use same map data structure between hicn-light and hicn-ctrl
- **libtransport**: remove all references to ntoh and hton
- **packet-cache**: add CS clear in hicn-light
- **portal.h**: modify PIT to register penging interests in both sides
- **libtransport**: add global module manager and library constructor
- multistream hiperf
- **libtransport**: add cache prefetch support and test to assess performance
- Add API to get/set ports in libhicn
- add enumeration for packet type in libhicn
- **pool**: remove unnecessary memset in pool and add script to test hiperf locally
- **packet-cache**: avoid double lookups when possible
- **packet-cache**: add two-level packet cache
- **hicn-ping**: add interest manifest support in hicn-ping
- sync build scripts with master-fdio
- **auth**: use membuf

### Fix

- **libhicnctrl**: fix name generation for new faces
- **libhicnctrl**: fix name generation for new faces
- fix memory corruption in msgbuf ids vector
- **hicn-light**: fix hardcoded limit on number of pending connections
- **hicn-light**: return error when not able to generate new connection name
- **transport**: fix forwarder io module in transport
- **auth**: invalid memory read in signer
- **libtransport**: pass all required callbacks when creating connectors
- fix htonll and ntohll in libhicn
- **packet-cache**: add missing data prefix caching on content packet received
- **production_protocol.h**: do not accept unvalid values of TRANSPORT_FEC_TYPE if environment variable is set
- use proper function to compare elements in listener and conenction table
- **docker**: do no use internal image in public dockerfile and remove old functional tests
- **fec**: correctly compute the transport header size of each packet
- **transport**: add rs fec header size also in the decoder
- **transport**: fix max packet size in producer socket
- **prod_protocol_rtc.cc**: check if fec_type is valid before using it
- **hicnctrl**: fix route command validation

### Refactor

- **manifest**: move decoding of manifest out of decoder constructor
- move interest manifest header to libhicn and update log
- refactor listener and connection table
- **manifest**: improve manifest verification and performance

## v3.11.3 (2022-04-18)

### Feat

- **manifest**: optimize manifest processing

## v3.11.2 (2022-04-13)

### Fix

- **manifest**: do not iterate on full data buffer to compute ratio

## v3.11.1 (2022-04-13)

### Fix

- **manifest**: ignore manifest entries of discarded unverified packets

## v3.11.0 (2022-04-11)

## v3.11.0b0 (2022-04-08)

### Feat

- release 3.11 of hicn
- **manifest**: add FEC parameters to manifests
- **manifest**: refactor verification process
- **manifest**: report auth alerts in hiperf instead of aborting
- **manifest**: remove FEC buffer callback in consumer
- **manifest**: refactor and enable manifests by default
- **manifest**: update manifest header with transport parameters
- **manifest**: batch interests for first manifest from RTC producer
- **manifest**: refactor processing of RTC manifests
- **manifest**: update manifest-related socket options of consumers
- **manifest**: update unit tests for manifests
- **manifest**: pack manifest headers
- **manifest**: verify FEC packets
- **auth**: add consumer socket option to set max unverified delay
- **manifest**: process manifests after full FEC decoding
- **manifest**: manage forward jumps in RTC verifier
- **fec**: remove useless fec codes
- **rs**: add new code rate
- **rs**: add new code rate
- **rs**: add new code rate
- **rs**: add new code rate
- **libtransport**: increase internal packet cache size
- remove internal cisco info in cmake
- **manifest**: add option to set manifest capacity
- **data_input_node.c**: add information about adj_index[VLIB_RX] on received data packets
- **hicn-plugin**: upgrade to VPP 22.02

### Refactor

- **manifest**: change default manifest options to support low-rate
- remove remaining traces of fec type option
- **hiperf**: cosmetic update
- **manifest**: apply code reviews
- **auth**: change auth failed callback signature

### Fix

- **strategy-callbacks**: fix callback calls when transport is out of scope
- **bitmap**: fix bitmap set operation
- **transport**: avoid to add fec at start up if no loss is detected
- **notifications**: add callbacks for forwarding/recovery strategy changes
- **face_node.c**: ensure IPv6 loopback is not interpreted as IPv4 address
- **manifest**: fix segfault with RS + manifests
- **manifest**: support RS
- **auth**: verify previously unverified packet signatures
- **bytestream**: make manifest branch work with RAAQM
- **pathlabel**: fix data path label in the hicn-light forwarder
- **deps**: fix cisco openssl and safec dependencies inclusion
- **udp_connector.cc**: call receive callback with correct parameters
- cannot retrieve integer producer socket option
- **fec.cc**: correct fec after wrong merge
- **liiib/CMakeLists.txt**: correct typo

## v3.10.0 (2022-04-02)

### Feat

- release 3.10 of hicn
- **manifest**: refactor verification process
- **manifest**: report auth alerts in hiperf instead of aborting
- **manifest**: remove FEC buffer callback in consumer
- **manifest**: refactor and enable manifests by default
- **manifest**: update manifest header with transport parameters
- **manifest**: batch interests for first manifest from RTC producer
- **manifest**: refactor processing of RTC manifests
- **manifest**: update manifest-related socket options of consumers
- **manifest**: update unit tests for manifests
- **manifest**: pack manifest headers
- **manifest**: verify FEC packets
- **auth**: add consumer socket option to set max unverified delay
- **manifest**: process manifests after full FEC decoding
- **manifest**: manage forward jumps in RTC verifier
- **fec**: remove useless fec codes
- **rs**: add new code rate
- **rs**: add new code rate
- **rs**: add new code rate
- **rs**: add new code rate
- **libtransport**: increase internal packet cache size
- remove internal cisco info in cmake
- **manifest**: add option to set manifest capacity
- **hicn-plugin**: upgrade to VPP 22.02

### Fix

- **transport**: avoid to add fec at start up if no loss is detected
- **notifications**: add callbacks for forwarding/recovery strategy changes
- **face_node.c**: ensure IPv6 loopback is not interpreted as IPv4 address
- **manifest**: fix segfault with RS + manifests
- **manifest**: support RS
- **auth**: verify previously unverified packet signatures
- **bytestream**: make manifest branch work with RAAQM
- **pathlabel**: fix data path label in the hicn-light forwarder
- **deps**: fix cisco openssl and safec dependencies inclusion
- **udp_connector.cc**: call receive callback with correct parameters
- cannot retrieve integer producer socket option

### Refactor

- **hiperf**: cosmetic update
- **manifest**: apply code reviews
- **auth**: change auth failed callback signature

## v3.9.1 (2022-03-21)

### Fix

- **route**: fix route creation failure when id instead of symbolic

## v3.9.0 (2022-03-21)

### Feat

- release 3.9
- **data_input_node.c**: add information about adj_index[VLIB_RX] on received data packets
- **hicn-plugin**: upgrade to VPP 22.02

### Fix

- **liiib/CMakeLists.txt**: correct typo

## v3.8.1 (2022-03-15)

### Fix

- **android-sdk**: upgrade android-sdk version

## v3.8.0 (2022-03-14)

## v3.8.0b0 (2022-03-12)

### Feat

- release 3.8 of hicn
- **ci**: install correct VPP version in local ci scripts
- **Makefile**: add conveniente targets to build/use docker container
- **security**: define custom secure functions if not available
- **security**: improve input validation
- insert CPU info as compilation options

### Refactor

- **fec**: do not include FEC header when copying FEC payload
- **auth**: clean up
- **CMakeLists.txt**: global cleanup of CMakeLists files

### Fix

- **probe-generator**: return probe register time (fix probe generator test)
- fix pool index validation and removal of current listener/connection
- **strcpy_s**: fix warnings appearing after strcpy_s introduction
- **security**: use secure version of strlen
- **security**: use secure version of strcpy
- **test-rs**: typo
- **rs-test**: fix packet index size
- **cmake**: add ciscossl path
- **fec-rate**: set max loss rate to 0.95
- **loss-rate**: init loss rate using the rtt probes

## v3.7.2 (2022-02-25)

### Feat

- update android-sdk version to 2.0.6

## v3.7.1 (2022-02-17)

### Feat

- use android-sdk image with librdkafka 1.8.2

## v3.7.0 (2022-02-17)

### Fix

- **CS**: correctly forward packets coming from the CS

## v3.7.0b0 (2022-02-14)

### Feat

- release 3.7 of hicn
- **hicn-light-control**: distinguish between command and serialization errors
- **pit**: code style
- **pit**: code style
- **pit**: do not send aggregated interests
- **pit**: do not store state in the pit for interests with no nexthop
- add arm and x86 support to hicn
- **hicn-light-control**: add input validation in hicn-light-control parser
- **hicn-ctrl**: add command for notification subscription in hicn-light-control
- add vpp logs
- **hicn-plugin**: return the list of created faces after running hicn_route_enable.
- add constants for invalid face and invalid netdevice
- **packet-cache**: use Name instead of name_key_t as hashtable key
- **forwarder**: code style
- **hicn-light**: fix mapme packet processing
- **hicn-light**: remove commented code and missing initiliazations
- **forwarder**: fix tests
- **hicn-plugin**: add log
- create prod image of hicn
- **hicn-plugin**: allow UDP tunnels to be dynamically created upon interest reception.
- **hicn-plugin**: add support for UDP tunnels in mapme
- **strategy**: fix crash and nexthops compare
- **strategy**: fix add local prefixes
- **strategy**: add local prefixes and mapme updates to replication
- **strategy**: code style
- **strategy**: improve path switch
- **transport**: improve path switch
- **strategy**: set bestpath before send mapme message
- **strategy**: send mapme update at the end of each probing phase
- **hicn-light**: add support for strategy_add_local_prefix command from config file
- **facemgr**: use separate sockets for control and polling hicn-light
- **hicn-light**: close listener and connection file descriptors on forwarder stop
- **hicnctrl**: add timeout for recv operations
- **hicn-light**: remove hicnctrl connection from 'list connection' command output
- **listeners**: set local listeners without using resolver
- **doc**: update readme file
- **doc**: update readme file and authors' list

### Fix

- **parser**: add cast to compile in android
- **hicn-light-control**: fix missing error code in case of nack
- **hicn-light-control**: remove sopport for old forwarder
- **facemgr/libhicn**: Assigned value is garbage or undefined
- **facemgr**: Remove the commented out code
- **facemgr**: code/return will never be executed
- check that face_output sends interest to a complete face
- try not to keep a lock to dpo_ctx in each PIT entry.
- log route creation/deletion failures in linhicnctrl
- **memif_vapi.c**: initialize memif id before retrieving the next id to use.
- **libvapi_safe**: implement vapi_disconnect API
- **libhinctrl**: fix ring buffer management + refactor code
- **facemgr/netlink**: leaked facelets for interfaces not up and running
- **facemgr/hicn-light**: timerfd leak
- **hicnctrl**: fix notification processing
- **core::Portal**: ensure interest timeout handler refers to a valid Portal.
- **rtc-transport**: ensure RTC is running and valid before executing timer handlers
- **libhinctrl**: fix ring buffer management + refactor code
- **listener-table**: forbid creation of listener for already-existing address
- **connection-table**: fix multiple connections with same name
- **hicn-light**: fixed uninitialized memory in parser code
- **Jenkinsfile**: prod image is not created
- initialize listener memory
- **libhicnctrl**: remove useless size_in field in hicn_sock_request_t
- propagate listener hashtable fix in connection table and packet cache
- **listener-table**: fix listener removal from hashtable
- **dockerfile**: tests failed due the wrong docker image
- **rtc_state.h**: initialize rtc_state out of constructor
- **rtc_state.h**: check if RTCState is valid before dereferencing it.
- **hicn-light**: missing command_id in LIST command replies + cleanup
- producer face deletion does not delete the route from fib 0
- **hicn-plugin**: insert drop node in the next nodes of face-node
- delete faces when lock count reaches 0
- **libhicnctrl**: fix hardcoded AF_INET in hc_face_to_connection
- **facemgr/android**: handle missing android information on down interfaces
- **hicn-light**: fix memory leaks when forwarder is closed
- **hicn-light**: fix forwarder receive
- fix MacOS build errors

### Perf

- **hicn-light**: remove memory allocation inside name

### Refactor

- **packet-cache**: remove macro used in packet cache entry allocation
- **facemgr/hicn-light**: refactor poll timer code

## v3.6.8 (2022-02-10)

### Fix

- **mapme**: Ignore updates from current nexthop with lower sequence number

## v3.6.7 (2022-02-09)

### Fix

- **hicn-plugin**: get input face using source address lookup in place of using a list of possible incoming faces

## v3.6.6 (2022-02-08)

### Fix

- **hicn-plugin**: remove unused in_face_id from PCS
- **hicn-plugin**: remove vector of in_face_id

## v3.6.5 (2022-02-07)

### Fix

- **memif-connector**: signal send error up to application

## v3.6.4 (2022-02-05)

### Fix

- add NH before deleting tfib entr

## v3.6.3 (2022-02-05)

### Fix

- disable prints when hicn is compiled in release mode

## v3.6.2 (2022-02-04)

### Fix

- **facemgr**: prevent incorrect free of facelet added to cache

## v3.6.1 (2022-02-02)

### Fix

- use correct fib source when updating next hops with mapme

## v3.6.0 (2022-02-01)

### Fix

- update cmake version
- check that face_output sends interest to a complete face
- try not to keep a lock to dpo_ctx in each PIT entry.
- log route creation/deletion failures in linhicnctrl
- **memif_vapi.c**: initialize memif id before retrieving the next id to use.
- **libvapi_safe**: implement vapi_disconnect API
- **libhinctrl**: fix ring buffer management + refactor code
- **facemgr/netlink**: leaked facelets for interfaces not up and running
- **facemgr/hicn-light**: timerfd leak
- **hicnctrl**: fix notification processing
- **core::Portal**: ensure interest timeout handler refers to a valid Portal.
- **rtc-transport**: ensure RTC is running and valid before executing timer handlers
- **libhinctrl**: fix ring buffer management + refactor code
- **listener-table**: forbid creation of listener for already-existing address
- **connection-table**: fix multiple connections with same name
- **hicn-light**: fixed uninitialized memory in parser code
- **Jenkinsfile**: prod image is not created
- initialize listener memory
- **libhicnctrl**: remove useless size_in field in hicn_sock_request_t
- propagate listener hashtable fix in connection table and packet cache
- **listener-table**: fix listener removal from hashtable
- **dockerfile**: tests failed due the wrong docker image
- **rtc_state.h**: initialize rtc_state out of constructor
- **rtc_state.h**: check if RTCState is valid before dereferencing it.
- **hicn-light**: missing command_id in LIST command replies + cleanup
- producer face deletion does not delete the route from fib 0
- **hicn-plugin**: insert drop node in the next nodes of face-node
- delete faces when lock count reaches 0
- **libhicnctrl**: fix hardcoded AF_INET in hc_face_to_connection
- **facemgr/android**: handle missing android information on down interfaces
- **hicn-light**: fix memory leaks when forwarder is closed
- **hicn-light**: fix forwarder receive
- fix MacOS build errors

### Feat

- release 3.6 of hicn
- add vpp logs
- **hicn-plugin**: return the list of created faces after running hicn_route_enable.
- add constants for invalid face and invalid netdevice
- **packet-cache**: use Name instead of name_key_t as hashtable key
- **forwarder**: code style
- **hicn-light**: fix mapme packet processing
- **hicn-light**: remove commented code and missing initiliazations
- **forwarder**: fix tests
- **hicn-plugin**: add log
- create prod image of hicn
- **hicn-plugin**: allow UDP tunnels to be dynamically created upon interest reception.
- **hicn-plugin**: add support for UDP tunnels in mapme
- **strategy**: fix crash and nexthops compare
- **strategy**: fix add local prefixes
- **strategy**: add local prefixes and mapme updates to replication
- **strategy**: code style
- **strategy**: improve path switch
- **transport**: improve path switch
- **strategy**: set bestpath before send mapme message
- **strategy**: send mapme update at the end of each probing phase
- **hicn-light**: add support for strategy_add_local_prefix command from config file
- **facemgr**: use separate sockets for control and polling hicn-light
- **hicn-light**: close listener and connection file descriptors on forwarder stop
- **hicnctrl**: add timeout for recv operations
- **hicn-light**: remove hicnctrl connection from 'list connection' command output
- **listeners**: set local listeners without using resolver
- **doc**: update readme file
- **doc**: update readme file and authors' list

### Perf

- **hicn-light**: remove memory allocation inside name

### Refactor

- **packet-cache**: remove macro used in packet cache entry allocation
- **facemgr/hicn-light**: refactor poll timer code

## v3.5.0 (2022-01-15)

## v3.5.0b0 (2022-01-14)

### Feat

- release 3.5 of hicn
- **quality-score**: expose quality score header file
- **bytestream**: add segment size option for bytestream production
- **strategy-map**: duplicate string before adding to strategy hashmap
- **hicn-light-control**: add help command
- **.cz.toml**: release 3.4

### Fix

- **msgbuf-pool**: fix crash in msgbuf release when debug log is set to trace
- **hicn-light-control**: fix build error on android and clean hicn-light-control output

## v3.4.3 (2021-12-20)

### Fix

- **facemgr/android**: adding mutex to protect facelet array across threads

## v3.4.2 (2021-12-17)

### Fix

- **facemgr**: workaround for blocking operation preventing loop break

## v3.4.1 (2021-12-16)

### Fix

- **transport**: do not generate NaN values for loss rate

## v3.4.0 (2021-12-15)

## v3.4.0b0 (2021-12-14)

### Feat

- **.cz.toml**: release 3.4
- **libhicntransport**: split producer socket connect and start into 2 different APIs
- facemgr: android interface as an alternative to netlink (targetSdk >= 30)
- **functional-tests**: report output of test commands into robot report
- **content-store**: report number of stale entries
- **content-store**: add 'list cache' control command
- **transport**: select forwarding strategy from transport
- libtransport threading rework
- hicn-light: add ring buffer for connection egress
- **listener**: create local listeners using the "localhost" name
- **hicn-light**: add default ipv6 listener
- **test**: functional testing link model Signed-off-by: Luca Muscariello lumuscar@cisco.com
- **test**: functional testing link model
Signed-off-by: Luca Muscariello lumuscar@cisco.com
- **content-store**: disable content store when capacity is set to 0
- separate packet cache logic from debug prints and incorporate bugfix ICN-1127

### Fix

- **listener**: fix listener removal
- misc android fixes
- **production_protocol**: fix bugs in production protocols
- ensure sendContentObject is called from portal thread
- hicn-light/mapme: don't send adjacency updates to local faces
- **loop**: stop loop in signal handler
- fix access to uninitialized memory
- facemgr/android: release all resources
- **memif_connector.cc**: call reconnect_callback_ also from memif connector
- **build-system**: generate correct cmake config files
- **strategy**: avoid crash on new forwarding strategy selection

### BREAKING CHANGE

- this commit breaks the interface between transport and
application. Calls to socket operations are not blocking anymore, so applications
expecting a blocking behavior will need to be modified.

## v3.3.2 (2021-12-10)

### Fix

- **transport**: init forwarding strategy selection

## v3.3.1 (2021-12-10)

### Feat

- **libtransport**: make API of consumer and producer socket similar

## v3.3.0 (2021-12-10)

### Fix

- specify componenet when installing cmake config files
- **build-system**: generate correct cmake config files

### Feat

- release 3.3 of hicn
- facemgr: android interface as an alternative to netlink (targetSdk >= 30)
- **functional-tests**: report output of test commands into robot report
- **content-store**: report number of stale entries
- **content-store**: add 'list cache' control command
- **transport**: select forwarding strategy from transport
- libtransport threading rework
- hicn-light: add ring buffer for connection egress
- **listener**: create local listeners using the "localhost" name
- **hicn-light**: add default ipv6 listener
- **test**: functional testing link model Signed-off-by: Luca Muscariello lumuscar@cisco.com
- **test**: functional testing link model
Signed-off-by: Luca Muscariello lumuscar@cisco.com
- **content-store**: disable content store when capacity is set to 0
- separate packet cache logic from debug prints and incorporate bugfix ICN-1127

### BREAKING CHANGE

- this commit breaks the interface between transport and
application. Calls to socket operations are not blocking anymore, so applications
expecting a blocking behavior will need to be modified.

## v3.2.3 (2021-12-06)

### Feat

- **Dockerfile.android**: add android verify job

## v3.2.2 (2021-12-03)

### Fix

- revert removal for now to remain compatible with hicn_plugin_api #promote PATCH
- fixed hc_route_t face_id / name attributes overlap
- work around to create the right route
- **strategy**: avoid crash on new forwarding strategy selection
- **Dockerfile**: update base docker image of hicn

## v3.2.1 (2021-12-02)

### Fix

- remove libparc dependency

## v3.2.0 (2021-12-01)

## v3.2.0b0 (2021-11-30)

### Feat

- **.cz.toml**: release 3.2 of hicn
- trigger mapme updates from producer sockets to traverse nats

### Fix

- added check on listener and connection add
- **listener**: handle listener creation failure
- **packet-cache**: fix msgbuf acquire and release in cs update operations
- libhicntrl: default to hicn-light-ng
- hicn-light: don't disable MAP-Me messages
- libhicn: always_inline macro compilation issues
- libtransport : default to hicn-light-ng
- hicn-light : consistent listener and connection types
- **packet-cache**: fix collisions for names in packet cache
- go back to the use of system clock for delay measurements instead of steady clock
- **hash**: fix hash function usage
- **hash**: replace hash function
- **packet-cache**: fix wrong CS hit due to data name collision in pkt cache
- consistently use std::chrono to enforce timestamp types
- **Jenkinsfile**: re-enable publishing of robot tests on hicn
- set default log level to info

## v3.1.3 (2021-11-25)

### Fix

- **Jenkinsfile**: re-enable publishing of robot tests on hicn

## v3.1.2 (2021-11-24)

### Fix

- **ctrl/CMakeLists.txt**: libfacemgr does not compile on android

## v3.1.1 (2021-11-24)

### Fix

- **transport**: do not count the same packet multiple times as definitely lost

## v3.1.0 (2021-11-24)

### Fix

- **strategy**: do not switch back to old path at the end of a probing pahse

## v3.1.0b0 (2021-11-23)

### Feat

- release 3.1
- **.cz.toml**: create relesa 3.0 hicn
- **hiperf**: code style
- **hiperf**: remove commented queue check
- **hiperf**: fix compiling error
- **hiperf**: do not start forwarder interfaces if not needed
- **hiperf**: fix check to call best path
- **hiperf**: new check to trigger best path
- **hiperf**: add set strategy command
- **hiperf**: add set strategy command
- add cmake config for dependencies
- add cmake config for dependencies
- add cmake config for dependencies

### Fix

- **pipeline**: update pipeline version
- fix bugs in sonar
- **forwarder**: fix cmake
- fix command linkage for forwarder and remove unnecessary debug prints
- fix command registration for static lib
- fix missing libevent dependency on macos

## v3.0.0 (2021-11-23)

### Fix

- **pipeline**: update pipeline version

## v3.0.0b0 (2021-11-19)

### Feat

- **.cz.toml**: create relesa 3.0 hicn
- **transport**: fix error in setting fec to ask param
- **transport**: add second threshold for loss rate
- **transport**: add low rate transport strategy
- **transport**: compute (network) loss rate per second
- **libhicnctrl**: remove connection used to send commands
- **libhicnctrl**: Add support for serialization of connection and subscription removal commands
- **notification**: add notification processing
- **notification**: update libhicnctrl to support notifications
- **notification**: add retrieval of connections for a subscription
- **strategy**: code style
- **strategy**: add comment to log the issue with sendto
- **strategy**: add test for probe generator
- **strategy**: send probes at each interest
- **strategy**: use batching mode to send probes
- **strategy**: improve probing phase
- **stategy**: improve probing in best path strategy
- **stats**: Put additional stats and improve debug prints
- **subscription**: Add support for subscribe/unsubscribe
- **vector**: Add remove operation in vector
- **forwarder**: Enable daemon mode in forwarder
- **fec**: add metadata support to reedsolomon.

### Fix

- **Jenkinsfile**: change arch from x86_64 to amd64
- fix build errors
- GCC11 fixes and workarounds
- **transport**: keep track of skipped interests
- **transport**: count as lost the fec packets that are not recevied
- **transport**: fix check to increase highest seq in order
- **transport**: fix loss rate counters
- select latest version of pipelines library
- **addresses**: fix ipv6 addresses creation for listeners and connections
- restore previous cmake submodule reference
- fix circular dependency
- **connection**: fix bug in connection name generation
- set version of jenkins shared library to stable version #promote PATCH
- use hicn as image name in all scripts #promote 2.9
- **docker-gcc**: docker build script fails if env variables don't exist
- use hicn as image name in all scripts #promote 2.9
- Fix memory leakages and unreleased msgbufs in batch read
- **vector**: fix bug on vector reallocation and add related test
- **portal.h**: improve handling of unknown packet formats in libtransport.
- **packet-cache**: Check if data received from the expected interface
- **msgbuf-pool**: Fix release of msgbufs (after queue is emptied)
- **pit-entry**: Reset nexthops during pit entry creation
- Fix socket cleanup when receiving ack/nack
- **strategy**: Fix symbol not found in libhicn
- **forwarder**: Remove unused buffer allocations in release mode
- **command**: Fix connection parsing in connection list command
- **functional-tests**: Fix functional tests for hicn-light
- **mapme**: fix nexthop slection on mapme update
- **bitmap**: Fix bitmap set operation
- **fib_entry**: code style
- **fib_entry**: reset nexthop len if no local face is found
- Use msgbuf ids instead of msgbuf pointers
- start jenkins job

### Perf

- **RTX**: reduce wainting time for RTX in low rate flows

## v2.9.6 (2021-11-18)

### Fix

- **Jenkinsfile**: change threshold test limits
- **Packaging.cmake**: vpp deb dependency version is wrong

## v2.9.5 (2021-11-17)

### Fix

- **Jenkinsfile**: change arch from x86_64 to amd64

## v2.9.4 (2021-11-11)

### Feat

- **cmake**: update version of cmake
- **cmake**: update version of cmake

## v2.9.3 (2021-11-11)

### Feat

- add dockerfile for development

## v2.9.2 (2021-11-10)

### Fix

- fix circular dependency #promote PATCH

## v2.9.1 (2021-11-09)

### Fix

- set version of jenkins shared library to stable version #promote PATCH

## v2.9.0 (2021-11-09)

### Fix

- use hicn as image name in all scripts #promote 2.9
- **docker-gcc**: docker build script fails if env variables don't exist
- use hicn as image name in all scripts #promote 2.9
- start jenkins job
- **README**: remove white spaces #promote 2.9 Signed-off-by: Angelo Mantellini <manangel@cisco.com>
- **transport**: comment
- **transport**: remove fec packets from pending interests
- **transport**: do not use nacks to compute the avg RTT
- **promote-2.9**: promote 2.9
- **versions.cmake**: wrong dep versions
- **Dockerfile-gcc**: pass branch name env variable to dockerfile
- **cmake**: create packages with right version name and repo name corrected
- **libconfig**: correct libconfig version
- ICN-1047, adding Android support for hc_sock_create_forwarder
- **libhicnctrl**: unused file descriptor was closed when freeing the libhicnctrl socket.
- **vapi_safe**: groupp all vapi msg ids definitions under vapi_safe.c
- **libhicnctrl**: initialize all the fields of the struct hc_data_t during instantiation.
- **libhicnctrl**: fix initialization of vpp_vapi.
- **libhicnctrl**: Update libhicnctrl from new forwarder
- **portal.h**: improve handling of unknown packet formats in libtransport.
- **rc.cc**: fix error in reed solomon fec when passing packets back to caller.
- publish unit test reports for all tests executables
- cleanup redundant file
- **libhicnctrl**: add missing face.c to libhicnctrl source files
- **Jenkinsfile**: fix version of jenkins shared library
- **auth**: include fec header in packet signature
- **CmakeLists.txt**: fix install path of projects.
- **vpp-memif.yaml**: fix IPv6 memif connection between 2 VPPs involved in test.
- **hicn-plugin**: include vapi source code in src and includes folders.
- **cmake**: Fetch submodule containing modules as first action in root CMakeLists.txt

### Feat

- **add-build-number-to-deb-package-name**: Ref: SPT-759 Add build number to deb package name, if defined #promote 2.9
- **versions.cmake**: correct versions of deps
- **trasnport**: comment on RTT update
- **trasnport**: keep prev rtt in case of no available samples
- **trasnport**: remove moving avg from residual loss rate
- **transport**: add avg rtt
- create deb packages
- upgrade to new pipelines library version
- upgrade to new pipelines library version
- **fec**: add metadata support to reedsolomon.
- **Jenkinsfile**: Add robot threshold configuration.

## v1.0.0 (2021-11-05)

### Feat

- **versions.cmake**: correct versions of deps
- **trasnport**: comment on RTT update
- **trasnport**: keep prev rtt in case of no available samples
- **trasnport**: remove moving avg from residual loss rate
- **transport**: add avg rtt
- create deb packages
- upgrade to new pipelines library version
- upgrade to new pipelines library version
- **fec**: add metadata support to reedsolomon.
- **Jenkinsfile**: Add robot threshold configuration.

### Fix

- **versions.cmake**: wrong dep versions
- **Dockerfile-gcc**: pass branch name env variable to dockerfile
- **cmake**: create packages with right version name and repo name corrected
- **libconfig**: correct libconfig version
- ICN-1047, adding Android support for hc_sock_create_forwarder
- **libhicnctrl**: unused file descriptor was closed when freeing the libhicnctrl socket.
- **vapi_safe**: groupp all vapi msg ids definitions under vapi_safe.c
- **libhicnctrl**: initialize all the fields of the struct hc_data_t during instantiation.
- **libhicnctrl**: fix initialization of vpp_vapi.
- **libhicnctrl**: Update libhicnctrl from new forwarder
- **portal.h**: improve handling of unknown packet formats in libtransport.
- **rc.cc**: fix error in reed solomon fec when passing packets back to caller.
- publish unit test reports for all tests executables
- cleanup redundant file
- **libhicnctrl**: add missing face.c to libhicnctrl source files
- **Jenkinsfile**: fix version of jenkins shared library
- **auth**: include fec header in packet signature
- **CmakeLists.txt**: fix install path of projects.
- **vpp-memif.yaml**: fix IPv6 memif connection between 2 VPPs involved in test.
- **hicn-plugin**: include vapi source code in src and includes folders.
- **cmake**: Fetch submodule containing modules as first action in root CMakeLists.txt

## v21.06-rc0 (2021-07-20)

## v21.01-rc0 (2021-02-10)

## v20.05-release (2020-11-11)

## v20.01 (2020-01-30)

## v19.08 (2019-08-14)

## v19.04 (2019-04-29)

## v19.01 (2019-01-25)
