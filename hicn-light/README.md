hicn-light
=======

## Introduction ##

hicn-light is a socket based forwarder

## Using hicn-light ##

### Platforms ###

hicn-light has been tested in:

- Ubuntu 16.04 (x86_64)
- Debian Testing
- MacOSX 10.12

Other platforms and architectures may work.

### Dependencies ###

Build dependencies:

- c99 ( clang / gcc )
- CMake 3.4

Basic dependencies:

- OpenSSL
- pthreads
- Libevent
- Libparc

## hicn-light Executables ##

hicn-light is a set of binary executables that are used to run a forwarder instance. 
The forwarder can be run and configured using the commands

- `hicnLightDaemon`
- `hicnLightControl`

Use the `-h` option to display the help messages

### hicn-light Daemon ###

The command `hicnLightDaemon` runs the hicn-light forwarder. The forwarder can be executed 
with the following options:

```
hicnLightDaemon [--port port] [--daemon] [--capacity objectStoreSize] [--log facility=level] 
                [--log-file filename] [--config file]

Options:

--port            = tcp port for local in-bound connections
--daemon          = start as daemon process
--capacity        = maximum number of content objects to cache. To disable the cache 
                    objectStoreSize must be 0.
                    Default vaule for objectStoreSize is 100000
--log             = sets a facility to a given log level. You can have multiple of these.
                    facilities: all, config, core, io, message, processor
                    levels: debug, info, notice, warning, error, critical, alert, off
                    example: hicnLightDaemon --log io=debug --log core=off
--log-file        = file to write log messages to (required in daemon mode)
--config          = configuration filename
```

The configuration file contains configuration lines as per hicnLightControl (see below for all
the available commands). If logging level or content store capacity is set in the configuration
file, it overrides the command_line. When a configuration file is specified, no default listeners
are setup.  Only 'add listener' lines in the configuration file matter.

If no configuration file is specified, hicnLightDaemon will listen on TCP and UDP ports specified
by the --port flag (or default port).  It will listen on both IPv4 and IPv6 if available. The
default port for hicn-light is 9695. Commands are expected on port 2001.

### hicn-light Control ###

`hicnLightControl` can be used to send command to the hicn-light forwarder and configure it.
The command can be executed in the following way:

```
hicnLightControl [commands]

Options:
    -h              = This help screen
    commands        = configuration line to send to hicn-light (use 'help' for list)
```

#### Available Commands in hicn-light Control ####

This is the full list of available commands in `hicnLightControl`. This commands can be used
from the command line running `hicnLightControl` as explained before, or listing them in a
configuration file.

Information about the commands are also available in the `hicnLightControl` help message.

`add listener`: creates a TCP or UDP listener with the specified options on the local forwarder.
For local connections (application to hicn-light) we expect a TCP listener. The default port for
the local listener is 9695.

```
add listener <protocol> <symbolic> <local_adress> <local_port>

  <symbolic>        :User defined name for listener, must start with alpha and bealphanum
  <protocol>        :tcp | udp
  <localAddress>    :IPv4 or IPv6 address
  <local_port>      :TCP/UDP port

```

`add listener hicn`: creates a hicn listener with the specified options on the local forwarder.

```
add listener hicn <symbolic> <local_adress>

  <symbolic>        :User defined name for listener, must start with alpha and be alphanum
  <localAddress>    :IPv4 or IPv6 address

```

`add connection`: creates a TCP or UDP connection on the local forwarder with the specified options.

```
add connection <protocol> <symbolic> <remote_ip> <remote_port> <local_ip> <local_port>

  <protocol>              : tcp | udp
  <symbolic>              : symbolic name, e.g. 'conn1' (must be unique, start with alpha)
  <remote_ip>             : the IPv4 or IPv6 of the remote system
  <remote_port>           : the remote TCP/UDP port
  <local_ip>              : local IP address to bind to
  <local_port>            : local TCP/UDP port

```
`add connection hicn`: creates an hicn connection on the local forwarder with the specified options.

```
add connection hicn <symbolic> <remote_ip> <local_ip>

  <symbolic>            : symbolic name, e.g. 'conn1' (must be unique, start with alpha)
  <remote_ip>           : the IPv4 or IPv6 of the remote system
  <local_ip>            : local IP address to bind to

```
`list`: lists the connections, routes or listeners available on the local hicn-light forwarder
```
list <connections | routes | listeners>

```
`add route`: adds a route to the specified connection

```
add route <symbolic | connid> <prefix> <cost>

  <symbolic>   :The symbolic name for an exgress (must be unique, start with alpha)
  <connid>:    :The egress connection id (see 'help list connections')
  <prefix>:    :ipAddress/netmask
  <cost>:      :positive integer representing cost
```

`remove connection`: removes the specified connection. At the moment, this commands is available
only for UDP connections, TCP is ignored.

```
remove connection <protocol> <symbolic | connid>

  <protocol>   : tcp | upd. This is the protocol used to create the connection.
  <symbolic>   :The symbolic name for an exgress (must be unique, start with alpha)
  <connid>:    :The egress connection id (see 'help list connections')

```

`remove route`: remove the specified prefix for a local connection

```
remove route <symbolic | connid> <prefix>

  <connid>    : the alphanumeric name of a local connection
  <prefix>    : the prefix (ipAddress/netmask) to remove
```

`cache serve`: enables/disables replies from local content store (if available)

```
cache serve <on|off>
```
`cache store`:  enables/disables the storage of incoming data packets in the local content store
(if available)

```
cache store <on|off>

```
`cache clear`: removes all the cached data form the local content store (if available)

```
cache clear

```
`set strategy`: sets the forwarding strategy for a give prefix. There are 4 different strategies
implemented in hicn-light:

- random: each interest is forwarded randomly to one of the available output connections
- random_per_dash_segment: the output connection is selected randomly for each DASH segment.
  This can be used only for DASH video streams.
- loadbalancer: each interest is forwarded toward the output connection with the lowest number
  of pending interests. The pending interest are the interest sent on a certain connection but
  not yet satisfied. More information are available in: 
  G. Carofiglio, M. Gallo, L. Muscariello, M. Papalini, S. Wang, 
  "Optimal multipath congestion control and request forwarding in information-centric networks", 
  ICNP 2013.
- loadbalancer_with_delay: implements the same strategy as loadbalancer but it takes into account
  also the propagation delay behind each connections.

```
set strategy <prefix> <strategy>

  <preifx>    : the prefix to which apply the forwarding strategy
  <strategy>  : random | random_per_dash_segment | loadbalancer | loadbalancer_with_delay
```
`set wldr`: turns on/off WLDR on the specified connection. WLDR (Wireless Loss Detiection and
 Recovery) is a protocol that can be used to recover losses generated by unreliable wireless 
 connections, such as WIFI. More information on WLDR are available in: 
 G. Carofiglio, L. Muscariello, M. Papalini, N. Rozhnova, X. Zeng, 
 "Leveraging ICN In-network Control for Loss Detection and Recovery in Wireless Mobile networks", 
 ICN 2016. Notice that WLDR is currently available only for UDP connections. In order to work
 properly, WLDR needs to be activated on both side of the connection.

```
set wldr <on|off> <symbolic | connid>

  <symbolic>   :The symbolic name for an exgress (must be unique, start with alpha)
  <connid>:    :The egress connection id (see 'help list connections')

```
`add punting`: Add punting rules to the forwarders.

```
add punting <symbolic> <prefix>

 <symbolic> : listener symbolic name
 <address>  : prefix to add as a punting rule. (example 1234::0/64)
```
`mapme enable`: enables/disables mapme

```
mapme enable <on|off>
```
`mapme discovery`: enables/disables mapme discovery

```
mapme discovery <on|off>
```

`mapme timescale`: set the timescale value expressed in millisencods

```
mapme timescale <milliseconds>
```
`mapme retx`: set the retrasmission time value expressed in millisecond

```
mapme retx <milliseconds>
```
`quit`: Exits the interactive shell

### hicn-light Configuration File Example ###

This is an example of a simple configuration file for hicn-light. It can be loaded by running
the command `hicnLightDaemon --config configFile.cfg`, assuming the file name is configFile.cfg

```
#create a local listener on port 9199. This will be used by the applications to talk
with the forwarder
add listener udp local0 127.0.0.1 9199

#create a connection with a remote node
add connection udp conn0 192.168.0.20 12345 127.0.0.1 9199

#add a route toward the remote node
add route conn0 192.168.0.20/24 1
```


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
