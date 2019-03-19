Application examples using hicn stack
==================

## Introduction ##

higet and hicn-http-server are two application examples that use hicn stack.

## Using hICN Application Examples ##

### Platforms ###

The hICN application Examples have been tested in:

- Ubuntu 16.04 (x86_64)
- Debian Testing
- MacOSX 10.12

Other platforms and architectures may work.

### Dependencies ###

Build dependencies:

- c++14 ( clang++ / g++ )
- CMake 3.4

Basic dependencies:

- OpenSSL
- pthreads
- Libevent
- Libparc

## Executables ##

The application examples are a set of binary executables that are used to run a simple http client (higet) and a simple http server (hicn-http-server).

### higet ###

The command `higet` runs the higet application. higet can be executed 
with the following options:

```
higet [OPTION]... [URL]...

Options:
	-O filename             write documents to FILE
	-S                      print server response
Example:
	higet -O - http://origin/index.html

```

### hicn-http-server ###

`hicn-http-server` is a web server able to publish content and generate http responses over TCP/HICN
The command can be executed in the following way:

```
hicn-http-server [OPTIONS]

Options:
	-p path					path to root foot folder
	-f confFile				configuration file
	-o tcpPort				tcp listener port
	-l webserverPrefix		webserver prefix
	-x tcpProxyPrefix		tcp proxy prefix
	-z hicnProxyPrefix		hicn proxy prefix
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
