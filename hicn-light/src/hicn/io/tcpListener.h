/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file tcpListener.h
 * @brief Listens for in coming TCP connections
 *
 * This is the "server socket" of hicn-light for TCP connections.  The actual
 * I/O is handled by {@link StreamConnection}.
 *
 */

#ifndef tcpListener_h
#define tcpListener_h

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <hicn/core/forwarder.h>
#include <hicn/io/listener.h>
#include <stdlib.h>

ListenerOps *tcpListener_Create(Forwarder *forwarder, char *listenerName,
        const address_t * address, char *interfaceName);
#endif  // tcpListener_h
