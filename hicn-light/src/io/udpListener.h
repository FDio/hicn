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

#ifndef udpListener_h
#define udpListener_h

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <src/core/forwarder.h>
#include <src/io/listener.h>
#include <stdlib.h>

struct udp_listener;
typedef struct udp_listener UdpListener;

ListenerOps *udpListener_CreateInet6(Forwarder *forwarder,
                                     struct sockaddr_in6 sin6);
ListenerOps *udpListener_CreateInet(Forwarder *forwarder,
                                    struct sockaddr_in sin);
// void udpListener_SetPacketType(ListenerOps *ops, MessagePacketType type);
#endif  // udpListener_h
