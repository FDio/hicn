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
 * @file hicnListener.h
 * @brief Listens for in coming HIcn connections
 *
 *
 */

#ifndef hicnListener_h
#define hicnListener_h

#include <src/core/forwarder.h>
#include <src/core/messageHandler.h>
#include <src/io/listener.h>
#include <stdlib.h>

struct hicn_listener;
typedef struct hicn_listener HIcnListener;

ListenerOps *hicnListener_CreateInet(Forwarder *forwarder, char *symbolic,
                                     Address *address);
ListenerOps *hicnListener_CreateInet6(Forwarder *forwarder, char *symbolic,
                                      Address *address);
bool hicnListener_Punting(ListenerOps *ops, const char *prefix);
bool hicnListener_Bind(ListenerOps *ops, const Address *remoteAddress);
bool hicnListener_SetConnectionId(ListenerOps *ops, unsigned connId);
// const Address *hicnListener_GetTunAddress(const ListenerOps *ops);
#endif  // hicnListener_h
