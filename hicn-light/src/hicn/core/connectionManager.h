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
 * @file connectionManager.h
 * @brief The connection manager handles connection events, such as going down
 *
 * The connection manager listens to the event notification system.  Based on
 * those events, the connection manager will take specific actions.  This is
 * expected to be a singleton instantiated by the forwarder.
 *
 */

#ifndef connectionManager_h
#define connectionManager_h

#include <hicn/core/forwarder.h>

struct connection_manager;
typedef struct connection_manager ConnectionManager;

ConnectionManager *connectionManager_Create(Forwarder *forwarder);

void connectionManager_Destroy(ConnectionManager **managerPtr);
#endif  // connectionManager_h
