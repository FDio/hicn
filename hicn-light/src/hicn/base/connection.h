/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * @file connection.h
 * @brief hICN connections
 */

#ifndef HICNLIGHT_CONNECTION_H
#define HICNLIGHT_CONNECTION_H

#include <hicn/base/address_pair.h>
#include <hicn/base/listener.h>
#include <hicn/face.h>
#include <hicn/util/log.h>

// XXX TODO why no connection name like in listener ?
typedef struct {
    unsigned id;
    char * interface_name;
    face_type_t type;
    address_pair_t * pair;
    int fd;
//    bool up;
    bool local;
    face_state_t state;
    face_state_t admin_state;
#ifdef WITH_POLICY
    uint32_t priority;
#endif /* WITH_POLICY */
    void * data;
    
    void * forwarder; // recv only
    bool closed;
} connection_t;

#define connection_get_id(connection) ((connection)->id)
#define connection_get_pair(connection) ((connection)->pair)
#define connection_get_local(connection) \
    (address_pair_local(connection_get_pair(connection)))
#define connection_get_remote(connection) \
    (address_pair_remote(connection_get_pair(connection)))
#define connection_is_up(connection) ((connection)->up)
#define connection_is_local(connection) ((connection)->local)
#define connection_get_state(connection) ((connection)->state)
#define connection_set_state(connection, state) \
    (connection)->state = state
#define connection_get_admin_state(connection) ((connection)->admin_state)
#define connection_set_admin_state(connection, state) \
    (connection)->admin_state = state
#define connection_get_interface_name(connection) \
    ((connection)->interface_name)

#ifdef WITH_POLICY
#define connection_get_priority(connection) ((connection)->priority)
#define connection_set_priority(connection, priority) \
    (connection)->priority = priority
#endif /* WITH_POLICY */

int connection_create_on_listener(const address_pair_t * pair, const listener_t * listener,
        const void * forwarder);

int connection_create(face_type_t type, const address_pair_t * pair,
        void * forwarder);

int connection_initialize(connection_t * connection,
        const char * interface_name, int fd,
        const address_pair_t * address_pair, bool local,
        unsigned connection_id);

int connection_finalize(connection_t * connection);

#endif /* HICNLIGHT_CONNECTION_H */
