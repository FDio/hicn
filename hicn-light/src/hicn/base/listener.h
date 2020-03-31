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
 * @file listener.h
 * @brief hICN listeners
 */

#ifndef HICNLIGHT_LISTENER_H
#define HICNLIGHT_LISTENER_H

#include <hicn/base/address_pair.h>
#include <hicn/face.h>

struct forwarder_s;

/* This structure holds what is in common to all listeners */
typedef struct {
    int id;
    const char * name;

    /*
     * We keep type and address consecutive as they are used for lookup in the
     * listener table, so as to avoid copies
     */
    face_type_t type;
    address_t address;

    const char * interface_name;
    unsigned interface_index;
    unsigned family;
    int fd;
    void * data; /* Listener specific data */
    struct forwarder_s * forwarder;
} listener_t;

#define listener_get_id(listener) ((listener)->id)
#define listener_get_name(listener) ((listener)->name)
#define listener_get_type(listener) ((listener)->type)
#define listener_get_interface_name(listener) ((listener)->interface_name)
#define listener_get_interface_index(listener) ((listener)->interface_index)
#define listener_get_address(listener) (&(listener)->address)

#define listener_has_valid_type(listener) \
    (face_type_is_valid((listener)->type))

listener_t * listener_create(face_type_t type, const address_t * address,
        const char * interface_name, const char * symbolic, void * forwarder);

int listener_initialize(listener_t * listener, face_type_t * type,
        void * forwarder, const char * name, const address_t * address,
        const char * interface_name, unsigned listener_id);

int listener_finalize(listener_t * listener);

int listener_punt(const listener_t * listener, const char * prefix_s);

int listener_get_socket(const listener_t * listener,
        const address_pair_t * pair);

unsigned listener_create_connection(const listener_t * listener, int fd,
        const address_pair_t * pair);

void listener_setup_all(const struct forwarder_s * forwarder, uint16_t port, const char *localPath);

void listener_setup_local_ipv4(const struct forwarder_s * forwarder,  uint16_t port);

#endif /* HICNLIGHT_LISTENER_H */
