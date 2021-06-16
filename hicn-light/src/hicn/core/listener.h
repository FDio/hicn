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

#include <hicn/face.h>

#include "address_pair.h"
#include "msgbuf.h"
#include "../base/loop.h"

struct forwarder_s;

typedef struct {
  address_t address;
  face_type_t type;
} listener_key_t;

/* This structure holds what is in common to all listeners */
typedef struct {
    int id;
    char * name;
    union {
        listener_key_t key;
        struct {
            address_t address;
            face_type_t type;
        };
    };

    char * interface_name;
    unsigned interface_index;
    unsigned family;
    int fd;
    event_t *event_data;
    void * data; /* Listener specific data */
    struct forwarder_s * forwarder;
} listener_t;

#define listener_get_id(L) ((L)->id)
#define listener_get_name(L) ((L)->name)
#define listener_get_key(L) (&(L)->key)
#define listener_get_type(L) ((L)->type)
#define listener_get_interface_name(L) ((L)->interface_name)
#define listener_get_interface_index(L) ((L)->interface_index)
#define listener_get_address(L) (&(L)->address)

#define listener_has_valid_type(L) \
    (face_type_is_valid((L)->type))

listener_t * listener_create(face_type_t type, const address_t * address,
        const char * interface_name, const char * symbolic, struct forwarder_s * forwarder);

int listener_initialize(listener_t * listener, face_type_t type, const char * name,
        unsigned listener_id, const address_t * address,
        const char * interface_name, struct forwarder_s * forwarder);

int listener_finalize(listener_t * listener);

int listener_punt(const listener_t * listener, const char * prefix_s);

int listener_get_socket(const listener_t * listener, const address_t * local,
        const address_t * remote, const char * interface_name);

unsigned listener_create_connection(const listener_t * listener,
        const address_pair_t * pair);

void listener_setup_all(const struct forwarder_s * forwarder, uint16_t port, const char *localPath);

void listener_setup_local_ipv4(struct forwarder_s * forwarder,  uint16_t port);

void listener_process_packet(const listener_t * listener,
        const uint8_t * packet, size_t size);


ssize_t listener_read_single(listener_t * listener);
ssize_t listener_read_batch(listener_t * listener);

/**
 * @brief Callback helper function for batch reading data from listener fd.
 *
 * This function is usually called from the listener read callback to proceed to
 * actual reading of data from the fd.
 *
 * @see listener_read_callback
 *
 * NOTE: the function returns size_t as for TCP we might need to know how much
 * data we can consume from the socket.
 */
ssize_t listener_read_callback(listener_t * listener, int fd, void * user_data);

#endif /* HICNLIGHT_LISTENER_H */
