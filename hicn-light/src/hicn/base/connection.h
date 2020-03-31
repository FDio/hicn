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
#include <hicn/base/msgbuf.h>
#include <hicn/face.h>

#ifdef WITH_POLICY
#include <hicn/policy.h>
#endif /* WITH_POLICY */

#define CONNECTION_ID_UNDEFINED ~0

#ifdef WITH_MAPME
typedef enum {
  CONNECTION_EVENT_CREATE,
  CONNECTION_EVENT_DELETE,
  CONNECTION_EVENT_UPDATE,
  CONNECTION_EVENT_SET_UP,
  CONNECTION_EVENT_SET_DOWN,
  CONNECTION_EVENT_PRIORITY_CHANGED,
  CONNECTION_EVENT_TAGS_CHANGED,
} connection_event_t;

#endif /* WITH_MAPME */

struct wldr_s;

typedef struct {
    unsigned id;
    const char * name;
    char * interface_name;
    face_type_t type;
    address_pair_t pair;
    int fd;
//    bool up;
    bool local;
    face_state_t state;
    face_state_t admin_state;
#ifdef WITH_POLICY
    policy_tags_t tags;
    uint32_t priority;
#endif /* WITH_POLICY */
    void * data;

    void * forwarder; // recv only
    bool closed;

    /* WLDR */

    bool wldr_autostart;
    /*
     * if true, wldr can be set automatically by default this value is set to
     * true. if wldr is activated using a command (config file/hicnLightControl)
     * this value is set to false so that a base station can not disable wldr at
     * the client.
     */
    struct wldr_s * wldr;

} connection_t;

#if 1
#define connection_get_id(C) ((C)->id)
#define connection_id_is_valid(ID) (ID != CONNECTION_ID_UNDEFINED)
#define connection_get_name(C) ((C)->name)
#define connection_get_type(C) ((C)->type)
#define connection_has_valid_id(C) (connection_id_is_valid(connection_get_id(C))
#define connection_get_pair(C) (&(C)->pair)
#define connection_get_local(C) (address_pair_local(connection_get_pair(C)))
#define connection_get_remote(C) (address_pair_remote(connection_get_pair(C)))
#define connection_get_local(C) (address_pair_local(connection_get_pair(C)))
#define connection_get_remote(C) (address_pair_remote(connection_get_pair(C)))
#define connection_is_up(C) ((C)->state == FACE_STATE_UP)
#define connection_is_closed(C) ((C)->closed == true)
#define connection_is_local(C) ((C)->local)
#define connection_get_state(C) ((C)->state)
#define connection_set_state(C, STATE) (C)->state = STATE
#define connection_get_admin_state(C) ((C)->admin_state)
#define connection_set_admin_state(C, STATE) (C)->admin_state = STATE
#define connection_get_interface_name(C) ((C)->interface_name)

#ifdef WITH_POLICY
#define connection_get_priority(C) ((C)->priority)
#define connection_set_priority(C, PRIORITY) (C)->priority = PRIORITY
#define connection_get_tags(C) ((C)->tags)
#define connection_set_tags(C, TAGS) (C)->tags = TAGS
#define connection_has_tag(C, TAG) policy_tags_has(connection_get_tags(C), TAG)
#define connection_add_tag(C, TAG) policy_tags_add(connection_get_tags(X), TAG)
#define connection_remove_tag(C, TAG)           \
do {                                            \
    policy_tags_t _conn_var(tags);              \
    _conn_var(tags) = connection_get_tags(C);   \
    policy_tags_remove(_conn_var(tags), (TAG)); \
    connection_set_tags((C), _conn_var(tags));  \
} while(0)
#define connection_clear_tags(C) connection_set_tags(C, POLICY_TAGS_EMPTY)

#endif /* WITH_POLICY */


#else

/* Accessors */
static inline unsigned connection_get_id(const connection_t * connection);

#define connection_id_is_valid(id) (id != CONNECTION_ID_UNDEFINED)
#define connection_has_valid_id(C) (connection_id_is_valid(connection_get_id(C))

static inline char * connection_get_name(const connection_t * connection);

static inline face_type_t connection_get_type(const connection_t * connection);

static inline address_pair_t * connection_get_pair(const connection_t * connection);

#define connection_get_local(C) (address_pair_local(connection_get_pair(C)))
#define connection_get_remote(C) (address_pair_remote(connection_get_pair(C)))

static inline bool connection_is_up(const connection_t * connection);

static inline bool connection_is_local(const connection_t * connection);

static inline face_state_t connection_get_state(const connection_t * connection);

static inline void connection_set_state(connection_t * connection, face_state_t state);

static inline face_state_t connection_get_admin_state(const connection_t * connection);

static inline void connection_set_admin_state(connection_t * connection, face_state_t state);

static inline const char * connection_get_interface_name(const connection_t * connection);

#ifdef WITH_POLICY

static inline uint32_t connection_get_priority(const connection_t * connection);

static inline void connection_set_priority(connection_t * connection, uint32_t priority);

static inline policy_tags_t connection_get_tags(const connection_t * connection);

static inline void connection_set_tags(connection_t * connection, policy_tags_t tags);

#define connection_has_tag(C, TAG) policy_tags_has(connection_get_tags(C), TAG)

#define connection_add_tag(C, TAG) policy_tags_add(connection_get_tags(X), TAG)

#define connection_remove_tag(C, TAG)           \
do {                                            \
    policy_tags_t _conn_var(tags);              \
    _conn_var(tags) = connection_get_tags(C);   \
    policy_tags_remove(_conn_var(tags), (TAG)); \
    connection_set_tags((C), _conn_var(tags));  \
} while(0)

#define connection_clear_tags(C) connection_set_tags(C, POLICY_TAGS_EMPTY)

#endif /* WITH_POLICY */

#endif

connection_t * connection_create(face_type_t type, const char * name,
        const address_pair_t * pair, void * forwarder);

int connection_initialize(connection_t * connection,
        const char * name, const char * interface_name, int fd,
        const address_pair_t * address_pair, bool local,
        unsigned connection_id);

int connection_finalize(connection_t * connection);

int connection_send_packet(const connection_t * connection,
        const uint8_t * packet, size_t size);

bool connection_send(const connection_t * connection, msgbuf_t * msgbuf,
        bool queue);

size_t connection_process_buffer(connection_t * connection, const uint8_t * buffer, size_t size);

/* WLDR */

void connection_wldr_allow_autostart(connection_t * connection, bool value);

bool connection_wldr_autostart_is_allowed(connection_t * connection);

void connection_wldr_enable(connection_t * connection, bool value);

bool connection_has_wldr(const connection_t * connection);

void connection_wldr_detect_losses(const connection_t * connection, msgbuf_t * msgbuf);

void connection_wldr_handle_notification(const connection_t * connection, msgbuf_t * msgbuf);

#endif /* HICNLIGHT_CONNECTION_H */
