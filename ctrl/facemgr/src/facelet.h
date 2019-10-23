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
 * \file facelet.h
 * \brief Facelet
 *
 * A facelet consists in partial information and annotations collected towards
 * the contruction of the final face that will be sent to the forwarder.
 *
 * It might also consist in a pattern allowing the deletion of a group of face
 * for instance.
 */
#ifndef FACEMGR_FACELET_H
#define FACEMGR_FACELET_H

#include <stdbool.h>

#include <hicn/ctrl/face.h>
#include <hicn/facemgr.h>

#define MAXSZ_FACELET 1024

/* NOTE: Any test should be sufficient */
#define IS_VALID_NETDEVICE(netdevice) ((netdevice.index != 0) && (netdevice.name[0] != '\0'))

typedef struct facelet_s facelet_t;

/* Facelet status */
#define foreach_facelet_status  \
    _(UNDEFINED)                \
    _(NEW)                      \
    _(CLEAN)                    \
    _(DIRTY)                    \
    _(CONFLICT)                 \
    _(DELETED)                  \
    _(IGNORED)                  \
    _(ERROR)                    \
    _(N)

typedef enum {
#define _(x) FACELET_STATUS_ ## x,
    foreach_facelet_status
#undef _
} facelet_status_t;

extern const char * facelet_status_str[];

/* Facelet attribute status */

/*
 * We expect an attribute in the cache to be able to take any value but
 * UNDEFINED and N, which facelet events should either be UNSET or CLEAN
 */
#define foreach_facelet_attr_status             \
    _(UNDEFINED, '?')                           \
    _(UNSET, 'X')                               \
    _(CLEAN, ' ')                               \
    _(DIRTY, '*')                               \
    _(PENDING, 'P')                             \
    _(CONFLICT, '!')                            \
    _(N, '-')

typedef enum {
#define _(x, y) FACELET_ATTR_STATUS_ ## x,
    foreach_facelet_attr_status
#undef _
} facelet_attr_status_t;

extern const char * facelet_attr_status_str[];
extern const char * facelet_attr_status_str_short[];

/* Facelet attribute */

#define foreach_facelet_attr                    \
    _(netdevice_type_t, netdevice_type)         \
    _(netdevice_t, netdevice)                   \
    _(int, family)                              \
    _(ip_address_t, local_addr)                 \
    _(u16, local_port)                          \
    _(ip_address_t, remote_addr)                \
    _(u16, remote_port)                         \
    _(face_state_t, admin_state)                \
    _(face_state_t, state)                      \
    _(facemgr_face_type_t, face_type)

#define foreach_facelet_event   \
    _(UNDEFINED)                \
    _(GET)                      \
    _(CREATE)                   \
    _(UPDATE)                   \
    _(DELETE)                   \
    _(SET_PARAMS)               \
    _(SET_UP)                   \
    _(SET_DOWN)                 \
    _(SET_TAGS)                 \
    _(CLEAR_TAGS)               \
    _(ADD_TAG)                  \
    _(REMOVE_TAG)               \
    _(N)

#define MAXSZ_EVENT__ 10
#define MAXSZ_EVENT_ MAXSZ_EVENT_ + 1

/**
 * \brief Enumeration of the possible types of event
 */
typedef enum {
#define _(x) FACELET_EVENT_ ## x,
foreach_facelet_event
#undef _
} facelet_event_t;

extern const char * facelet_event_str[];

/**
 * \brief Create a facelet.
 */
facelet_t * facelet_create();

facelet_t * facelet_create_from_netdevice(netdevice_t * netdevice);

int facelet_validate_face(const facelet_t * facelet);

facelet_t * facelet_create_from_face(face_t * face);

void facelet_free(facelet_t * facelet);

facelet_t * facelet_dup(const facelet_t * current_facelet);

int facelet_cmp(const facelet_t * f1, const facelet_t * f2);

/* NOTE: only clean attributes are matched */
bool facelet_match(const facelet_t * facelet, const facelet_t * facelet_match);

/**
 * \brief Returns whether the specified facelet has all key attributes defined.
 *
 * Key attributes are netdevice and family. If both are present, this allows to
 * uniquely identify a facelet, otherwise it is a 'wildcard' facelet
 * specification and might match several facelets.
 */
bool facelet_has_key(const facelet_t * facelet);

#define FACELET_ACCESSORS_H(TYPE, NAME)                                         \
bool facelet_has_ ## NAME(const facelet_t * facelet);                           \
facelet_attr_status_t facelet_get_ ## NAME ## _status(const facelet_t * facelet);\
int facelet_get_ ## NAME(const facelet_t * facelet, TYPE * NAME);               \
int facelet_set_ ## NAME(facelet_t * facelet, TYPE NAME);                       \
int facelet_unset_ ## NAME(facelet_t * facelet);

#define _(TYPE, NAME) FACELET_ACCESSORS_H(TYPE, NAME)
foreach_facelet_attr
#undef _

int facelet_get_face(const facelet_t * facelet, face_t ** pface);

int facelet_merge(facelet_t * facelet, const facelet_t * facelet_to_merge);

facelet_status_t facelet_get_status(const facelet_t * facelet);
void facelet_set_status(facelet_t * facelet, facelet_status_t status);

void facelet_set_bj_done(facelet_t * facelet);
void facelet_unset_bj_done(facelet_t * facelet);
bool facelet_is_bj_done(const facelet_t * facelet);
void facelet_set_au_done(facelet_t * facelet);
bool facelet_is_au_done(const facelet_t * facelet);

facelet_event_t facelet_get_event(const facelet_t * facelet);
void facelet_set_event(facelet_t * facelet, facelet_event_t event);

int facelet_snprintf(char * buf, size_t size, facelet_t * facelet);

#define DUMP_FACELET(msg, facelet) do {                 \
    char buf[MAXSZ_FACELET];                            \
    facelet_snprintf(buf, MAXSZ_FACELET, facelet);      \
    DEBUG("%s : %s", msg, buf);                         \
} while(0)

#endif /* FACEMGR_FACELET_H */
