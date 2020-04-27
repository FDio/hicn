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

#include <hicn/face.h>
#include <hicn/ctrl/route.h>

#define MAXSZ_FACELET 1024

#define FACELET_MAX_ERRORS 10

/* NOTE: Any test should be sufficient */
#define IS_VALID_NETDEVICE(netdevice) ((netdevice.index != 0) && (netdevice.name[0] != '\0'))

typedef struct facelet_s facelet_t;

/* Face type */

#define foreach_face_type_layer \
    _(UNDEFINED)                \
    _(3)                        \
    _(4)                        \
    _(N)

typedef enum {
#define _(x) FACE_TYPE_LAYER_ ## x,
    foreach_face_type_layer
#undef _
} face_type_layer_t;

#define foreach_face_type_encap \
    _(UNDEFINED)                \
    _(TCP)                      \
    _(UDP)                      \
    _(N)

typedef enum {
#define _(x) FACE_TYPE_ENCAP_ ## x,
    foreach_face_type_encap
#undef _
} face_type_encap_t;

typedef struct {
   face_type_layer_t layer;
   face_type_encap_t encap;
} facemgr_face_type_t;


extern const char * face_type_layer_str[];
extern const char * face_type_encap_str[];

#define FACEMGR_FACE_TYPE_STR(x)                                \
    face_type_layer_str[x.layer], face_type_encap_str[x.encap]

#define FACEMGR_FACE_TYPE_UNDEFINED (facemgr_face_type_t) {     \
    .layer = FACE_TYPE_LAYER_UNDEFINED,                         \
    .encap = FACE_TYPE_ENCAP_UNDEFINED,                         \
}

#define FACEMGR_FACE_TYPE_NATIVE_UDP (facemgr_face_type_t) {    \
    .layer = FACE_TYPE_LAYER_3,                                 \
    .encap = FACE_TYPE_ENCAP_UDP,                               \
}

#define FACEMGR_FACE_TYPE_NATIVE_TCP (facemgr_face_type_t) {    \
    .layer = FACE_TYPE_LAYER_3,                                 \
    .encap = FACE_TYPE_ENCAP_TCP,                               \
}

#define FACEMGR_FACE_TYPE_OVERLAY_UDP (facemgr_face_type_t) {   \
    .layer = FACE_TYPE_LAYER_4,                                 \
    .encap = FACE_TYPE_ENCAP_UDP,                               \
}

#define FACEMGR_FACE_TYPE_OVERLAY_TCP (facemgr_face_type_t) {   \
    .layer = FACE_TYPE_LAYER_4,                                 \
    .encap = FACE_TYPE_ENCAP_TCP,                               \
}

/* Facelet status */
#define foreach_facelet_status  \
    _(UNDEFINED)                \
    _(DOWN)                     \
    _(UNCERTAIN)                \
    _(INCOMPLETE)               \
    _(CREATE)                   \
    _(CLEAN)                    \
    _(IGNORED)                  \
    _(UPDATE)                   \
    _(DELETE)                   \
    _(DELETED)                  \
    _(N)

typedef enum {
#define _(x) FACELET_STATUS_ ## x,
    foreach_facelet_status
#undef _
} facelet_status_t;

extern const char * facelet_status_str[];

/* Facelet error reason */
#define foreach_facelet_error_reason    \
    _(UNDEFINED)                        \
    _(UNSPECIFIED_ERROR)                \
    _(FORWARDER_OFFLINE)                \
    _(PERMISSION_DENIED)                \
    _(INTERNAL_ERROR)                   \
    _(N)

typedef enum {
#define _(x) FACELET_ERROR_REASON_ ## x,
    foreach_facelet_error_reason
#undef _
} facelet_error_reason_t;

extern const char * facelet_error_reason_str[];

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

#ifdef WITH_POLICY
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
    _(u32, priority)                            \
    _(facemgr_face_type_t, face_type)
#else
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
#endif /* WITH_POLICY */

#define foreach_facelet_event   \
    _(UNDEFINED)                \
    _(GET)                      \
    _(CREATE)                   \
    _(UPDATE)                   \
    _(DELETE)                   \
    _(SET_UP)                   \
    _(SET_DOWN)                 \
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

unsigned facelet_get_id(facelet_t * facelet);
void facelet_set_id(facelet_t * facelet, unsigned id);

int facelet_validate_face(const facelet_t * facelet);

facelet_t * facelet_create_from_face(face_t * face);

void facelet_free(facelet_t * facelet);

facelet_t * facelet_dup(const facelet_t * current_facelet);

int facelet_cmp(const facelet_t * f1, const facelet_t * f2);

bool facelet_equals(const facelet_t * facelet1, const facelet_t * facelet2);

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
void facelet_set_ ## NAME ## _status(facelet_t * facelet,                       \
        facelet_attr_status_t status);                                          \
int facelet_get_ ## NAME(const facelet_t * facelet, TYPE * NAME);               \
int facelet_set_ ## NAME(facelet_t * facelet, TYPE NAME);                       \
int facelet_unset_ ## NAME(facelet_t * facelet);

#define _(TYPE, NAME) FACELET_ACCESSORS_H(TYPE, NAME)
foreach_facelet_attr
#undef _

int facelet_get_face(const facelet_t * facelet, face_t ** pface);

int facelet_merge(facelet_t * facelet, facelet_t * facelet_to_merge);

facelet_status_t facelet_get_status(const facelet_t * facelet);
void facelet_set_status(facelet_t * facelet, facelet_status_t status);
void facelet_set_attr_clean(facelet_t * facelet);

void facelet_set_error(facelet_t * facelet, facelet_error_reason_t reason);
void facelet_unset_error(facelet_t * facelet);
bool facelet_get_error(const facelet_t * facelet);

void facelet_set_bj_done(facelet_t * facelet);
void facelet_unset_bj_done(facelet_t * facelet);
bool facelet_is_bj_done(const facelet_t * facelet);
void facelet_set_au_done(facelet_t * facelet);
bool facelet_is_au_done(const facelet_t * facelet);

facelet_event_t facelet_get_event(const facelet_t * facelet);
void facelet_set_event(facelet_t * facelet, facelet_event_t event);

int facelet_add_route(facelet_t * facelet, hicn_route_t * route);
int facelet_remove_route(facelet_t * facelet, hicn_route_t * route, hicn_route_t ** route_removed);
int facelet_clear_routes(facelet_t * facelet);
int facelet_get_route_array(const facelet_t * facelet, hicn_route_t *** route_array);

int facelet_snprintf(char * buf, size_t size, const facelet_t * facelet);

#define DUMP_FACELET(msg, facelet) do {                 \
    char buf[MAXSZ_FACELET];                            \
    facelet_snprintf(buf, MAXSZ_FACELET, facelet);      \
    DEBUG("%s : %s", msg, buf);                         \
} while(0)

int facelet_snprintf_json(char * buf, size_t size, const facelet_t * facelet, int indent);

#endif /* FACEMGR_FACELET_H */
