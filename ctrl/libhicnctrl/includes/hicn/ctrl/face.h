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
 * \file face.h
 * \brief Face abstraction
 */
#ifndef HICN_FACE_H
#define HICN_FACE_H

#ifndef SPACES
#define SPACES(x) x
#endif
#ifndef SPACE
#define SPACE 1
#endif
#ifndef NULLTERM
#define NULLTERM 1
#endif

#ifndef _HICNTRL_NO_DEF_IPADDR
#include "util/ip_address.h"
#endif /* _HICNTRL_NO_DEF_IPADDR */
#include "util/policy.h"
#include "util/types.h"


/* Netdevice type */

#include <net/if.h> // IFNAMSIZ

#define foreach_netdevice_type  \
    _(UNDEFINED)                \
    _(WIRED)                    \
    _(WIFI)                     \
    _(CELLULAR)                 \
    _(VPN)                      \
    _(N)

#define MAXSZ_NETDEVICE_TYPE_ 9
#define MAXSZ_NETDEVICE_TYPE MAXSZ_NETDEVICE_TYPE_ + NULLTERM

typedef enum {
#define _(x) NETDEVICE_TYPE_ ## x,
foreach_netdevice_type
#undef _
} netdevice_type_t;

extern const char * netdevice_type_str[];


/* Netdevice */

typedef struct {
    u32 index;
    char name[IFNAMSIZ];
} netdevice_t;

#define NETDEVICE_UNDEFINED_INDEX 0

/* Face state */

#define foreach_face_state      \
    _(UNDEFINED)                \
    _(PENDING_UP)               \
    _(UP)                       \
    _(PENDING_DOWN)             \
    _(DOWN)                     \
    _(ERROR)                    \
    _(N)

#define MAXSZ_FACE_STATE_ 12
#define MAXSZ_FACE_STATE MAXSZ_FACE_STATE_ + 1

typedef enum {
#define _(x) FACE_STATE_ ## x,
foreach_face_state
#undef _
} face_state_t;

extern const char * face_state_str[];


/* Face type */

#define foreach_face_type       \
    _(UNDEFINED)                \
    _(HICN)                     \
    _(HICN_LISTENER)            \
    _(TCP)                      \
    _(TCP_LISTENER)             \
    _(UDP)                      \
    _(UDP_LISTENER)             \
    _(N)

#define MAXSZ_FACE_TYPE_ 13
#define MAXSZ_FACE_TYPE MAXSZ_FACE_TYPE_  + 1

typedef enum {
#define _(x) FACE_TYPE_ ## x,
foreach_face_type
#undef _
} face_type_t;

extern const char * face_type_str[];

#define MAXSZ_FACE_ MAXSZ_FACE_TYPE_ + 2 * MAXSZ_IP_ADDRESS + 2 * MAXSZ_PORT + 9
#define MAXSZ_FACE MAXSZ_FACE_ + 1

/* Face */

typedef union {
    int family; /* To access family independently of face type */
    struct {
        int family;
        netdevice_t netdevice;
        ip_address_t local_addr;
        ip_address_t remote_addr;
    } hicn;
    struct {
        int family;
        ip_address_t local_addr;
        u16 local_port;
        ip_address_t remote_addr;
        u16 remote_port;
    } tunnel;
} face_params_t;

typedef struct {
    face_type_t type;
    face_params_t params;
    face_state_t admin_state;
    face_state_t state;
#ifdef WITH_POLICY
    policy_tags_t tags; /**< \see policy_tag_t */
#endif /* WITH_POLICY */
} face_t;

int face_initialize(face_t * face);
int face_initialize_udp(face_t * face, const ip_address_t * local_addr,
        u16 local_port, const ip_address_t * remote_addr, u16 remote_port,
        int family);
int face_initialize_udp_sa(face_t * face,
        const struct sockaddr * local_addr, const struct sockaddr * remote_addr);

face_t * face_create();
face_t * face_create_udp(const ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port, int family);
face_t * face_create_udp_sa(const struct sockaddr * local_addr,
        const struct sockaddr * remote_addr);

int face_finalize(face_t * face);

void face_free(face_t * face);

typedef int (*face_cmp_t)(const face_t * f1, const face_t * f2);

int face_cmp(const face_t * f1, const face_t * f2);
hash_t face_hash(const face_t * face);

size_t
face_snprintf(char * s, size_t size, const face_t * face);

int face_set_tags(face_t * face, policy_tags_t tags);

#endif /* HICN_FACE_H */

