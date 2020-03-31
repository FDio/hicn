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

#include <hicn/policy.h>

#include <hicn/util/ip_address.h>

/* Netdevice type */

#include <net/if.h> // IFNAMSIZ

#define foreach_netdevice_type  \
    _(UNDEFINED)                \
    _(LOOPBACK)                 \
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

/**
 * \brief Netdevice type
 *
 * NOTE
 *  - This struct cannot be made opaque as it is currently part of face_t
 *  - We recommand using the API as to keep redundant attributes consistent
 */
typedef struct {
    u32 index;
    char name[IFNAMSIZ];
} netdevice_t;

#define NETDEVICE_EMPTY (netdevice_t) { \
    .index = 0,                         \
    .name = {0},                        \
}

netdevice_t * netdevice_create_from_index(u32 index);
netdevice_t * netdevice_create_from_name(const char * name);
#define netdevice_initialize_from_index netdevice_set_index
#define netdevice_initialize_from_name netdevice_set_name
void netdevice_free(netdevice_t * netdevice);
int netdevice_get_index(const netdevice_t * netdevice, u32 * index);
int netdevice_set_index(netdevice_t * netdevice, u32 index);
int netdevice_get_name(const netdevice_t * netdevice, const char ** name);
int netdevice_set_name(netdevice_t * netdevice, const char * name);
int netdevice_update_index(netdevice_t * netdevice);
int netdevice_update_name(netdevice_t * netdevice);
int netdevice_cmp(const netdevice_t * nd1, const netdevice_t * nd2);

#define NETDEVICE_UNDEFINED_INDEX 0

/* Face state */

#define foreach_face_state      \
    _(UNDEFINED)                \
    _(DOWN)                     \
    _(UP)                       \
    _(N)


#define MAXSZ_FACE_STATE_ 9
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

#ifdef WITH_POLICY
#define MAXSZ_FACE_ MAXSZ_FACE_TYPE_ + 2 * MAXSZ_URL_ + 2 * MAXSZ_FACE_STATE_ + MAXSZ_POLICY_TAGS_ + 7
#else
#define MAXSZ_FACE_ MAXSZ_FACE_TYPE_ + 2 * MAXSZ_URL_ + 2 * MAXSZ_FACE_STATE_ + 4
#endif /* WITH_POLICY */
#define MAXSZ_FACE MAXSZ_FACE_ + 1

/* Face */

typedef u32 face_id_t;

typedef struct {
    face_type_t type;
    face_state_t admin_state;
    face_state_t state;
#ifdef WITH_POLICY
    uint32_t priority;
    policy_tags_t tags; /**< \see policy_tag_t */
#endif /* WITH_POLICY */

    /*
     * Depending on the face type, some of the following fields will be unused
     */
    netdevice_t netdevice;
    int family; /* To access family independently of face type */
    ip_address_t local_addr;
    ip_address_t remote_addr;
    u16 local_port;
    u16 remote_port;
} face_t;

int face_initialize(face_t * face);
int face_initialize_udp(face_t * face, const char * interface_name,
        const ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port,
        int family);
int face_initialize_udp_sa(face_t * face,
        const char * interface_name,
        const struct sockaddr * local_addr, const struct sockaddr * remote_addr);

face_t * face_create();
face_t * face_create_udp(const char * interface_name,
        const ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port, int family);
face_t * face_create_udp_sa(const char * interface_name,
        const struct sockaddr * local_addr,
        const struct sockaddr * remote_addr);

int face_finalize(face_t * face);

void face_free(face_t * face);

typedef int (*face_cmp_t)(const face_t * f1, const face_t * f2);

int face_cmp(const face_t * f1, const face_t * f2);

size_t
face_snprintf(char * s, size_t size, const face_t * face);

policy_tags_t face_get_tags(const face_t * face);
int face_set_tags(face_t * face, policy_tags_t tags);

#endif /* HICN_FACE_H */

