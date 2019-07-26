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
 * \file face.c
 * \brief Implementation of face abstraction
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "face.h"
#include "util/hash.h"
#include "util/token.h"

#define member_size(type, member) sizeof(((type *)0)->member)


/* Netdevice */

const char * netdevice_type_str[] = {
#define _(x) [NETDEVICE_TYPE_ ## x] = STRINGIZE(x),
foreach_netdevice_type
#undef _
};


/* Face state */

const char * face_state_str[] = {
#define _(x) [FACE_STATE_ ## x] = STRINGIZE(x),
foreach_face_state
#undef _
};


/* Face type */

const char * face_type_str[] = {
#define _(x) [FACE_TYPE_ ## x] = STRINGIZE(x),
foreach_face_type
#undef _
};


/* Face */

int
face_initialize(face_t * face)
{
    bzero(face, sizeof(face_t)); /* 0'ed for hash */
    return 1;
}

int
face_initialize_udp(face_t * face, const ip_address_t * local_addr,
        u16 local_port, const ip_address_t * remote_addr, u16 remote_port,
        int family)
{
    if (!local_addr)
        return -1;

    *face = (face_t) {
        .type = FACE_TYPE_UDP,
        .params.tunnel = {
            .family = family,
            .local_addr = *local_addr,
            .local_port = local_port,
            .remote_addr = remote_addr ? *remote_addr : IP_ADDRESS_EMPTY,
            .remote_port = remote_port,
        },
    };
    return 1;
}

int
face_initialize_udp_sa(face_t * face, const struct sockaddr * local_addr,
        const struct sockaddr * remote_addr)
{
    if (!local_addr)
        return -1;

    if (remote_addr && (local_addr->sa_family != remote_addr->sa_family))
        return -1;

    switch (local_addr->sa_family) {
        case AF_INET:
            {
            struct sockaddr_in *lsai = (struct sockaddr_in *)local_addr;
            struct sockaddr_in *rsai = (struct sockaddr_in *)remote_addr;
            *face = (face_t) {
                .type = FACE_TYPE_UDP,
                .params.tunnel = {
                    .family = AF_INET,
                    .local_addr.v4.as_inaddr = lsai->sin_addr,
                    .local_port = lsai ? ntohs(lsai->sin_port) : 0,
                    .remote_addr = IP_ADDRESS_EMPTY,
                    .remote_port = rsai ? ntohs(rsai->sin_port) : 0,
                },
            };
            if (rsai)
                face->params.tunnel.remote_addr.v4.as_inaddr = rsai->sin_addr;
            }
            break;
        case AF_INET6:
            {
            struct sockaddr_in6 *lsai = (struct sockaddr_in6 *)local_addr;
            struct sockaddr_in6 *rsai = (struct sockaddr_in6 *)remote_addr;
            *face = (face_t) {
                .type = FACE_TYPE_UDP,
                .params.tunnel = {
                    .family = AF_INET6,
                    .local_addr.v6.as_in6addr = lsai->sin6_addr,
                    .local_port = lsai ? ntohs(lsai->sin6_port) : 0,
                    .remote_addr = IP_ADDRESS_EMPTY,
                    .remote_port = rsai ? ntohs(rsai->sin6_port) : 0,
                },
            };
            if (rsai)
                face->params.tunnel.remote_addr.v6.as_in6addr = rsai->sin6_addr;
            }
            break;
        default:
            return -1;
    }
    return 1;
}

face_t * face_create()
{
    face_t * face = calloc(1, sizeof(face_t)); /* 0'ed for hash */
    return face;
}

face_t * face_create_udp(const ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port, int family)
{
    face_t * face = face_create();
    if (face_initialize_udp(face, local_addr, local_port, remote_addr, remote_port, family) < 0)
        goto ERR_INIT;
    return face;

ERR_INIT:
    free(face);
    return NULL;
}

face_t * face_create_udp_sa(const struct sockaddr * local_addr,
        const struct sockaddr * remote_addr)
{
    face_t * face = face_create();
    if (face_initialize_udp_sa(face, local_addr, remote_addr) < 0)
        goto ERR_INIT;
    return face;

ERR_INIT:
    free(face);
    return NULL;
}

void face_free(face_t * face)
{
    free(face);
}

#define face_param_cmp(f1, f2, face_param_type)            \
    memcmp(&f1->type, &f2->type,  \
            member_size(face_params_t, face_param_type));

/**
 * \brief Compare two faces
 * \param [in] f1 - First face
 * \param [in] f2 - Second face
 * \return whether faces are equal, ie both their types are parameters are
 * equal.
 *
 * NOTE: this function implements a partial order.
 */
int
face_cmp(const face_t * f1, const face_t * f2)
{
    if (f1->type != f2->type)
        return false;

    switch(f1->type) {
        case FACE_TYPE_HICN:
            return face_param_cmp(f1, f2, hicn);
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            return face_param_cmp(f1, f2, tunnel);
        default:
            return false;
    }
}

hash_t
face_hash(const face_t * face)
{
    /* Assuming the unused part of the struct is set to zero */
    return hash_struct(face);
}

/* /!\ Please update constants in header file upon changes */
size_t
face_snprintf(char * s, size_t size, const face_t * face)
{
    switch(face->type) {
        case FACE_TYPE_HICN:
            return 0; // XXX Not implemented
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            {
                char local[MAXSZ_IP_ADDRESS];
                char remote[MAXSZ_IP_ADDRESS];
                char tags[MAXSZ_POLICY_TAGS];

                ip_address_snprintf(local, MAXSZ_IP_ADDRESS,
                        &face->params.tunnel.local_addr,
                        face->params.tunnel.family);
                ip_address_snprintf(remote, MAXSZ_IP_ADDRESS,
                        &face->params.tunnel.remote_addr,
                        face->params.tunnel.family);
                policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->tags);

                return snprintf(s, size, "%s [%s:%d -> %s:%d] [%s]",
                        face_type_str[face->type],
                        local,
                        face->params.tunnel.local_port,
                        remote,
                        face->params.tunnel.remote_port,
                        tags);
            }
            break;
        default:
            return 0;
    }

}

int
face_set_tags(face_t * face, policy_tags_t tags)
{
    face->tags = tags;
    return 1;
}
