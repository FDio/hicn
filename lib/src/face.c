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

#include <hicn/face.h>
#include <hicn/util/token.h>

#define member_size(type, member) sizeof(((type *)0)->member)


/* Netdevice */

const char * _netdevice_type_str[] = {
#define _(x) [NETDEVICE_TYPE_ ## x] = STRINGIZE(x),
foreach_netdevice_type
#undef _
};

netdevice_t *
netdevice_create_from_index(u32 index)
{
    netdevice_t * netdevice = malloc(sizeof(netdevice_t));
    if (!netdevice)
        goto ERR_MALLOC;

    int rc = netdevice_set_index(netdevice, index);
    if (rc < 0)
        goto ERR_INIT;

    return netdevice;

ERR_INIT:
    free(netdevice);
ERR_MALLOC:
    return NULL;
}

netdevice_t *
netdevice_create_from_name(const char * name)
{
    netdevice_t * netdevice = malloc(sizeof(netdevice_t));
    if (!netdevice)
        goto ERR_MALLOC;

    int rc = netdevice_set_name(netdevice, name);
    if (rc < 0)
        goto ERR_INIT;

    return netdevice;

ERR_INIT:
    free(netdevice);
ERR_MALLOC:
    return NULL;
}

/**
 * \brief Update the index of the netdevice based on the name
 */
int
netdevice_update_index(netdevice_t * netdevice)
{
    netdevice->index = if_nametoindex(netdevice->name);
    if (netdevice->index == 0)
        return -1;
    return 0;
}

int
netdevice_update_name(netdevice_t * netdevice)
{
    if (!if_indextoname(netdevice->index, netdevice->name))
        return -1;
    return 0;
}

void
netdevice_free(netdevice_t * netdevice)
{
    free(netdevice);
}

int
netdevice_get_index(const netdevice_t * netdevice, u32 * index)
{
    if (netdevice->index == 0)
        return -1;
    *index = netdevice->index;
    return 0;
}

int
netdevice_set_index(netdevice_t * netdevice, u32 index)
{
    netdevice->index = index;
    return netdevice_update_name(netdevice);
}

int
netdevice_get_name(const netdevice_t * netdevice, const char ** name)
{
    if (netdevice->name[0] == '\0')
        return -1;
    *name = netdevice->name;
    return 0;
}

int
netdevice_set_name(netdevice_t * netdevice, const char * name)
{
    memset(netdevice->name, 0, sizeof(netdevice->name));
    int rc = snprintf(netdevice->name, IFNAMSIZ, "%s", name);
    if (rc < 0)
        return -1;
    if (rc >= IFNAMSIZ)
        return -2; /* truncated */
    return netdevice_update_index(netdevice);
}

int
netdevice_cmp(const netdevice_t * nd1, const netdevice_t * nd2)
{
    return (nd1->index - nd2->index);
}


/* Face state */

const char * _face_state_str[] = {
#define _(x) [FACE_STATE_ ## x] = STRINGIZE(x),
foreach_face_state
#undef _
};


/* Face type */

const char * _face_type_str[] = {
#define _(x) [FACE_TYPE_ ## x] = STRINGIZE(x),
foreach_face_type
#undef _
};


/* Face */

int
face_initialize(face_t * face)
{
    memset(face, 0, sizeof(face_t));
    return 1;
}

int
face_initialize_udp(face_t * face, const char * interface_name, const
        ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port,
        int family)
{
    if (!local_addr)
        return -1;

    *face = (face_t) {
        .type = FACE_TYPE_UDP,
        .family = family,
        .local_addr = *local_addr,
        .local_port = local_port,
        .remote_addr = remote_addr ? *remote_addr : IP_ADDRESS_EMPTY,
        .remote_port = remote_port,
    };

    snprintf(face->netdevice.name, IFNAMSIZ, "%s", interface_name);

    return 1;
}

int
face_initialize_udp_sa(face_t * face, const char * interface_name,
        const struct sockaddr * local_addr,
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
                .family = AF_INET,
                .local_addr.v4.as_inaddr = lsai->sin_addr,
                .local_port = lsai ? ntohs(lsai->sin_port) : 0,
                .remote_addr = IP_ADDRESS_EMPTY,
                .remote_port = rsai ? ntohs(rsai->sin_port) : 0,
            };
            if (rsai)
                face->remote_addr.v4.as_inaddr = rsai->sin_addr;
            }
            break;
        case AF_INET6:
            {
            struct sockaddr_in6 *lsai = (struct sockaddr_in6 *)local_addr;
            struct sockaddr_in6 *rsai = (struct sockaddr_in6 *)remote_addr;
            *face = (face_t) {
                .type = FACE_TYPE_UDP,
                .family = AF_INET6,
                .local_addr.v6.as_in6addr = lsai->sin6_addr,
                .local_port = lsai ? ntohs(lsai->sin6_port) : 0,
                .remote_addr = IP_ADDRESS_EMPTY,
                .remote_port = rsai ? ntohs(rsai->sin6_port) : 0,
            };
            if (rsai)
                face->remote_addr.v6.as_in6addr = rsai->sin6_addr;
            }
            break;
        default:
            return -1;
    }

    snprintf(face->netdevice.name, IFNAMSIZ, "%s", interface_name);

    return 1;
}

face_t * face_create()
{
    face_t * face = calloc(1, sizeof(face_t));
    return face;
}

face_t * face_create_udp(const char * interface_name,
        const ip_address_t * local_addr, u16 local_port,
        const ip_address_t * remote_addr, u16 remote_port, int family)
{
    face_t * face = face_create();
    if (face_initialize_udp(face, interface_name, local_addr, local_port, remote_addr, remote_port, family) < 0)
        goto ERR_INIT;
    return face;

ERR_INIT:
    free(face);
    return NULL;
}

face_t * face_create_udp_sa(const char * interface_name,
        const struct sockaddr * local_addr,
        const struct sockaddr * remote_addr)
{
    face_t * face = face_create();
    if (face_initialize_udp_sa(face, interface_name, local_addr, remote_addr) < 0)
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

    int ret = f1->type - f2->type;
    if (ret != 0)
        return ret;

    ret = f1->family - f2->family;
    if (ret != 0)
        return ret;

    /*
     * FIXME As hicn-light API might not return the netdevice, we can discard the
     * comparison when one of the two is not set for now...
     */
    if ((f1->netdevice.index != 0) && (f2->netdevice.index != 0)) {
        ret = netdevice_cmp(&f1->netdevice, &f2->netdevice);
        if (ret != 0)
            return ret;
    }

    switch(f1->type) {
        case FACE_TYPE_HICN:
            ret = ip_address_cmp(&f1->local_addr, &f2->local_addr, f1->family);
            if (ret != 0)
                return ret;

            ret = ip_address_cmp(&f1->remote_addr, &f2->remote_addr, f1->family);
            if (ret != 0)
                return ret;

            break;

        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            ret = ip_address_cmp(&f1->local_addr, &f2->local_addr, f1->family);
            if (ret != 0)
                return ret;

            ret = f1->local_port - f2->local_port;
            if (ret != 0)
                return ret;

            ret = ip_address_cmp(&f1->remote_addr, &f2->remote_addr, f1->family);
            if (ret != 0)
                return ret;

            ret = f1->remote_port - f2->remote_port;
            if (ret != 0)
                return ret;

            break;
        default:
            break;
    }

    return 0;
}

/* /!\ Please update constants in header file upon changes */
size_t
face_snprintf(char * s, size_t size, const face_t * face)
{
    switch(face->type) {
        case FACE_TYPE_HICN:
        {
            char local[MAXSZ_IP_ADDRESS];
            char remote[MAXSZ_IP_ADDRESS];
            char tags[MAXSZ_POLICY_TAGS];

            ip_address_snprintf(local, MAXSZ_IP_ADDRESS,
                    &face->local_addr,
                    face->family);
            ip_address_snprintf(remote, MAXSZ_IP_ADDRESS,
                    &face->remote_addr,
                    face->family);
            policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->tags);
            return snprintf(s, size, "%s [%s -> %s] [%s]",
                    face_type_str(face->type),
                    local,
                    remote,
                    tags);
        }
        case FACE_TYPE_UNDEFINED:
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
        {
            char local[MAXSZ_IP_ADDRESS];
            char remote[MAXSZ_IP_ADDRESS];
            char tags[MAXSZ_POLICY_TAGS];

            ip_address_snprintf(local, MAXSZ_IP_ADDRESS,
                    &face->local_addr,
                    face->family);
            ip_address_snprintf(remote, MAXSZ_IP_ADDRESS,
                    &face->remote_addr,
                    face->family);
            policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->tags);

            return snprintf(s, size, "%s [%s:%d -> %s:%d] [%s]",
                    face_type_str(face->type),
                    local,
                    face->local_port,
                    remote,
                    face->remote_port,
                    tags);
        }
        default:
            return -1;
    }

}

policy_tags_t face_get_tags(const face_t * face)
{
    return face->tags;
}

int
face_set_tags(face_t * face, policy_tags_t tags)
{
    face->tags = tags;
    return 1;
}
