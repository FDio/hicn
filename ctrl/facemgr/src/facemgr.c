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
 * \file facemgr.c
 * \brief Implementation of Face manager library interface
 */

#include <stdio.h>

#include "common.h"
#include "event.h"
#include "facemgr.h"
#include "interface.h"
#include "util/log.h"

#ifdef __APPLE__
extern interface_ops_t network_framework_ops;
#endif
#ifdef __linux__
extern interface_ops_t netlink_ops;
#endif
#if 0
extern interface_ops_t dummy_ops;
#endif
extern interface_ops_t hicn_light_ops;

int
facemgr_initialize(facemgr_t * facemgr)
{
    int rc;

    rc = interface_map_initialize(&facemgr->interface_map);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_INTERFACE_MAP;

    rc = face_cache_initialize(&facemgr->face_cache);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_FACE_SET;

    rc = face_rules_initialize(&facemgr->rules);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_FACE_SET;

    return FACEMGR_SUCCESS;

ERR_FACE_SET:
    interface_map_finalize(&facemgr->interface_map);

ERR_INTERFACE_MAP:
    return FACEMGR_FAILURE;
}

int
facemgr_finalize(facemgr_t * facemgr)
{
    int rc;

    /* XXX Free all interfaces: pass free to map */
    rc = interface_map_finalize(&facemgr->interface_map);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR;

    rc = face_cache_finalize(&facemgr->face_cache);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR;

    rc = face_rules_finalize(&facemgr->rules);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR;

    return FACEMGR_SUCCESS;

ERR:
    return FACEMGR_FAILURE;
}

AUTOGENERATE_CREATE_FREE(facemgr);

int
facemgr_on_event(facemgr_t * facemgr, event_t * event)
{
    int rc;
    char face_s[MAXSZ_FACE];
    face_t * cached_face;

    if (!event->face) {
        printf("Event with empty face\n");
        return -1;
    }

    face_t face = *event->face;

    /* Complement unbound UDP faces */
    switch(face.type) {
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            switch (face.params.tunnel.family) {
                case AF_INET:
                    if ((ip_address_empty(&face.params.tunnel.remote_addr)) &&
                            (!ip_address_empty(&facemgr->overlay_v4_remote_addr)))
                        face.params.tunnel.remote_addr = facemgr->overlay_v4_remote_addr;
                    if ((face.params.tunnel.local_port == 0) && (facemgr->overlay_v4_local_port != 0))
                        face.params.tunnel.local_port = facemgr->overlay_v4_local_port;
                    if ((face.params.tunnel.remote_port == 0) && (facemgr->overlay_v4_remote_port != 0))
                        face.params.tunnel.remote_port = facemgr->overlay_v4_remote_port;
                    break;
                case AF_INET6:
                    if ((ip_address_empty(&face.params.tunnel.remote_addr)) &&
                            (!ip_address_empty(&facemgr->overlay_v6_remote_addr)))
                        face.params.tunnel.remote_addr = facemgr->overlay_v6_remote_addr;
                    if ((face.params.tunnel.local_port == 0) && (facemgr->overlay_v6_local_port != 0))
                        face.params.tunnel.local_port = facemgr->overlay_v6_local_port;
                    if ((face.params.tunnel.remote_port == 0) && (facemgr->overlay_v6_remote_port != 0))
                        face.params.tunnel.remote_port = facemgr->overlay_v6_remote_port;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    face_snprintf(face_s, MAXSZ_FACE, &face);

    /* TODO Here, we need to filter events based on our cache, and update the cache
     * based on our actions if they are successful */

    switch(event->type) {
        case EVENT_TYPE_CREATE:
            rc = face_cache_get(&facemgr->face_cache, &face, &cached_face);
            if (!FACEMGR_IS_ERROR(rc)) {
                DEBUG("Face found in cache");
                goto IGNORE_EVENT;
            }
            rc = face_cache_add(&facemgr->face_cache, &face);
            if (FACEMGR_IS_ERROR(rc))
                WARN("Failed to add face to cache");
            break;
        case EVENT_TYPE_DELETE:
            rc = face_cache_remove(&facemgr->face_cache, &face, &cached_face);
            if (FACEMGR_IS_ERROR(rc))
                WARN("Face not found in cache");
            break;
        case EVENT_TYPE_SET_UP:
        case EVENT_TYPE_SET_DOWN:
            /* TODO We need a return code to update the cache */
            break;
        default:
            printf("Not implemented!\n");
            break;
    }

    /* Process event */
    printf("[ FACE %s ] %s\n", event_type_str[event->type], face_s);
    /* Hardcoded hicn-light */
    rc = interface_on_event(facemgr->hl, event);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR;

IGNORE_EVENT:
    return FACEMGR_SUCCESS;

ERR:
    return FACEMGR_FAILURE;
}

#ifdef __linux__
void interface_callback(evutil_socket_t fd, short what, void * arg) {
    interface_t * interface = (interface_t *)arg;
    interface->ops->callback(interface);
}
#endif /* __linux__ */

int
facemgr_create_interface(facemgr_t * facemgr, const char * name, const char * type, interface_t ** interface)
{
    int fd, rc;

    INFO("Creating interface %s [%s]...\n", name, type);
    *interface = interface_create(name, type);
    if (!*interface) {
        ERROR("Error creating interface %s [%s]\n", name, type);
        return -1;
    }
    interface_set_callback(*interface, facemgr_on_event, facemgr);

    fd = interface_initialize(*interface, &facemgr->rules);
    if (fd < 0)
        return -2;
    if (fd != 0) {
#ifdef __linux__
        evutil_make_socket_nonblocking(fd);
        struct event * event = event_new(facemgr->loop, fd, EV_READ | EV_PERSIST, interface_callback, *interface);
        if (!event) {
            return -3;
        }

        if (event_add(event, NULL) < 0) {
            return -4;
        }
#else
        ERROR("Not implemented\n");
        return FACEMGR_FAILURE;
#endif /* __linux__ */
    }

    rc = interface_map_add(&facemgr->interface_map, (*interface)->name, *interface);
    if (FACEMGR_IS_ERROR(rc))
        return -5;

    DEBUG("Interface created successfully.\n");
    return FACEMGR_SUCCESS;
}

int
facemgr_bootstrap(facemgr_t * facemgr)
{
    int rc;

    DEBUG("Registering interfaces...");
    rc = interface_register(&hicn_light_ops);
    if (FACEMGR_IS_ERROR(rc)) {
        ERROR("Could not register interfaces");
        goto ERR_REGISTER;
    }

#ifdef __APPLE__
    rc = interface_register(&network_framework_ops);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_REGISTER;
#endif /* __APPLE__ */

#ifdef __linux__
    rc = interface_register(&netlink_ops);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_REGISTER;
#endif /* __linux__ */

#if 0
    rc = interface_register(&dummy_ops);
    if (FACEMGR_IS_ERROR(rc))
        goto ERR_REGISTER;
#endif

    rc = facemgr_create_interface(facemgr, "hl", "hicn_light", &facemgr->hl);
    if (rc < 0) {
        ERROR("Error creating 'hICN forwarder (hicn-light)' interface\n");
        goto ERR_HL_CREATE;
    }

#ifdef __APPLE__
    rc = facemgr_create_interface(facemgr, "nf", "network_framework", &facemgr->nf);
    if (rc < 0) {
        ERROR("Error creating 'Apple Network Framework' interface\n");
        goto ERR_NF_CREATE;
    }
#endif /* __APPLE__ */

#ifdef __linux__
    rc = facemgr_create_interface(facemgr, "nl", "netlink", &facemgr->nl);
    if (rc < 0) {
        ERROR("Error creating 'Netlink' interface\n");
        goto ERR_NF_CREATE;
    }
#endif /* __linux__ */

#if 0
    rc = facemgr_create_interface(facemgr, "dummy", "dummy", &facemgr->dummy);
    if (rc < 0) {
        ERROR("Error creating 'Dummy' interface\n");
        goto ERR_NF_CREATE;
    }
#endif

    DEBUG("Facemgr successfully initialized...");

    return FACEMGR_SUCCESS;

ERR_NF_CREATE:
    interface_free(facemgr->hl);
ERR_HL_CREATE:
    //interface_map_remove(&facemgr->interface_map, data->nf->name);
ERR_REGISTER:
    return FACEMGR_FAILURE;
}
