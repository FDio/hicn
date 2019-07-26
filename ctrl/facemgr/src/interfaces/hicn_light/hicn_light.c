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
 * \file interfaces/hicn_light/hicn_light.c
 * \brief hICN light interface
 */
#include <stdbool.h>
#include <stdlib.h> // arc4random [random, rand]
#include <stdio.h> // snprintf
#include <time.h> // time

#include <hicn/ctrl.h>

#include "../../facemgr.h"
#include "../../interface.h"
#include "../../util/ip_address.h"
#include "../../util/log.h"
#include "../../util/map.h"
#include "../../event.h"

#define DEFAULT_ROUTE_COST 0

typedef struct {
    hc_sock_t * s;
    bool busy;
} hl_data_t;

int hl_initialize(interface_t * interface, face_rules_t * rules, void ** pdata)
{
    hl_data_t * data = malloc(sizeof(hl_data_t));
    if (!data) {
        ERROR("[hicn_light] Out of memory!");
        goto ERR_MALLOC;
    }

    data->s = hc_sock_create();
    if (data->s <= 0) {
        ERROR("[hicn_light] Could not create control socket");
        goto ERR_SOCK;
    }

    if (hc_sock_connect(data->s) < 0) {
        ERROR("[hicn_light] Could not connect control socket");
        goto ERR_CONNECT;
    }

    data->busy = false;

    *pdata = data;

    return FACEMGR_SUCCESS;

ERR_CONNECT:
    hc_sock_free(data->s);
ERR_SOCK:
    free(data);
ERR_MALLOC:
    return FACEMGR_FAILURE;
}

int hl_finalize(interface_t * interface)
{
    //hc_data_t * data = interface->data;
    //hc_sock_close(data->s);
    return FACEMGR_SUCCESS;
}

int hl_on_event(interface_t * interface, const event_t * event)
{
    hc_face_t face;
    hc_route_t route;
    int rc;
    hl_data_t * data = (hl_data_t *)interface->data;

    /* XXX We need  a queue or a socket pool to process concurrent events */
    if (data->busy) {
        ERROR("[hicn_light] Busy !");
        return FACEMGR_FAILURE;
    }

    switch(event->type) {
        case EVENT_TYPE_CREATE:

            /* Create face */
            face.face = *event->face;
            rc = hc_face_create(data->s, &face);
            if (rc < 0) {
                ERROR("Failed to create face\n");
                goto ERR;
            }
            DEBUG("Created face id=%d\n", face.id);

#if 0
            /* Add default route v4 */
            route = (hc_route_t) {
                .face_id = face.id,
                .family = AF_INET,
                .remote_addr = IPV4_ANY,
                .len = 0,
                .cost = DEFAULT_ROUTE_COST,

            };
            if (hc_route_create(data->s, &route) < 0) {
                ERROR("Failed to create default hICN/IPv4 route");
                goto ERR;
            }
            INFO("Successfully created default hICN/IPv4 route.");
#endif

#if 0
            route = (hc_route_t) {
                .face_id = face.id,
                .family = AF_INET6,
                .remote_addr = IPV6_ANY,
                .len = 0,
                .cost = DEFAULT_ROUTE_COST,
            };
            if (hc_route_create(data->s, &route) < 0) {
                ERROR("Failed to create default hICN/IPv6 route");
                goto ERR;
            }
#endif

#if 1
            /* We add routes based on face tags */

            if (policy_tags_has(event->face->tags, POLICY_TAG_TRUSTED)) {
                route = (hc_route_t) {
                    .face_id = face.id,
                    .family = AF_INET6,
                    .len = 16,
                    .cost = DEFAULT_ROUTE_COST,
                };
                if (ip_address_pton("b001::", &route.remote_addr) < 0) {
                    ERROR("Failed to convert prefix");
                    goto ERR;
                }
                if (hc_route_create(data->s, &route) < 0) {
                    ERROR("Failed to create hICN/IPv6 route");
                    goto ERR;
                }

                route = (hc_route_t) {
                    .face_id = face.id,
                    .family = AF_INET6,
                    .len = 16,
                    .cost = DEFAULT_ROUTE_COST,
                };
                if (ip_address_pton("d001::", &route.remote_addr) < 0) {
                    ERROR("Failed to convert prefix");
                    goto ERR;
                }
                if (hc_route_create(data->s, &route) < 0) {
                    ERROR("Failed to create hICN/IPv6 route");
                    goto ERR;
                }

            } else {

                route = (hc_route_t) {
                    .face_id = face.id,
                    .family = AF_INET6,
                    .len = 16,
                    .cost = DEFAULT_ROUTE_COST,
                };
                if (ip_address_pton("c001::", &route.remote_addr) < 0) {
                    ERROR("Failed to convert prefix");
                    goto ERR;
                }
                if (hc_route_create(data->s, &route) < 0) {
                    ERROR("Failed to create hICN/IPv6 route");
                    goto ERR;
                }
            }
#endif

            break;

        case EVENT_TYPE_DELETE:
            /* Removing a face should also remove associated routes */
            /* Create face */
            face.face = *event->face;
            rc = hc_face_delete(data->s, &face);
            if (rc < 0) {
                ERROR("Failed to delete face\n");
                goto ERR;
            }
            INFO("Deleted face id=%d\n", face.id);
            break;

        default:
            ERROR("Unknown event %s\n", event_type_str[event->type]);
            /* Unsupported events */
            goto ERR;
    }

    return FACEMGR_SUCCESS;

ERR:
    return FACEMGR_FAILURE;
}

const interface_ops_t hicn_light_ops = {
    .type = "hicn_light",
    .is_singleton = false,
    .initialize = hl_initialize,
    .finalize = hl_finalize,
    .on_event = hl_on_event,
};
