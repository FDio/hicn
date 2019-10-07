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
#include <stdio.h> // snprintf
#include <time.h> // time

#include <hicn/ctrl.h>
#include <hicn/facemgr.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>

#include "../../facelet.h"
#include "../../interface.h"
#include "../../util/map.h"

#define DEFAULT_ROUTE_COST 0

typedef enum {
    HL_STATE_UNDEFINED,
    HL_STATE_FACES_SENT,
    HL_STATE_DONE,
} hl_state_t;

typedef struct {
    hc_sock_t * s;
    hl_state_t state;
} hl_data_t;

int hl_process_state(interface_t * interface)
{
    hl_data_t * data = (hl_data_t *)interface->data;

    hc_data_t * faces;
#if 0
    char buf[MAXSZ_FACE];
#endif

    switch(data->state)
    {
        case HL_STATE_UNDEFINED:
            if (hc_face_list(data->s, &faces) < 0) {
                /* Blocking call */
                printf("Could not retrieve face list\n");
                return -1;
            }
            foreach_face(f, faces) {
#if 0
                hc_face_snprintf(buf, MAXSZ_FACE, f);
                printf("Face: %s\n", buf);
#endif
                facelet_t * facelet = facelet_create_from_face(&f->face);
                facelet_set_event(facelet, FACELET_EVENT_GET);
                facelet_raise_event(facelet, interface);
            }
            break;

        case HL_STATE_FACES_SENT:
            break;

        default: /* HL_STATE_DONE never called */
            break;
    }

    return 0;
}

int hl_initialize(interface_t * interface, void * cfg)
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

    data->state = HL_STATE_UNDEFINED;

    interface->data = data;

    hl_process_state(interface);

    return 0;

ERR_CONNECT:
    hc_sock_free(data->s);
ERR_SOCK:
    free(data);
ERR_MALLOC:
    return -1;
}

int hl_finalize(interface_t * interface)
{
    //hc_data_t * data = interface->data;
    //hc_sock_close(data->s);
    return 0;
}

int hl_on_event(interface_t * interface, const facelet_t * facelet)
{
    hc_face_t hc_face;
    hc_route_t route;
    int rc;
    hl_data_t * data = (hl_data_t *)interface->data;

    face_t * face = NULL;
    if (facelet_get_face(facelet, &face) < 0)
        return -1;

    switch(facelet_get_event(facelet)) {

        case FACELET_EVENT_CREATE:

            /* Create face */
            hc_face.face = *face;
            rc = hc_face_create(data->s, &hc_face);
            if (rc < 0) {
                ERROR("Failed to create face\n");
                goto ERR;
            }
            INFO("Created face id=%d\n", hc_face.id);

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

            /* Adding default route */
            route = (hc_route_t) {
                .face_id = hc_face.id,
                .family = AF_INET6,
                .len = 0,
                .cost = DEFAULT_ROUTE_COST,
            };
            if (ip_address_pton("::", &route.remote_addr) < 0) {
                ERROR("Failed to convert prefix");
                goto ERR;
            }
            if (hc_route_create(data->s, &route) < 0) {
                ERROR("Failed to create hICN/IPv6 route");
                goto ERR;
            }

            break;

        case FACELET_EVENT_DELETE:
            /* Removing a face should also remove associated routes */
            /* Create face */
            hc_face.face = *face;
            rc = hc_face_delete(data->s, &hc_face);
            if (rc < 0) {
                ERROR("Failed to delete face\n");
                goto ERR;
            }
            INFO("Deleted face id=%d\n", hc_face.id);
            break;

        case FACELET_EVENT_UPDATE:
            /* Currently, only admin_state is supported */
            if (facelet_get_admin_state_status(facelet) == FACELET_ATTR_STATUS_DIRTY) {
                hc_face.face = *face;
                hc_face_t * face_found;
                rc = hc_face_get(data->s, &hc_face, &face_found);
                if (rc < 0) {
                    ERROR("Failed to find face\n");
                    goto ERR;
                }
                if (!face_found) {
                    ERROR("Face to update has not been found");
                    goto ERR;
                }
                char conn_id_or_name[NAME_LEN];
                snprintf(conn_id_or_name, NAME_LEN, "%d", face_found->id);
                free(face_found);
                printf("Face id = %d\n", face_found->id);

                face_state_t admin_state;
                if (facelet_get_admin_state(facelet, &admin_state) < 0) {
                    ERROR("Failed to retrieve facelet admin state");
                    goto ERR;
                }

                printf("Setting admin state");
                if (hc_connection_set_admin_state(data->s, conn_id_or_name, admin_state) < 0) {
                    ERROR("Failed to update admin state");
                    goto ERR;
                }
                INFO("Admin state updated");
            }
            break;

        default:
            ERROR("Unknown event %s\n", facelet_event_str[facelet_get_event(facelet)]);
            /* Unsupported events */
            goto ERR;
    }

    return 0;

ERR:
    return -1;
}

const interface_ops_t hicn_light_ops = {
    .type = "hicn_light",
    .initialize = hl_initialize,
    .finalize = hl_finalize,
    .on_event = hl_on_event,
};
