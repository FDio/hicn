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
#include <assert.h>
#include <stdbool.h>
#include <stdio.h> // snprintf
#include <time.h> // time

#include <hicn/ctrl.h>
#include <hicn/facemgr.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>

#include "../../interface.h"
#include "../../util/map.h"

#define DEFAULT_ROUTE_COST 0

#define INTERVAL_MS 1000

typedef enum {
    HL_STATE_UNDEFINED,
    HL_STATE_CONNECTING,
    HL_STATE_FACES_SENT,
    HL_STATE_DONE,
} hl_state_t;

typedef struct {
    hc_sock_t * s; /* NULL means no active socket */
    hl_state_t state;

    /* Timer used for forwarder reconnection */
    int reconnect_timer_fd; /* 0 means no active timer */

    /* Timer used to periodically poll the forwarder face and routing tables */
    int poll_timer_fd;
} hl_data_t;

/* Forward declarations */
int hl_timeout(interface_t * interface, int fd, void * unused);

int hl_process_state(interface_t * interface)
{
    hl_data_t * data = (hl_data_t *)interface->data;

#if 0
    char buf[MAXSZ_FACE];
#endif

    switch(data->state)
    {
        case HL_STATE_UNDEFINED: // FIXME
        case HL_STATE_CONNECTING: // FIXME
            if (hc_face_list_async(data->s) < 0) {
                /* Blocking call */
                printf("Could not retrieve face list\n");
                return -1;
            }
            break;

        case HL_STATE_FACES_SENT:
            break;

        default: /* HL_STATE_DONE never called */
            break;
    }

    return 0;
}


int
hl_after_connect(interface_t * interface)
{
    hl_data_t * data = interface->data;

    /* File descriptor for control socket operations */
    if (interface_register_fd(interface, hc_sock_get_fd(data->s), NULL) < 0) {
        ERROR("[hc_connect] Error registering fd");
        goto ERR_FD;
    }

    data->state = HL_STATE_UNDEFINED;

    hl_process_state(interface);

    return 0;

    //interface_unregister_fd(interface, hc_sock_get_fd(data->s));
ERR_FD:
    return -1;
}

int _hl_connect(interface_t * interface);

int
hl_connect_timeout(interface_t * interface, int fd, void * unused)
{
    int rc = _hl_connect(interface);
    if (rc < 0) {
        DEBUG("[hl_initialize] Error during connection reattempt; next attempt in %ds", INTERVAL_MS / 1000);
        return -1;
    }

    if (interface_unregister_timer(interface, fd) < 0) {
        ERROR("[hl_connect_timeout] Could not cancel timer after successful connect");
    }

    /* Connect success */
    return hl_after_connect(interface);
}


int
_hl_connect(interface_t * interface)
{
    hl_data_t * data = interface->data;
    assert(!data->s);

    data->s = hc_sock_create();
    if (data->s <= 0) {
        ERROR("[hc_connect] Could not create control socket");
        goto ERR_SOCK;
    }

    if (hc_sock_connect(data->s) < 0) {
        DEBUG("[hc_connect] Could not connect control socket");
        goto ERR_CONNECT;
    }

    return 0;

ERR_CONNECT:
    hc_sock_free(data->s);
    data->s = NULL;
ERR_SOCK:
    return -1;

}

int hl_disconnect(interface_t * interface)
{
    hl_data_t * data = (hl_data_t *) interface->data;
    if (data->reconnect_timer_fd > 0)
        interface_unregister_timer(interface, data->reconnect_timer_fd);

    if (data->s) {
        interface_unregister_fd(interface, hc_sock_get_fd(data->s));
        hc_sock_free(data->s);
    }

    return 0;
}

int
hl_connect(interface_t * interface)
{
    hl_data_t * data = interface->data;

    if (_hl_connect(interface) >= 0)
        return hl_after_connect(interface);

    /* Timer for managing the connection to the forwarder */
    DEBUG("Connection to forwarder failed... next retry in %ds", INTERVAL_MS / 1000);
    data->reconnect_timer_fd = interface_register_timer(interface, INTERVAL_MS, hl_connect_timeout, NULL);
    if (data->reconnect_timer_fd < 0) {
        ERROR("[hc_connect] Could not initialize reattempt timer");
        return -1;
    }

    return 0;
}

int
hl_initialize(interface_t * interface, void * cfg)
{
    hl_data_t * data = malloc(sizeof(hl_data_t));
    if (!data) {
        ERROR("[hicn_light] Out of memory!");
        goto ERR_MALLOC;
    }

    data->s = NULL;
    data->reconnect_timer_fd = 0;

    interface->data = data;

    if (hl_connect(interface) < 0) {
        ERROR("[hl_initialize] Error during connection to forwarder");
        goto ERR_CONNECT;
    }

    return 0;

ERR_CONNECT:
    free(data);
ERR_MALLOC:
    return -1;
}

int hl_finalize(interface_t * interface)
{
    hl_data_t * data = (hl_data_t *) interface->data;

    hl_disconnect(interface);

    free(data);

    return 0;
}

int hl_on_event(interface_t * interface, const facelet_t * facelet)
{
    hc_face_t hc_face;
    hc_route_t route;
    int rc;
    int ret = 0;
    hl_data_t * data = (hl_data_t *)interface->data;

    face_t * face = NULL;

    /* NOTE
     *  - One example where this fails (and it is normal) is when we delete a
     *  face that was not completely created, because for instance bonjour did
     *  not give any data
     */
    if (facelet_get_face(facelet, &face) < 0) {
        ERROR("Could not retrieve face from facelet");
        goto ERR_FACE;
    }

    if (!data->s) {
        /* We are not connected to the forwarder */
        goto ERR;
    }

    switch(facelet_get_event(facelet)) {

        case FACELET_EVENT_CREATE:

            /* Create face */
            {
            char buf[MAXSZ_FACELET];
            facelet_snprintf(buf, MAXSZ_FACELET, facelet);
            printf("Create face %s\n", buf);
            }
            hc_face.face = *face;
            rc = hc_face_create(data->s, &hc_face);
            if (rc < 0) {
                ERROR("Failed to create face\n");
                goto ERR;
            }
            INFO("Created face id=%d", hc_face.id);

            hicn_route_t ** route_array;
            int n = facelet_get_route_array(facelet, &route_array);
            if (n < 0) {
                ERROR("Failed to create default hICN/IPv4 route");
                goto ERR;
            }
            if (n == 0) {
                /* Adding default routes */
                route = (hc_route_t) {
                    .face_id = hc_face.id,
                    .family = AF_INET,
                    .remote_addr = IPV4_ANY,
                    .len = 0,
                    .cost = DEFAULT_ROUTE_COST,

                };
                if (hc_route_create(data->s, &route) < 0) {
                    ERROR("Failed to create default hICN/IPv4 route");
                    ret = -1;
                }

                route = (hc_route_t) {
                    .face_id = hc_face.id,
                    .family = AF_INET6,
                    .remote_addr = IPV6_ANY,
                    .len = 0,
                    .cost = DEFAULT_ROUTE_COST,
                };
                if (hc_route_create(data->s, &route) < 0) {
                    ERROR("Failed to create default hICN/IPv6 route");
                    ret = -1;
                }

                INFO("Successfully created default route(s).");
            } else {
                for (unsigned i = 0; i < n; i++) {
                    hicn_route_t * hicn_route = route_array[i];
                    ip_prefix_t prefix;
                    int cost;
                    if (hicn_route_get_prefix(hicn_route, &prefix) < 0) {
                        ERROR("Failed to get route prefix");
                        ret = -1;
                        continue;
                    }
                    if (hicn_route_get_cost(hicn_route, &cost) < 0) {
                        ERROR("Failed to get route cost");
                        ret = -1;
                        continue;
                    }
                    route = (hc_route_t) {
                        .face_id = hc_face.id,
                        .family = prefix.family,
                        .remote_addr = prefix.address,
                        .len = prefix.len,
                        .cost = cost,
                    };
                    if (hc_route_create(data->s, &route) < 0) {
                        ERROR("Failed to create static route route");
                        ret = -1;
                        continue;
                    }
                }

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
                char conn_id_or_name[SYMBOLIC_NAME_LEN];
                snprintf(conn_id_or_name, SYMBOLIC_NAME_LEN, "%d", face_found->id);
                free(face_found);

                face_state_t admin_state;
                if (facelet_get_admin_state(facelet, &admin_state) < 0) {
                    ERROR("Failed to retrieve facelet admin state");
                    goto ERR;
                }

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

    face_free(face);
    return ret;

ERR:
    face_free(face);
ERR_FACE:
    return -1;
}

int hl_callback(interface_t * interface, int fd, void * unused)
{
    hl_data_t * data = (hl_data_t*)interface->data;

    hc_data_t * faces;
    if (hc_sock_callback(data->s, &faces) < 0){
        DEBUG("Closing socket... reconnecting...");
        if (interface_unregister_fd(interface, hc_sock_get_fd(data->s)) < 0) {
            ERROR("[hl_initialize] Error registering fd");
        }
        hc_sock_free(data->s);
        data->s = NULL;
        hl_connect(interface);
        return 0;
    }

    if (faces->complete) {
        foreach_face(f, faces) {
#if 0
            char buf[MAXSZ_FACE];
            hc_face_snprintf(buf, MAXSZ_FACE, f);
            printf("Face: %s\n", buf);
#endif
            facelet_t * facelet = facelet_create_from_face(&f->face);
            facelet_set_event(facelet, FACELET_EVENT_GET);
            interface_raise_event(interface, facelet);
        }
    }
    hc_data_free(faces);

    /* XXX how do we know what object we get back */

    /* We have a queue of pending data elements per active query */

    return 0;
}

const interface_ops_t hicn_light_ops = {
    .type = "hicn_light",
    .initialize = hl_initialize,
    .finalize = hl_finalize,
    .on_event = hl_on_event,
    .callback = hl_callback,
};
