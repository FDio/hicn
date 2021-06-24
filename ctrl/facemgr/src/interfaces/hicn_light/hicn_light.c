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
#include <hicn/util/map.h>

#include "../../common.h"
#include "../../interface.h"

#define DEFAULT_ROUTE_COST 0

#define INTERVAL_MS 1000

#define WITH_POLL

typedef enum {
    HL_STATE_UNDEFINED,
    HL_STATE_IDLE,
    HL_STATE_ROUTES_SENT,
    HL_STATE_ROUTES_RECEIVED,
    HL_STATE_FACES_SENT,
    HL_STATE_FACES_RECEIVED,
    HL_STATE_N
} hl_state_t;

typedef struct {
    hc_sock_t * s; /* NULL means no active socket */
    hl_state_t state;

    /* Timer used for forwarder reconnection */
    int reconnect_timer_fd; /* 0 means no active timer */

    /* Timer used to periodically poll the forwarder face and routing tables */
    int poll_timer_fd;
    hc_data_t * polled_routes;
} hl_data_t;

/* Forward declarations */
int hl_timeout(interface_t * interface, int fd, void * unused);

#ifdef WITH_POLL
int hl_process_state(interface_t * interface, int fd, void * unused)
#else
int hl_process_state(interface_t * interface)
#endif
{
    hl_data_t * data = (hl_data_t *)interface->data;

    /*
     * Every tick we need to probe the forwarder for the list of faces and
     * associated routes.
     *
     * This is used to guess manually added faces and routes
     *
     * TODO ensure we are idle at tick time
     */

    switch(data->state)
    {
        case HL_STATE_IDLE:
            assert(!data->polled_routes);

            //DEBUG("[hl_process_state] Querying route list");
            if (hc_route_list_async(data->s) < 0) {
                DEBUG("[hl_process_state] Error querying route list");
                return -1;
            }
            data->state = HL_STATE_ROUTES_SENT;
            break;


        case HL_STATE_ROUTES_RECEIVED:
            //DEBUG("[hl_process_state] Querying face list");
            if (hc_face_list_async(data->s) < 0) {
                DEBUG("[hl_process_state] Error querying face list");
                return -1;
            }
            data->state = HL_STATE_FACES_SENT;
            break;

        case HL_STATE_FACES_RECEIVED:
            data->state = HL_STATE_IDLE;
            break;

        case HL_STATE_ROUTES_SENT:
        case HL_STATE_FACES_SENT:
            INFO("[hl_process_state] Out of sync... resetting state");
            if (data->polled_routes) {
                hc_data_free(data->polled_routes);
                data->polled_routes = NULL;
            }
            data->state = HL_STATE_IDLE;
            break;

        case HL_STATE_UNDEFINED:
        case HL_STATE_N:
            ERROR("[hl_process_state] Unexpected state");
            return -1;
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

    /* We always restart from the idle phase */
    data->state = HL_STATE_IDLE;


/* poll will replace the original get, ideally we would get notifications */
#ifdef WITH_POLL
    data->poll_timer_fd = interface_register_timer(interface, INTERVAL_MS,
            hl_process_state, interface);
    if (data->poll_timer_fd < 0) {
        ERROR("[hc_connect] Could not initialize polling timer");
        return -1;
    }
#else
    hl_process_state(interface);
#endif

    return 0;

    //interface_unregister_fd(interface, hc_sock_get_fd(data->s));
ERR_FD:
    return -1;
}

int _hl_connect(interface_t * interface);

int
hl_connect_timeout(interface_t * interface, int fd, void * unused)
{
    hl_data_t * data = interface->data;
    assert(fd == data->reconnect_timer_fd);
    _unused(data);

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

    if (data->poll_timer_fd > 0)
        interface_unregister_timer(interface, data->poll_timer_fd);

    if (data->polled_routes)
        hc_data_free(data->polled_routes);

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
    data->poll_timer_fd = 0;

    interface->data = data;

    if (hl_connect(interface) < 0) {
        ERROR("[hl_initialize] Error during connection to forwarder");
        goto ERR_CONNECT;
    }

    data->polled_routes = NULL;

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

    if (data->polled_routes)
        hc_data_free(data->polled_routes);

    free(data);

    return 0;
}

int hl_on_event(interface_t * interface, facelet_t * facelet)
{
    hc_face_t hc_face;
    hc_route_t route;
    int rc;
    int ret = 0;
    hl_data_t * data = (hl_data_t *)interface->data;
    face_t * face = NULL;

    hc_face.id = 0;
    memset(hc_face.name, 0, sizeof(hc_face.name));


    /* NOTE
     *  - One example where this fails (and it is normal) is when we delete a
     *  face that was not completely created, because for instance bonjour did
     *  not give any data
     */
    if (facelet_get_face(facelet, &face) < 0) {
        ERROR("Could not retrieve face from facelet");
        ret = -FACELET_ERROR_REASON_INTERNAL_ERROR;
        goto ERR_FACE;
    }

    if (!data->s) {
        /* We are not connected to the forwarder */
        ret = -FACELET_ERROR_REASON_FORWARDER_OFFLINE;
        goto ERR;
    }

    switch(facelet_get_event(facelet)) {

        case FACELET_EVENT_CREATE:
            {
            /* Create face */
            char buf[MAXSZ_FACELET];
            facelet_snprintf(buf, MAXSZ_FACELET, facelet);
            DEBUG("Create facelet %s", buf);

            hc_face.face = *face;
            rc = hc_face_create(data->s, &hc_face);
            if (rc < 0) {
                ERROR("Failed to create face\n");
                ret = -FACELET_ERROR_REASON_UNSPECIFIED_ERROR;
                goto ERR;
            }
            INFO("Created face id=%d - %s", hc_face.id, buf);
            }

            hicn_route_t ** route_array;
            int n = facelet_get_route_array(facelet, &route_array);
            if (n < 0) {
                ERROR("Failed to create default hICN/IPv4 route");
                ret = -FACELET_ERROR_REASON_UNSPECIFIED_ERROR;
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
            free(route_array);

            break;

        case FACELET_EVENT_DELETE:
            /* Removing a face should also remove associated routes */
            hc_face.face = *face;
            rc = hc_face_delete(data->s, &hc_face);
            if (rc < 0) {
                ERROR("Failed to delete face\n");
                ret = -FACELET_ERROR_REASON_UNSPECIFIED_ERROR;
                goto ERR;
            }

            char buf[MAXSZ_FACELET];
            facelet_snprintf(buf, MAXSZ_FACELET, facelet);
            INFO("Deleted face id=%d", hc_face.id);

            break;

        case FACELET_EVENT_UPDATE:
            /* Currently, only admin_state & priority are supported */
            if (facelet_get_admin_state_status(facelet) == FACELET_ATTR_STATUS_DIRTY) {
                hc_face.face = *face;
                hc_face_t * face_found;

                rc = hc_face_get(data->s, &hc_face, &face_found);
                if (rc < 0) {
                    ERROR("Failed to find face\n");
                    ret = -FACELET_ERROR_REASON_INTERNAL_ERROR;
                    goto ERR;
                }
                if (!face_found) {
                    ERROR("Face to update has not been found");
                    ret = -FACELET_ERROR_REASON_UNSPECIFIED_ERROR;
                    goto ERR;
                }
                char conn_id_or_name[SYMBOLIC_NAME_LEN];
                snprintf(conn_id_or_name, SYMBOLIC_NAME_LEN, "%d", face_found->id);
                free(face_found);

                face_state_t admin_state;
                if (facelet_get_admin_state(facelet, &admin_state) < 0) {
                    ERROR("Failed to retrieve facelet admin state");
                    ret = -FACELET_ERROR_REASON_INTERNAL_ERROR;
                    goto ERR;
                }

                if (hc_connection_set_admin_state(data->s, conn_id_or_name, admin_state) < 0) {
                    ERROR("Failed to update admin state");
                    ret = -FACELET_ERROR_REASON_UNSPECIFIED_ERROR;
                    goto ERR;
                }
                facelet_set_admin_state_status(facelet, FACELET_ATTR_STATUS_CLEAN);
                INFO("Updated face id=%d - admin_state=%s", hc_face.id,
                        face_state_str(admin_state));
            }
#ifdef WITH_POLICY
            if (facelet_get_netdevice_type_status(facelet) == FACELET_ATTR_STATUS_DIRTY) {
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

                netdevice_type_t netdevice_type;
                if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
                    ERROR("Failed to retrieve facelet netdevice_type");
                    goto ERR;
                }

                /* Encode netdevice type into tags */ 
                policy_tags_t tags = POLICY_TAGS_EMPTY;
                if (facelet_has_netdevice_type(facelet)) {
                    netdevice_type_t netdevice_type;
                    if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
                        ERROR("error getting netdevice_type");
                        goto ERR;
                    }


                    switch(netdevice_type) {
                        case NETDEVICE_TYPE_UNDEFINED:
                        case NETDEVICE_TYPE_LOOPBACK:
                            break;
                        case NETDEVICE_TYPE_WIRED:
                            policy_tags_add(&tags, POLICY_TAG_WIRED);
                            break;
                        case NETDEVICE_TYPE_WIFI:
                            policy_tags_add(&tags, POLICY_TAG_WIFI);
                            break;
                        case NETDEVICE_TYPE_CELLULAR:
                            policy_tags_add(&tags, POLICY_TAG_CELLULAR);
                            break;
                        default:
                            goto ERR;
                    }
                }
                //face->tags = tags;

                if (hc_connection_set_tags(data->s, conn_id_or_name, tags) < 0) {
                    ERROR("Failed to update tags");
                    goto ERR;
                }
                facelet_set_netdevice_type_status(facelet, FACELET_ATTR_STATUS_CLEAN);
                INFO("Updated face id=%d - netdevice_type=%s", hc_face.id,
                        netdevice_type_str(netdevice_type));
            }
            if (facelet_get_priority_status(facelet) == FACELET_ATTR_STATUS_DIRTY) {
                INFO("Updating priority...");
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

                uint32_t priority;
                if (facelet_get_priority(facelet, &priority) < 0) {
                    ERROR("Failed to retrieve facelet priority");
                    goto ERR;
                }

                INFO("Changing connection %s priority to %d", conn_id_or_name, priority);
                if (hc_connection_set_priority(data->s, conn_id_or_name, priority) < 0) {
                    ERROR("Failed to update priority");
                    goto ERR;
                }
                facelet_set_priority_status(facelet, FACELET_ATTR_STATUS_CLEAN);

                INFO("Updated face id=%d - priority=%d", hc_face.id, priority);
            }
#endif /* WITH_POLICY */
            break;

        default:
            ERROR("Unknown event %s\n", facelet_event_str[facelet_get_event(facelet)]);
            /* Unsupported events */
            ret = -FACELET_ERROR_REASON_INTERNAL_ERROR;
            goto ERR;
    }

ERR:
    face_free(face);
ERR_FACE:
    return ret;
}

int hl_callback(interface_t * interface, int fd, void * unused)
{
    hl_data_t * data = (hl_data_t*)interface->data;
    hc_data_t * results;
    int ret = 0;

    /* In case of error, reconnect to forwarder */
    if (hc_sock_callback(data->s, &results) < 0) {
        DEBUG("Closing socket... reconnecting...");
        if (interface_unregister_fd(interface, hc_sock_get_fd(data->s)) < 0) {
            ERROR("[hl_callback] Error unregistering fd");
        }

        /* Stopping poll timer */
        if (interface_unregister_timer(interface, data->poll_timer_fd) < 0) {
            ERROR("[hl_callback] Could not cancel polling timer after forwarder disconnect");
        }
        if (data->polled_routes)
            hc_data_free(data->polled_routes);

        hc_sock_free(data->s);
        data->s = NULL;
        hl_connect(interface);
        return ret;
    }

    /* Shall we wait for more data ? */
    if (!results->complete)
        return ret;

    /* Process returned data */
    switch(data->state) {

        case HL_STATE_ROUTES_SENT:
            //DEBUG("[hl_callback] Processing routes");
            data->polled_routes = results;

#if 0
            foreach_route(r, results) {
                char buf[MAXSZ_FACE];
                int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, r);
                if (rc >= MAXSZ_HC_ROUTE)
                    ERROR("[hl_callback] Unexpected truncation of route string");
                if (rc < 0)
                    ERROR("[hl_callback] Error during route string formatting");
                DEBUG("Route: %s", buf);
            }
#endif
            data->state = HL_STATE_ROUTES_RECEIVED;
            if (hl_process_state(interface, fd, unused) < 0) {
                ERROR("[hl_callback] Error processing state after routes received");
                ret = -1;
            }
            break;


        case HL_STATE_FACES_SENT:
            //DEBUG("[hl_callback] Processing faces");
            assert(data->polled_routes);
            foreach_face(f, results) {

#if 0
                char buf[MAXSZ_FACE];
                int rc = hc_face_snprintf(buf, MAXSZ_FACE, f);
                if (rc >= MAXSZ_HC_FACE)
                    ERROR("[hl_callback] Unexpected truncation of face string");
                if (rc < 0)
                    ERROR("[hl_callback] Error during face string formatting");

                DEBUG("Face: %s", buf);
#endif

                /* We can ignore faces on localhost */

                facelet_t * facelet = facelet_create_from_face(&f->face);
                if (!facelet) {
                    ERROR("[hl_callback] Could not create facelet... skipping");
                    continue;
                }

                foreach_route(r, data->polled_routes) {
                    if (r->face_id != f->id)
                        continue;

#if 0
                    char route_s[MAXSZ_HC_ROUTE];
                    int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, r);
                    if (rc >= MAXSZ_HC_ROUTE)
                        ERROR("[hl_callback] Unexpected truncation of route string");
                    if (rc < 0)
                        ERROR("[hl_callback] Error during route string formatting");
                    DEBUG("Associated route: %s", route_s);
#endif

                    if (r->len == 0)
                        continue;

                    ip_prefix_t prefix = {
                        .family = r->family,
                        .address = r->remote_addr,
                        .len = r->len,
                    };
                    hicn_route_t * route = hicn_route_create(&prefix, r->face_id, r->cost);
                    facelet_add_route(facelet, route);
                }

                facelet_set_event(facelet, FACELET_EVENT_GET);
                interface_raise_event(interface, facelet);
            }
            hc_data_free(results);
            hc_data_free(data->polled_routes);
            data->polled_routes = NULL;
            data->state = HL_STATE_FACES_RECEIVED;
            if (hl_process_state(interface, fd, unused) < 0) {
                ERROR("[hl_callback] Error processing state after faces received");
                ret = -1;
            }
            break;

        case HL_STATE_IDLE:
        case HL_STATE_FACES_RECEIVED:
        case HL_STATE_ROUTES_RECEIVED:
        case HL_STATE_UNDEFINED:
        case HL_STATE_N:
            ERROR("[hl_callback] Unexpected state");
            ret = -1;
    }

    return ret;
}

const interface_ops_t hicn_light_ops = {
    .type = "hicn_light",
    .initialize = hl_initialize,
    .finalize = hl_finalize,
    .on_event = hl_on_event,
    .callback = hl_callback,
};
