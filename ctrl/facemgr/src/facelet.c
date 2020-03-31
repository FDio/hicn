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
 * \file facelet.c
 * \brief Implementation of facelet
 */

#include <assert.h>
#include <stdbool.h>
#include <hicn/face.h>
#include <hicn/ctrl/route.h>
#include <hicn/facemgr/cfg.h>
#include <hicn/facemgr/facelet.h>
#include <hicn/util/log.h>
#include <hicn/util/set.h>

#define FACELET_MAX_ROUTES 10

TYPEDEF_SET_H(route_set, hicn_route_t *);
TYPEDEF_SET(route_set, hicn_route_t *, hicn_route_cmp, generic_snprintf);

const char * face_type_layer_str[] = {
#define _(x) [FACE_TYPE_LAYER_ ## x] = STRINGIZE(x),
    foreach_face_type_layer
#undef _
};

const char * face_type_encap_str[] = {
#define _(x) [FACE_TYPE_ENCAP_ ## x] = STRINGIZE(x),
    foreach_face_type_encap
#undef _
};

const char * facelet_status_str[] = {
#define _(x) [FACELET_STATUS_ ## x] = STRINGIZE(x),
    foreach_facelet_status
#undef _
};

const char * facelet_error_reason_str[] = {
#define _(x) [FACELET_ERROR_REASON_ ## x] = STRINGIZE(x),
    foreach_facelet_error_reason
#undef _
};

/* Facelet attribute status */

const char * facelet_attr_status_str[] = {
#define _(x, str) [FACELET_ATTR_STATUS_ ## x] = STRINGIZE(x),
    foreach_facelet_attr_status
#undef _
};

const char * facelet_attr_status_str_short[] = {
#define _(x, str) [FACELET_ATTR_STATUS_ ## x] = STRINGIZE(str),
    foreach_facelet_attr_status
#undef _
};


/* Facelet */

struct facelet_s {
    unsigned id;

#define _(TYPE, NAME) TYPE NAME;
    foreach_facelet_attr
#undef _
#define _(TYPE, NAME) facelet_attr_status_t NAME ## _status;
    foreach_facelet_attr
#undef _



    facelet_status_t status;
    int error;

    facelet_event_t event;

    route_set_t * routes;
    bool routes_done;

    bool bj_done;
    bool au_done;
};

const char * facelet_event_str[] = {
#define _(x) [FACELET_EVENT_ ## x] = STRINGIZE(x),
foreach_facelet_event
#undef _
};

facelet_t *
facelet_create()
{
    facelet_t * facelet = calloc(1, sizeof(facelet_t));
    if (!facelet)
        goto ERR_MALLOC;

    facelet->id = 0;

    facelet->netdevice_status = FACELET_ATTR_STATUS_UNSET;
    facelet->netdevice_type_status = FACELET_ATTR_STATUS_UNSET;
    facelet->family_status = FACELET_ATTR_STATUS_UNSET;
    facelet->local_addr_status = FACELET_ATTR_STATUS_UNSET;
    facelet->local_port_status = FACELET_ATTR_STATUS_UNSET;
    facelet->remote_addr_status = FACELET_ATTR_STATUS_UNSET;
    facelet->remote_port_status = FACELET_ATTR_STATUS_UNSET;
    facelet->admin_state_status = FACELET_ATTR_STATUS_UNSET;
    facelet->state_status = FACELET_ATTR_STATUS_UNSET;
#ifdef WITH_POLICY
    facelet->priority_status = FACELET_ATTR_STATUS_UNSET;
#endif /* WITH_POLICY */
    facelet->face_type_status = FACELET_ATTR_STATUS_UNSET;

    facelet->status = FACELET_STATUS_UNDEFINED;
    facelet->error = 0;

    facelet->bj_done = false;
    facelet->au_done = false;

    facelet->event = FACELET_EVENT_UNDEFINED;

    facelet->routes = route_set_create();
    if (!facelet->routes) {
        ERROR("[facelet_create] Cannot create route set");
        goto ERR_ROUTE_SET;
    }
    facelet->routes_done = false;

    return facelet;

ERR_ROUTE_SET:
    free(facelet);
ERR_MALLOC:
    return NULL;
}

unsigned
facelet_get_id(facelet_t * facelet)
{
    return facelet->id;
}

void
facelet_set_id(facelet_t * facelet, unsigned id)
{
    facelet->id = id;
}

facelet_t *
facelet_create_from_netdevice(netdevice_t * netdevice)
{
    facelet_t * facelet = facelet_create();
    if (!facelet)
        goto ERR_FACELET;

    int rc = facelet_set_netdevice(facelet, *netdevice);
    if (rc < 0)
        goto ERR_NETDEV;

    return facelet;

ERR_NETDEV:
    facelet_free(facelet);
ERR_FACELET:
    return NULL;
}

/**
 * \brief Validate whether the facelet has all required fields to construct a
 *      face of the given type
 * \param [in] facelet - Pointer to the facelet to verify
 * \return 0 in case of success, -1 otherwise
 */
int
facelet_validate_face(const facelet_t * facelet)
{
    if (!facelet_has_face_type(facelet))
        return false;
    switch(facelet->face_type.layer) {
        case FACE_TYPE_LAYER_4:
            if (!facelet_has_remote_port(facelet))
                return false;
            if (!facelet_has_remote_addr(facelet))
                return false;
        case FACE_TYPE_LAYER_3:
            if (!facelet_has_local_port(facelet))
                return false;
            if (!facelet_has_local_addr(facelet))
                return false;
            if (!facelet_has_netdevice(facelet))
                return false;
            return true;

        default:
            return false; /* Error */
    }
    // FIXME Not implemented
    return 0;
}


netdevice_type_t
netdevice_type_from_face_tags(const face_t * face)
{
    policy_tags_t tags = face->tags;
    if (policy_tags_has(tags, POLICY_TAG_WIRED))
        return NETDEVICE_TYPE_WIRED;
    else if (policy_tags_has(tags, POLICY_TAG_WIFI))
        return NETDEVICE_TYPE_WIFI;
    else if (policy_tags_has(tags, POLICY_TAG_CELLULAR))
        return NETDEVICE_TYPE_CELLULAR;
    return NETDEVICE_TYPE_UNDEFINED;
}

facelet_t *
facelet_create_from_face(face_t * face)
{
    facelet_t * facelet = malloc(sizeof(facelet_t));
    if (!facelet)
        goto ERR_MALLOC;

    facelet->id = 0;

    /* Go through the face attributes to update the local representation */

    /* Attribute : netdevice */
    /* NOTE index is not set */
    if (IS_VALID_NETDEVICE(face->netdevice)) {
        /* /!\ A face has only the netdevice name */
        netdevice_set_name(&facelet->netdevice, face->netdevice.name);
        facelet->netdevice_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->netdevice_status = FACELET_ATTR_STATUS_UNSET;
    }

    /* Attribute : netdevice_type */
    facelet->netdevice_type = netdevice_type_from_face_tags(face);
    if (facelet->netdevice_type != NETDEVICE_TYPE_UNDEFINED) {
        facelet->netdevice_type_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->netdevice_type = NETDEVICE_TYPE_UNDEFINED;
        facelet->netdevice_type_status = FACELET_ATTR_STATUS_UNSET;
    }

    /* Attribute : family */
    if (IS_VALID_FAMILY(face->family)) {
        facelet->family = face->family;
        facelet->family_status = FACELET_ATTR_STATUS_CLEAN;

        /* Attribute : local_addr  */
        if (ip_address_cmp(&face->local_addr, &IP_ADDRESS_EMPTY, face->family) != 0) {
            facelet->local_addr = face->local_addr;
            facelet->local_addr_status = FACELET_ATTR_STATUS_CLEAN;
        } else {
            facelet->local_addr_status = FACELET_ATTR_STATUS_UNSET;
        }

        /* Attribute : local_port  */
        if (IS_VALID_PORT(face->local_port)) {
            facelet->local_port = face->local_port;
            facelet->local_port_status = FACELET_ATTR_STATUS_CLEAN;
        } else {
            facelet->local_port_status = FACELET_ATTR_STATUS_UNSET;
        }

        /* Attribute : remote_addr  */
        if (ip_address_cmp(&face->remote_addr, &IP_ADDRESS_EMPTY, face->family) != 0) {
            facelet->remote_addr = face->remote_addr;
            facelet->remote_addr_status = FACELET_ATTR_STATUS_CLEAN;
        } else {
            facelet->remote_addr_status = FACELET_ATTR_STATUS_UNSET;
        }

        /* Attribute : remote_port  */
        if (IS_VALID_PORT(face->remote_port)) {
            facelet->remote_port = face->remote_port;
            facelet->remote_port_status = FACELET_ATTR_STATUS_CLEAN;
        } else {
            facelet->remote_port_status = FACELET_ATTR_STATUS_UNSET;
        }

    } else {
        facelet->family_status = FACELET_ATTR_STATUS_UNSET;
        facelet->local_addr_status = FACELET_ATTR_STATUS_UNSET;
        facelet->local_port_status = FACELET_ATTR_STATUS_UNSET;
        facelet->remote_addr_status = FACELET_ATTR_STATUS_UNSET;
        facelet->remote_port_status = FACELET_ATTR_STATUS_UNSET;
    }

    /* Attribute : admin_state */
    if ((face->admin_state == FACE_STATE_UP) ||
            (face->admin_state == FACE_STATE_DOWN)) {
        facelet->admin_state = face->admin_state;
        facelet->admin_state_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->admin_state_status = FACELET_ATTR_STATUS_UNSET;
    }

    /* Attribute : state */
    if ((face->state == FACE_STATE_UP) ||
            (face->state == FACE_STATE_DOWN)) {
        facelet->state = face->state;
        facelet->state_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->state_status = FACELET_ATTR_STATUS_UNSET;
    }

#ifdef WITH_POLICY
    /* Attribute : priority */
    if (face->priority > 0) {
        facelet->priority = face->priority;
        facelet->priority_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->priority_status = FACELET_ATTR_STATUS_UNSET;
    }
#endif /* WITH_POLICY */

    /* Attribute : face_type */
    if ((face->type != FACE_TYPE_UNDEFINED) && (face->type != FACE_TYPE_N)) {
        switch(face->type) {
            case FACE_TYPE_UDP:
                facelet->face_type = FACEMGR_FACE_TYPE_OVERLAY_UDP;
                break;
            case FACE_TYPE_TCP:
                facelet->face_type = FACEMGR_FACE_TYPE_OVERLAY_TCP;
                break;
            case FACE_TYPE_HICN:
                facelet->face_type = FACEMGR_FACE_TYPE_NATIVE_TCP;
                break;
            default:
                ERROR("[facelet_create_from_face] Face type not (yet) implemented");
                goto ERR_FACE;
        }
        facelet->face_type_status = FACELET_ATTR_STATUS_CLEAN;
    } else {
        facelet->face_type_status = FACELET_ATTR_STATUS_UNSET;
    }

    /* Status */
    facelet->status = FACELET_STATUS_CLEAN;
    facelet->error = 0;

    /* TODO Consistency check between face type and found attributes */
    if (facelet_validate_face(facelet) < 0)
        goto ERR_FACE;

    facelet->bj_done = false;
    facelet->au_done = false;

    facelet->event = FACELET_EVENT_UNDEFINED;

    /* We need to get route set */
    facelet->routes = route_set_create();
    if (!facelet->routes) {
        ERROR("[facelet_create] Cannot create route set");
        goto ERR_ROUTE_SET;
    }
    facelet->routes_done = false;

    return facelet;

ERR_ROUTE_SET:
ERR_FACE:
    free(facelet);
ERR_MALLOC:
    return NULL;
}


void
facelet_free(facelet_t * facelet)
{
    /* Free up routes */
    route_set_clear(facelet->routes);
    route_set_free(facelet->routes);
    free(facelet);
}

facelet_t *
facelet_dup(const facelet_t * current_facelet)
{
    facelet_t * facelet = facelet_create();
    if (!facelet)
        goto ERR_CREATE;

#define _(TYPE, NAME) facelet-> NAME = current_facelet-> NAME;
    foreach_facelet_attr
#undef _
#define _(TYPE, NAME) facelet-> NAME ## _status = current_facelet-> NAME ## _status;
    foreach_facelet_attr
#undef _

    facelet->status = current_facelet->status;
    facelet->event = current_facelet->event;

    facelet->bj_done = current_facelet->bj_done;
    facelet->au_done = current_facelet->au_done;

    /* Routes */
    hicn_route_t ** route_array;
    int n = route_set_get_array(current_facelet->routes, &route_array);
    if (n < 0) {
        ERROR("[facelet_free] Error getting route set associated to facelet");
    } else {
        for (unsigned i = 0; i < n; i++) {
            hicn_route_t * route = route_array[i];
            hicn_route_t * new_route = hicn_route_dup(route);
            if (!new_route)
                goto ERR_ROUTE;
            route_set_add(facelet->routes, new_route);
        }
    }
    free(route_array);

    return facelet;

ERR_ROUTE:
    /* This will free all routes */
    facelet_free(facelet);
ERR_CREATE:
    return NULL;
}

int
facelet_cmp(const facelet_t * f1, const facelet_t * f2)
{
    /*
     * Under the assumption we only create a face per physical interface, a
     * facelet is uniquely identified by its netdevice attribute, and address
     * family if any.
     *
     * Because of additional static faces, we introduce a unique facelet id
     *
     * This function is mostly used for lookups into the cache, and the face
     * thus needs to have a netdevice associated, and optionally, an address
     * family.
     *
     * For other situations, the `facelet_match` function is more appropriate.
     */

    if (f1->id != f2->id)
        return f1->id > f2->id ?  1 : -1;

    if ((f1->netdevice_status != FACELET_ATTR_STATUS_UNSET) &&
            (f2->netdevice_status != FACELET_ATTR_STATUS_UNSET)) {
        int rc = netdevice_cmp(&f1->netdevice, &f2->netdevice);
        if (rc != 0)
            return rc;

    } else {
        /* Both unset : we might have the face without netdevice due to hicn
         * light not returning it currently, but we cannot skip it in the match
         * otherwise we cannot distinguish with other faces except matching on
         * other fields which might unfortunately not be determined yet...
         */
        return (f1->netdevice_status == FACELET_ATTR_STATUS_UNSET) ? -1 : 1;
    }

    assert(f1->family_status != FACELET_ATTR_STATUS_UNSET);
    assert(f2->family_status != FACELET_ATTR_STATUS_UNSET);

    if ((f1->family == AF_UNSPEC) || (f2->family == AF_UNSPEC))
        return 0;
    int diff = f1->family - f2->family;
    return (diff > 0) ? 1  :
           (diff < 0) ? -1 : 0;
}

/*
 * If the match has a field set, then the facelet only matches iif it has the
 * same field set, and both values are equal
 */
#define EQUALS_ATTRIBUTE(TYPE, NAME)                                            \
do {                                                                            \
    if (facelet_has_ ## NAME(facelet1)) {                                       \
        if (facelet_has_ ## NAME(facelet2)) {                                   \
            TYPE NAME ## 1;                                                     \
            TYPE NAME ## 2;                                                     \
            if (facelet_get_ ## NAME (facelet1, & NAME ## 1) < 0)               \
                return false;                                                   \
            if (facelet_get_ ## NAME (facelet2, & NAME ## 2) < 0)               \
                return false;                                                   \
            if (memcmp(& NAME ## 1, & NAME ## 2, sizeof(TYPE)) != 0)            \
                return false;                                                   \
        } else {                                                                \
            return false;                                                       \
        }                                                                       \
    } else {                                                                    \
        if (facelet_has_ ## NAME(facelet2)) {                                   \
            return false;                                                       \
        }                                                                       \
    }                                                                           \
} while(0)

bool
facelet_equals(const facelet_t * facelet1, const facelet_t * facelet2)
{
#define _(TYPE, NAME) EQUALS_ATTRIBUTE(TYPE, NAME);
    foreach_facelet_attr
#undef _
    return true;
}

/*
 * If the match has a field set, then the facelet only matches iif it has the
 * same field set, and both values are equal
 */
#define MATCH_ATTRIBUTE(TYPE, NAME)                                             \
do {                                                                            \
    if (facelet_match->NAME ## _status == FACELET_ATTR_STATUS_CLEAN) {          \
        if (facelet_has_ ## NAME(facelet_match)) {                              \
            TYPE NAME;                                                          \
            TYPE NAME ## _match;                                                \
            if (!facelet_has_ ## NAME(facelet)) {                               \
                continue; /* return false; */                                   \
            }                                                                   \
            if (facelet_get_ ## NAME (facelet, & NAME) < 0)                     \
                return false;                                                   \
            if (facelet_get_ ## NAME (facelet_match, & NAME ## _match) < 0)     \
                return false;                                                   \
            if (memcmp(& NAME, & NAME ## _match, sizeof(NAME)) != 0) {          \
                return false;                                                   \
            }                                                                   \
        }                                                                       \
    }                                                                           \
} while(0)

/* facelet_match is the incoming one */
bool
facelet_match(const facelet_t * facelet, const facelet_t * facelet_match)
{
#define _(TYPE, NAME) MATCH_ATTRIBUTE(TYPE, NAME);
    foreach_facelet_attr
#undef _

#if 0
    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet_match);
    DEBUG("MATCHED FACELET %s", facelet_s);
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet);
    DEBUG("         WITH %s", facelet_s);
#endif
    return true;
}

bool facelet_has_key(const facelet_t * facelet) {
    return (facelet_has_netdevice(facelet) && facelet_has_family(facelet));
}

/*
 * Implementation note:
 * - facelet_set_* is equivalent to merge with a CLEAN remote attribute
 */
#define FACELET_ACCESSORS(TYPE, NAME)                                           \
bool                                                                            \
facelet_has_ ## NAME(const facelet_t * facelet)                                 \
{                                                                               \
    assert(facelet);                                                            \
    assert(facelet->NAME ## _status != FACELET_ATTR_STATUS_UNDEFINED);          \
    assert(facelet->NAME ## _status != FACELET_ATTR_STATUS_N);                  \
    return ((facelet-> NAME ## _status != FACELET_ATTR_STATUS_UNSET));          \
}                                                                               \
                                                                                \
facelet_attr_status_t                                                           \
facelet_get_ ## NAME ## _status(const facelet_t * facelet)                      \
{                                                                               \
    return (facelet->NAME ## _status);                                          \
}                                                                               \
                                                                                \
void                                                                            \
facelet_set_ ## NAME ## _status(facelet_t * facelet,                            \
        facelet_attr_status_t status)                                           \
{                                                                               \
    facelet->NAME ## _status = status;                                          \
}                                                                               \
                                                                                \
int                                                                             \
facelet_get_ ## NAME(const facelet_t * facelet, TYPE * NAME)                    \
{                                                                               \
    assert(facelet);                                                            \
    if (!facelet_has_ ## NAME(facelet))                                         \
        return -1;                                                              \
    *NAME = facelet-> NAME;                                                     \
    return 0;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
facelet_set_local_ ## NAME(facelet_t * facelet, TYPE NAME)                      \
{                                                                               \
    assert(facelet);                                                            \
    switch(facelet->NAME ## _status) {                                          \
        case FACELET_ATTR_STATUS_UNSET:                                         \
        case FACELET_ATTR_STATUS_CLEAN:                                         \
        case FACELET_ATTR_STATUS_DIRTY:                                         \
        case FACELET_ATTR_STATUS_PENDING:                                       \
            facelet-> NAME = NAME;                                              \
            facelet->NAME ## _status = FACELET_ATTR_STATUS_DIRTY;               \
            if (facelet->status == FACELET_STATUS_CLEAN)                        \
                facelet->status = FACELET_STATUS_UPDATE;                        \
            break;                                                              \
        case FACELET_ATTR_STATUS_CONFLICT:                                      \
            break;                                                              \
        case FACELET_ATTR_STATUS_UNDEFINED:                                     \
        case FACELET_ATTR_STATUS_N:                                             \
            ERROR("Unexpected attribute status value");                         \
            return -1;                                                          \
    }                                                                           \
    return 0;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
facelet_set_remote_ ## NAME(facelet_t * facelet, TYPE NAME)                     \
{                                                                               \
    assert(facelet);                                                            \
    switch(facelet->NAME ## _status) {                                          \
        case FACELET_ATTR_STATUS_UNSET:                                         \
            facelet-> NAME = NAME;                                              \
            facelet->NAME ## _status = FACELET_ATTR_STATUS_CLEAN;               \
            break;                                                              \
        case FACELET_ATTR_STATUS_CLEAN:                                         \
            facelet->NAME = NAME;                                               \
            break;                                                              \
        case FACELET_ATTR_STATUS_DIRTY:                                         \
            ERROR("Discarded remote value for status reasons");                 \
            break;                                                              \
        case FACELET_ATTR_STATUS_PENDING:                                       \
            ERROR("Received remote value on pending attribute");                \
            facelet->NAME ## _status = FACELET_ATTR_STATUS_CONFLICT;            \
            /* We need to proceed to an update of the face */                   \
            if (facelet->status != FACELET_STATUS_UPDATE)                       \
                facelet->status = FACELET_STATUS_UPDATE;                        \
            break;                                                              \
        case FACELET_ATTR_STATUS_CONFLICT:                                      \
            return -1;                                                          \
        case FACELET_ATTR_STATUS_UNDEFINED:                                     \
        case FACELET_ATTR_STATUS_N:                                             \
            ERROR("Unexpected attribute status value");                         \
            return -1;                                                          \
    }                                                                           \
    return 0;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
facelet_set_ ## NAME(facelet_t * facelet, TYPE NAME)                            \
{                                                                               \
    return facelet_set_local_ ## NAME(facelet, NAME);                           \
}                                                                               \
                                                                                \
int                                                                             \
facelet_unset_ ## NAME(facelet_t * facelet)                                     \
{                                                                               \
    return facelet->NAME ## _status = FACELET_ATTR_STATUS_UNSET;                \
}

#define _(TYPE, NAME) FACELET_ACCESSORS(TYPE, NAME)
foreach_facelet_attr
#undef _

/*
 * This function is called for every facelet attribute. It is responsible for
 * comparing both the current and new value, and set the attribute and facelet
 * status appropriately.
 */

// FIXME CLEAN for key fields, dirty for fields to update.

#define MERGE_ATTRIBUTE(TYPE, NAME)                                                     \
do {                                                                                    \
    switch(facelet_to_merge->NAME ## _status) {                                         \
        case FACELET_ATTR_STATUS_UNDEFINED:                                             \
        case FACELET_ATTR_STATUS_N:                                                     \
        case FACELET_ATTR_STATUS_PENDING:                                               \
        case FACELET_ATTR_STATUS_CONFLICT:                                              \
            ERROR("Unexpected facelet attribute status");                               \
            return -1;                                                                  \
        case FACELET_ATTR_STATUS_UNSET:                                                 \
            break;                                                                      \
        case FACELET_ATTR_STATUS_CLEAN:                                                 \
        case FACELET_ATTR_STATUS_DIRTY:                                                 \
            facelet_set_ ## NAME(facelet, facelet_to_merge-> NAME);                     \
            break;                                                                      \
    }                                                                                   \
} while (0)

int facelet_merge(facelet_t * facelet, facelet_t * facelet_to_merge)
{
    assert(facelet && facelet_to_merge);

#define _(TYPE, NAME) MERGE_ATTRIBUTE(TYPE, NAME);
    foreach_facelet_attr
#undef _
    facelet->event = facelet_to_merge->event;

    /* Routes */
    hicn_route_t ** route_array;
    int n = route_set_get_array(facelet_to_merge->routes, &route_array);
    if (n < 0) {
        ERROR("[facelet_free] Error getting route set associated to facelet");
    } else {
        for (unsigned i = 0; i < n; i++) {
            hicn_route_t * route = route_array[i];
            hicn_route_t * route_found = NULL;
            if (route_set_get(facelet->routes, route, &route_found) < 0) {
                ERROR("Error searching for route");
                continue;
            }
            if (route_found)
                continue;
            route_set_add(facelet->routes, hicn_route_dup(route));
        }
    }
    free(route_array);

    return 0;
}

#define MERGE_ATTRIBUTE_REMOTE(TYPE, NAME)                                              \
do {                                                                                    \
    switch(facelet_to_merge->NAME ## _status) {                                         \
        case FACELET_ATTR_STATUS_UNDEFINED:                                             \
        case FACELET_ATTR_STATUS_N:                                                     \
        case FACELET_ATTR_STATUS_DIRTY:                                                 \
        case FACELET_ATTR_STATUS_PENDING:                                               \
        case FACELET_ATTR_STATUS_CONFLICT:                                              \
            ERROR("Unexpected facelet attribute status");                               \
            return -1;                                                                  \
        case FACELET_ATTR_STATUS_UNSET:                                                 \
            break;                                                                      \
        case FACELET_ATTR_STATUS_CLEAN:                                                 \
            facelet_set_ ## NAME(facelet, facelet_to_merge-> NAME);                     \
            break;                                                                      \
                                                                                        \
    }                                                                                   \
} while (0)

int facelet_merge_remote(facelet_t * facelet, const facelet_t * facelet_to_merge)
{
    assert(facelet && facelet_to_merge);
#define _(TYPE, NAME) MERGE_ATTRIBUTE_REMOTE(TYPE, NAME);
    foreach_facelet_attr
#undef _
    facelet->event = facelet_to_merge->event;
    return 0;
}

int
facelet_get_face(const facelet_t * facelet, face_t ** pface)
{
    assert(pface);

    /* Facelet has all the required information to create a face */
    if (facelet_validate_face(facelet) < 0) {
        ERROR("[facelet_get_face] Face does not validate");
        return 0;
    }

    face_t * face = face_create();
    if (!face)
        goto ERR_CREATE;

    assert(facelet_has_netdevice(facelet));
    face->netdevice = facelet->netdevice;

    /* Face type */
    switch(facelet->face_type.layer) {
        case FACE_TYPE_LAYER_4:
            switch(facelet->face_type.encap) {
                case FACE_TYPE_ENCAP_UDP:
                    face->type = FACE_TYPE_UDP;
                    break;
                case FACE_TYPE_ENCAP_TCP:
                    face->type = FACE_TYPE_TCP;
                    break;
                case FACE_TYPE_ENCAP_UNDEFINED:
                case FACE_TYPE_ENCAP_N:
                    ERROR("[facelet_get_face] Unsupported face encapsulation");
                    goto ERR;
            }

            if (facelet_get_family(facelet, &face->family) < 0) {
                ERROR("[facelet_get_face] Error retrieving face family");
                goto ERR;
            }
            if (facelet_get_local_addr(facelet, &face->local_addr) < 0) {
                ERROR("[facelet_get_face] Error retrieving face local address");
                goto ERR;
            }
            if (facelet_get_local_port(facelet, &face->local_port) < 0) {
                ERROR("[facelet_get_face] Error retrieving face local port");
                goto ERR;
            }
            if (facelet_get_remote_addr(facelet, &face->remote_addr) < 0) {
                ERROR("[facelet_get_face] Error retrieving face remote address");
                goto ERR;
            }
            if (facelet_get_remote_port(facelet, &face->remote_port) < 0) {
                ERROR("[facelet_get_face] Error retrieving face remote port");
                goto ERR;
            }
            break;

        case FACE_TYPE_LAYER_3:
            ERROR("{facelet_get_face] hICN face not (yet) implemented");
            goto ERR;

        case FACE_TYPE_LAYER_UNDEFINED:
        case FACE_TYPE_LAYER_N:
            ERROR("[facelet_get_face] Unsupported face type");
            goto ERR;
    }

    if (facelet_has_admin_state(facelet)) {
        if (facelet_get_admin_state(facelet, &face->admin_state) < 0) {
            ERROR("[facelet_get_face] Error getting face admin state");
            goto ERR;
        }
    } else {
        face->admin_state = FACE_STATE_UP;
    }

    if (facelet_has_state(facelet)) {
        if (facelet_get_state(facelet, &face->state) < 0) {
            ERROR("[facelet_get_face] Error getting face state");
            goto ERR;
        }
    } else {
        face->state = FACE_STATE_UP;
    }

#ifdef WITH_POLICY
    /* Priority */
    if (facelet_has_priority(facelet)) {
        if (facelet_get_priority(facelet, &face->priority) < 0) {
            ERROR("[facelet_get_face] Error getting face priority");
            goto ERR;
        }
    } else {
        face->priority = 0;
    }

    /* Tags */

    /* - based on netdevice type */
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
    face->tags = tags;
#endif /* WITH_POLICY */

    *pface = face;

    return 0;

ERR:
    free(face);
ERR_CREATE:
    *pface = NULL;
    return -1;
}

facelet_status_t
facelet_get_status(const facelet_t * facelet)
{
    return facelet->status;
}

void
facelet_set_status(facelet_t * facelet, facelet_status_t status)
{
    facelet->status = status;
}

#define SET_ATTR_STATUS_CLEAN(TYPE, NAME)                       \
do {                                                            \
    if (facelet->NAME ## _status  == FACELET_ATTR_STATUS_DIRTY) \
        facelet->NAME ## _status = FACELET_ATTR_STATUS_CLEAN;   \
} while (0)

void
facelet_set_attr_clean(facelet_t * facelet)
{
#define _(TYPE, NAME) SET_ATTR_STATUS_CLEAN(TYPE, NAME);
    foreach_facelet_attr
#undef _
}

void
facelet_set_error(facelet_t * facelet, facelet_error_reason_t reason)
{
    facelet->error++;
    switch(reason) {
        case FACELET_ERROR_REASON_UNSPECIFIED_ERROR:
        case FACELET_ERROR_REASON_INTERNAL_ERROR:
        case FACELET_ERROR_REASON_PERMISSION_DENIED:
            if (facelet->error >= FACELET_MAX_ERRORS)
                facelet_set_status(facelet, FACELET_STATUS_IGNORED);
            break;
        case FACELET_ERROR_REASON_FORWARDER_OFFLINE:
            break;
        case FACELET_ERROR_REASON_UNDEFINED:
        case FACELET_ERROR_REASON_N:
            ERROR("facelet_set_error] Unexpected error reason");
            break;
    }
}

void
facelet_unset_error(facelet_t * facelet)
{
    facelet->error = 0;
}

bool
facelet_get_error(const facelet_t * facelet)
{
    return facelet->error;
}

void
facelet_set_bj_done(facelet_t * facelet)
{
    facelet->bj_done = true;
}

void
facelet_unset_bj_done(facelet_t * facelet)
{
    facelet->bj_done = false;
}

bool
facelet_is_bj_done(const facelet_t * facelet)
{
    return facelet->bj_done;
}

void
facelet_set_au_done(facelet_t * facelet)
{
    facelet->au_done = true;
}

bool
facelet_is_au_done(const facelet_t * facelet)
{
    return facelet->au_done;
}

facelet_event_t
facelet_get_event(const facelet_t * facelet)
{
    return facelet->event;
}

void
facelet_set_event(facelet_t * facelet, facelet_event_t event)
{
    facelet->event = event;
}

int
facelet_add_route(facelet_t * facelet, hicn_route_t * route)
{
    return route_set_add(facelet->routes, route);
}

int
facelet_remove_route(facelet_t * facelet, hicn_route_t * route, hicn_route_t ** route_removed)
{
    return route_set_remove(facelet->routes, route, route_removed);
}

int
facelet_clear_routes(facelet_t * facelet)
{
    return route_set_clear(facelet->routes);
}

int
facelet_get_route_array(const facelet_t * facelet, hicn_route_t *** route_array)
{
    return route_set_get_array(facelet->routes, route_array);
}

int
facelet_snprintf(char * s, size_t size, const facelet_t * facelet)
{
    char * cur = s;
    int rc;

    assert(facelet);

    /* Header + key attributes (netdevice + family) */
    rc = snprintf(cur, s + size - cur, "<Facelet [%d] %s %s (%s)",
            facelet->id,
            facelet_status_str[facelet->status],
            facelet_get_error(facelet) ? "/!\\" : "",
            (facelet->family == AF_INET) ? "AF_INET" :
            (facelet->family == AF_INET6) ? "AF_INET6" :
            (facelet->family == AF_UNSPEC) ? "AF_UNSPEC" :
            "unknown");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* Netdevice */
    if (facelet_has_netdevice(facelet)) {
        rc = snprintf(cur, s + size - cur, " netdevice=%s",
                facelet->netdevice.name[0] ? facelet->netdevice.name : "*");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = snprintf(cur, s + size - cur, "/%d", facelet->netdevice.index);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

    } else {
        rc = snprintf(cur, s + size - cur, " netdevice=*/*");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Netdevice type */
    if (facelet_has_netdevice_type(facelet)) {
        rc = snprintf(cur, s + size - cur, " type=%s",
                netdevice_type_str(facelet->netdevice_type));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Local ip address */
    if (facelet_has_local_addr(facelet)) {
        rc = snprintf(cur, s + size - cur, " local_addr=");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = ip_address_snprintf(cur, s + size - cur, &facelet->local_addr,
                facelet->family);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Local port */
    if (facelet_has_local_port(facelet)) {
        rc = snprintf(cur, s + size - cur, " local_port=%d",
                facelet->local_port);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Remote ip address */
    if (facelet_has_remote_addr(facelet)) {
        rc = snprintf(cur, s + size - cur, " remote_addr=");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = ip_address_snprintf(cur, s + size - cur, &facelet->remote_addr,
                facelet->family);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Remote port */
    if (facelet_has_remote_port(facelet)) {
        rc = snprintf(cur, s + size - cur, " remote_port=%d",
                facelet->remote_port);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Admin state */
    if (facelet_has_admin_state(facelet)) {
        rc = snprintf(cur, s + size - cur, " admin_state=%s",
                face_state_str(facelet->admin_state));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* State */
    if (facelet_has_state(facelet)) {
        rc = snprintf(cur, s + size - cur, " state=%s",
                face_state_str(facelet->state));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

#ifdef WITH_POLICY
    /* Priority */
    if (facelet_has_priority(facelet)) {
        rc = snprintf(cur, s + size - cur, " priority=%d", facelet->priority);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }
#endif /* WITH_POLICY */

    /* Face type */
    if (facelet_has_face_type(facelet)) {
        rc = snprintf(cur, s + size - cur, " face_type=LAYER%s/%s",
            FACEMGR_FACE_TYPE_STR(facelet->face_type));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Routes */
    rc = snprintf(cur, s + size - cur, " routes={ ");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    hicn_route_t ** route_array;
    int n = route_set_get_array(facelet->routes, &route_array);
    if (n < 0) {
        ERROR("[facelet_free] Error getting route set associated to facelet");
    } else {
        for (unsigned i = 0; i < n; i++) {
            hicn_route_t * route = route_array[i];
            rc = (int)hicn_route_snprintf(cur, s + size - cur, route);
            if (rc < 0)
                return rc;
            cur += rc;
            if (cur >= s + size)
                return (int)(cur - s);

            rc = snprintf(cur, s + size - cur, ", ");
            if (rc < 0)
                return rc;
            cur += rc;
            if (cur >= s + size)
                return (int)(cur - s);
        }
    }
    free(route_array);

    rc = snprintf(cur, s + size - cur, "}>");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    return (int)(cur - s);
}

int facelet_snprintf_json(char * s, size_t size, const facelet_t * facelet, int indent)
{
    char * cur = s;
    int rc;

    assert(facelet);

    /* Header + key attributes (netdevice + family) */
    rc = snprintf(cur, s + size - cur, "%*s%s", 4 * indent, "", "{\n");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* id */
    rc = snprintf(cur, s + size - cur, "%*s%s: %d,\n", 4 * (indent+1), "", "\"id\"",
            facelet->id);
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* Status */
    rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "", "\"status\"",
            facelet_status_str[facelet->status]);
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* Family */
    rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "", "\"family\"",
            (facelet->family == AF_INET) ? "AF_INET" :
            (facelet->family == AF_INET6) ? "AF_INET6" :
            (facelet->family == AF_UNSPEC) ? "AF_UNSPEC" :
            "unknown");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* Netdevice */
    if (facelet_has_netdevice(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "",
                "\"netdevice\"",
                facelet->netdevice.name[0] ? facelet->netdevice.name : "*");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

    } else {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "",
                "\"netdevice\"", "*");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Netdevice type */
    if (facelet_has_netdevice_type(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "",
                "\"netdevice_type\"",
                netdevice_type_str(facelet->netdevice_type));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Local ip address */
    if (facelet_has_local_addr(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"", 4 * (indent+1), "",
                "\"local_addr\"");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = ip_address_snprintf(cur, s + size - cur, &facelet->local_addr,
                facelet->family);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = snprintf(cur, s + size - cur, "\",\n");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Local port */
    if (facelet_has_local_port(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: %d,\n", 4 * (indent+1), "",
                "\"local_port\"",
                facelet->local_port);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Remote ip address */
    if (facelet_has_remote_addr(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"", 4 * (indent+1), "",
                "\"remote_addr\"");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = ip_address_snprintf(cur, s + size - cur, &facelet->remote_addr,
                facelet->family);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);

        rc = snprintf(cur, s + size - cur, "\",\n");
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Remote port */
    if (facelet_has_remote_port(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: %d,\n", 4 * (indent+1), "",
                "\"remote_port\"",
                facelet->remote_port);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Admin state */
    if (facelet_has_admin_state(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "",
                "\"admin_state\"",
                face_state_str(facelet->admin_state));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* State */
    if (facelet_has_state(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\",\n", 4 * (indent+1), "",
                "\"state\"",
                face_state_str(facelet->state));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

#ifdef WITH_POLICY
    /* Priority */
    if (facelet_has_priority(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: %d,\n", 4 * (indent+1), "",
                "\"priority\"", facelet->priority);
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }
#endif /* WITH_POLICY */

    if (facelet_has_face_type(facelet)) {
        rc = snprintf(cur, s + size - cur, "%*s%s: \"LAYER%s/%s\",\n", 4 * (indent+1), "",
                "\"face_type\"",
            FACEMGR_FACE_TYPE_STR(facelet->face_type));
        if (rc < 0)
            return rc;
        cur += rc;
        if (cur >= s + size)
            return (int)(cur - s);
    }

    /* Status error */
    rc = snprintf(cur, s + size - cur, "%*s%s: \"%s\"\n", 4 * (indent+1), "",
            "\"error\"",
            facelet_get_error(facelet) ? "true" : "false");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    /* Routes */
    // TODO

    rc = snprintf(cur, s + size - cur, "%*s%s", 4 * indent, "", "}");
    if (rc < 0)
        return rc;
    cur += rc;
    if (cur >= s + size)
        return (int)(cur - s);

    return (int)(cur - s);
}
