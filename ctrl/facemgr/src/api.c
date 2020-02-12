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

#ifdef __ANDROID__

/*
 * Use AndroidUtility to determine interface types
 *
 * NOTE: this is currently disabled as SDK APIs do not allow to determine the
 * type of interfaces that are DOWN
 */
//#define WITH_ANDROID_UTILITY

/*
 * Use priority controller interface
 */
#define WITH_PRIORITY_CONTROLLER

/*
 * Allow priority setting before interface is actually created
 */
#define WITH_DEFAULT_PRIORITIES

#endif /* __ANDROID__ */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <hicn/facemgr/api.h>
#include <hicn/facemgr/cfg.h>
#include <hicn/facemgr/facelet.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <hicn/util/set.h>

#ifdef __APPLE__
#include "interfaces/network_framework/network_framework.h"
#endif /* __APPLE__ */

#ifdef __linux__
#include "interfaces/bonjour/bonjour.h"
#endif /* __linux__ */

#ifdef WITH_ANDROID_UTILITY
#include "interfaces/android_utility/android_utility.h"
#endif /* WITH_ANDROID_UTILITY */

#include <hicn/ctrl/face.h>
#include <hicn/facemgr/facelet.h>
#include "common.h"
#include "facelet_array.h"
#include "interface.h"

#define RAND_NAME_LEN 5

#define DEFAULT_PORT 9695

#define DEFAULT_REATTEMPT_DELAY_MS 250
#define MAX_FDS 10

typedef struct {
    interface_t * interface;
    int fds[MAX_FDS];
    size_t num_fds;
} interface_map_data_t;

TYPEDEF_SET_H(facelet_set, facelet_t *);
TYPEDEF_SET(facelet_set, facelet_t *, facelet_cmp, facelet_snprintf);

TYPEDEF_MAP_H(interface_map, const char *, interface_map_data_t *);
TYPEDEF_MAP(interface_map, const char *, interface_map_data_t *, strcmp, string_snprintf, generic_snprintf);

TYPEDEF_MAP_H(bonjour_map, netdevice_t *, interface_t *);
TYPEDEF_MAP(bonjour_map, netdevice_t *, interface_t *, netdevice_cmp, generic_snprintf, generic_snprintf);

/* TODO automatically register interfaces */

#ifdef __APPLE__
extern interface_ops_t network_framework_ops;
#endif
#ifdef __linux__
extern interface_ops_t netlink_ops;
extern interface_ops_t bonjour_ops;
#endif
#ifdef WITH_ANDROID_UTILITY
extern interface_ops_t android_utility_ops;
#endif /* WITH_ANDROID_UTILITY */
#ifdef WITH_PRIORITY_CONTROLLER
extern interface_ops_t priority_controller_ops;
#endif
#ifdef WITH_EXAMPLE_DUMMY
extern interface_ops_t dummy_ops;
#endif
#ifdef WITH_EXAMPLE_UPDOWN
extern interface_ops_t updown_ops;
#endif
extern interface_ops_t hicn_light_ops;

int facemgr_on_event(facemgr_t * facemgr, facelet_t * facelet);

int
facemgr_overlay_snprintf(char * s, size_t size, const facemgr_overlay_t * overlay)
{
    return -1;
}

struct facemgr_s {
    /**************************************************/
    /* Configuration parameters (exposed through API) */

    facemgr_cfg_t * cfg;

#ifdef __ANDROID__
    /*
     * Those two pointers are needed to call java functions from the face
     * manager.
     */
    JavaVM *jvm;
#endif /* __ANDROID__ */

    /* Callback */
    facemgr_cb_t callback;
    void * callback_owner;

    /****************************/
    /* Internal data structures */

    /* Map of interfaces index by name */
    interface_map_t * interface_map;

    /* Faces under construction */
    facelet_set_t * facelet_cache;

    /* Static facelets */
    facelet_array_t * static_facelets;

#ifdef WITH_DEFAULT_PRIORITIES
    /* Default priorities */
    u32 default_priority[NETDEVICE_TYPE_N+1];
#endif /* WITH_DEFAULT_PRIORITIES */

    /********************************************************/
    /* Interfaces - Those should be fully replaced by a map */

    interface_t * hl;

#ifdef WITH_ANDROID_UTILITY
    interface_t * au; /* android_utility */
#endif /* WITH_ANDROID_UTILITY */

#ifdef WITH_PRIORITY_CONTROLLER
    interface_t * pc;
#endif

#ifdef __APPLE__
    interface_t * nf; /* network_framework */
#endif /* __APPLE__ */

#ifdef __linux__
    interface_t * nl; /* netlink */
    /*
     * We maintain a map of dynamically created bonjour interfaces, one for each
     * found netdevice
     */
    bonjour_map_t * bonjour_map;
#endif /* __linux__ */

#ifdef WITH_EXAMPLE_DUMMY
    interface_t * dummy;
#endif
#ifdef WITH_EXAMPLE_UPDOWN
    interface_t * updown;
#endif
    int timer_fd; /* Timer used for reattempts */

    int cur_static_id; /* Used to distinguish static faces (pre-incremented) */
};

int
facemgr_initialize(facemgr_t * facemgr)
{
    facemgr->interface_map = interface_map_create();
    if (!facemgr->interface_map) {
        ERROR("[facemgr_initialize] Error creating interface map");
        goto ERR_INTERFACE_MAP;
    }

    facemgr->facelet_cache = facelet_set_create();
    if (!facemgr->facelet_cache) {
        ERROR("[facemgr_initialize] Error creating interface map");
        goto ERR_FACE_CACHE_PENDING;
    }

    facemgr->static_facelets = facelet_array_create();
    if (!facemgr->static_facelets) {
        ERROR("[facemgr_initialize] Error creating interface map");
        goto ERR_STATIC;
    }

#ifdef __linux__
    facemgr->bonjour_map = bonjour_map_create();
    if (!facemgr->bonjour_map) {
        ERROR("[facemgr_initialize] Error creating bonjour map");
        goto ERR_BJ;
    }
#endif /* __linux */

    facemgr->cfg = facemgr_cfg_create();
    if (!facemgr->cfg) {
        ERROR("[facemgr_initialize] Error creating face manager configuration");
        goto ERR_CFG;
    }

    facemgr->timer_fd = 0;
    facemgr->cur_static_id = 0;

#ifdef WITH_DEFAULT_PRIORITIES

#define _(x) facemgr->default_priority[NETDEVICE_TYPE_ ## x] = 0;
foreach_netdevice_type
#undef _

#endif /* WITH_DEFAULT_PRIORITIES */

    return 0;

ERR_CFG:
#ifdef __linux__
    bonjour_map_free(facemgr->bonjour_map);
ERR_BJ:
#endif /* __linux__ */
    facelet_array_free(facemgr->static_facelets);
ERR_STATIC:
    facelet_set_free(facemgr->facelet_cache);
ERR_FACE_CACHE_PENDING:
    interface_map_free(facemgr->interface_map);
ERR_INTERFACE_MAP:
    return -1;
}

int
facemgr_finalize(facemgr_t * facemgr)
{
    int ret = 0;
    int rc;

    if (facemgr->timer_fd) {
        rc = facemgr->callback(facemgr->callback_owner,
                FACEMGR_CB_TYPE_UNREGISTER_TIMER, &facemgr->timer_fd);
        if (rc < 0) {
            ERROR("[facemgr_finalize] Error unregistering timer");
            ret = -1;
        }
        facemgr->timer_fd = 0;
    }

    interface_map_free(facemgr->interface_map);

    /* Free all facelets from cache */
    facelet_t ** facelet_array;
    int n = facelet_set_get_array(facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_finalize] Could not retrieve facelets in cache");
    } else {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * facelet = facelet_array[i];
            if (facelet_set_remove(facemgr->facelet_cache, facelet, NULL)) {
                ERROR("[facemgr_finalize] Could not purge facelet from cache");
            }
            facelet_free(facelet);
        }
        free(facelet_array);
    }

    facelet_set_free(facemgr->facelet_cache);

    /* Free all facelets from static array */
    for (unsigned i = 0; i < facelet_array_len(facemgr->static_facelets); i++) {
        facelet_t * facelet;
        if (facelet_array_get_index(facemgr->static_facelets, i, &facelet) < 0) {
            ERROR("[facemgr_cfg_finalize] Error getting facelet in array");
            continue;
        }
        if (facelet_array_remove_index(facemgr->static_facelets, i, NULL) < 0) {
            ERROR("[facemgr_finalize] Could not purge facelet from static array");
        }
        facelet_free(facelet);
    }

    facelet_array_free(facemgr->static_facelets);

#ifdef __linux__
    bonjour_map_free(facemgr->bonjour_map);
#endif /* __linux__ */

    interface_unregister_all();

    return ret;
}

AUTOGENERATE_CREATE_FREE(facemgr);

int
facemgr_set_config(facemgr_t * facemgr, facemgr_cfg_t * cfg)
{
    if (facemgr->cfg) {
        facemgr_cfg_free(facemgr->cfg);
    }
    facemgr->cfg = cfg;

    /* Populate the initial list of static facelets */
    facelet_t ** facelet_array;
    int n = facemgr_cfg_get_static_facelet_array(cfg, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_finalize] Could not retrieve static facelets from cfg");
    } else {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * facelet = facelet_dup(facelet_array[i]);
            facelet_set_status(facelet, FACELET_STATUS_UNDEFINED);
            facelet_set_attr_clean(facelet);
            if (facelet_array_add(facemgr->static_facelets, facelet)) {
                ERROR("[facemgr_finalize] Could not add static facelet to face manager");
            }
        }
    }

    return 0;
}

int facemgr_reset_config(facemgr_t * facemgr)
{
    assert(facemgr->cfg);
    facemgr_cfg_free(facemgr->cfg);
    facemgr->cfg = facemgr_cfg_create();
    if (!facemgr->cfg)
        return -1;
    return 0;
}

facemgr_t *
facemgr_create_with_config(facemgr_cfg_t * cfg)
{
    facemgr_t * facemgr = facemgr_create();
    if (!facemgr)
        return NULL;
    int rc = facemgr_set_config(facemgr, cfg);
    if (rc < 0) {
        free(facemgr);
        return NULL;
    }
    return facemgr;
}

/*
 * \brief Heuristics to determine face type based on name, until a better
 * solution is found
 */
netdevice_type_t
facemgr_get_netdevice_type(const facemgr_t * facemgr, const char * interface_name)
{
    if (strncmp(interface_name, "lo", 2) == 0) {
        return NETDEVICE_TYPE_LOOPBACK;
    }
    if ((strncmp(interface_name, "eth", 3) == 0) ||
            (strncmp(interface_name, "en", 2) == 0)) {
        /* eth* en* enx* */
        return NETDEVICE_TYPE_WIRED;
    }
    if (strncmp(interface_name, "wl", 2) == 0) {
        /* wlan* wlp* wlx* */
        return NETDEVICE_TYPE_WIFI;
    }
    if (strncmp(interface_name, "rmnet_ipa", 9) == 0) {
        /* Qualcomm IPA driver */
        return NETDEVICE_TYPE_UNDEFINED;
    }
    if ((strncmp(interface_name, "rmnet", 5) == 0) ||
            (strncmp(interface_name, "rev_rmnet", 9) == 0) ||
            (strncmp(interface_name, "ccmni", 5) == 0)) {
        /*
         * rmnet* (Qualcomm) ccmni* (MediaTek)
         */
        return NETDEVICE_TYPE_CELLULAR;
    }
    /* usb0 might be cellular (eg Zenfone2) */
    /* what about tethering */
    /* tun* dummy* ... */
    /* bnet* pan* hci* for bluetooth */
    return NETDEVICE_TYPE_UNDEFINED;
}

int facemgr_callback(facemgr_t * facemgr, interface_cb_type_t type, void * data);

int
facemgr_create_interface(facemgr_t * facemgr, const char * name, const char * type, void * cfg, interface_t ** pinterface)
{
    char rand_name[RAND_NAME_LEN+1];
    interface_t * interface;

    if (!name) {
        /*
         * We can manipulate the name on the stack as it will be strdup'ed by
         * interface_create
         */
        rand_str(rand_name, RAND_NAME_LEN);
        name = rand_name;
    }

    INFO("Creating interface %s [%s]...", name, type);
    interface = interface_create(name, type);
    if (!interface) {
        ERROR("Error creating interface %s [%s]", name, type);
        goto ERR_CREATE;
    }
    interface_set_callback(interface, facemgr, facemgr_callback);

    interface_map_data_t * interface_map_data = malloc(sizeof(interface_map_data_t));
    if (!interface_map_data)
        goto ERR_MAP_DATA;

    *interface_map_data = (interface_map_data_t) {
        .interface = interface,
        .fds = {0},
        .num_fds = 0,
    };

    if (interface_map_add(facemgr->interface_map, interface->name, interface_map_data) < 0)
        goto ERR_MAP_ADD;

    /*
     * This should be called _after_ the interface_map is initialized otherwise
     * it will be impossible to register fds from *_initialize
     */
    if (interface_initialize(interface, cfg) < 0) {
        ERROR("[facemgr_create_interface] Error initializing interface");
        goto ERR_INIT;
    }

    DEBUG("Interface %s created successfully.", name);
    if (pinterface)
        *pinterface = interface;
    return 0;


    //interface_finalize(interface);
ERR_INIT:
    interface_map_remove(facemgr->interface_map, interface->name, NULL);
ERR_MAP_ADD:
    free(interface_map_data);
ERR_MAP_DATA:
    interface_free(interface);
ERR_CREATE:
    if (pinterface)
        *pinterface = NULL;
    return -1;
}

int
facemgr_delete_interface(facemgr_t * facemgr, interface_t * interface)
{
    int rc;

    interface_map_data_t * interface_map_data = NULL;

    DEBUG("Removing interface %s", interface->name);
    rc = interface_map_remove(facemgr->interface_map, interface->name, &interface_map_data);
    if (rc < 0)
        return -1;

    if (!interface_map_data)
        return -1;

    for (unsigned i = 0; i < interface_map_data->num_fds; i++) {
        int fd = interface_map_data->fds[i];
        fd_callback_data_t fd_callback_data = {
            .fd = fd,
            .owner = facemgr,
            .callback = NULL,
            .data = NULL,
        };
        facemgr->callback(facemgr->callback_owner, FACEMGR_CB_TYPE_UNREGISTER_FD, &fd_callback_data);
        if (rc < 0)
            WARN("[facemgr_delete_interface] Error unregistering fd %d for interface", fd);
    }

    free(interface_map_data);

    interface_finalize(interface);
    interface_free(interface);

    return 0;
}

#ifdef __linux__
int facemgr_query_bonjour(facemgr_t * facemgr, netdevice_t * netdevice)
{
    interface_t * bj = NULL;

    int rc = bonjour_map_get(facemgr->bonjour_map, netdevice, &bj);
    if (rc < 0)
        return rc;

    if (!bj) {
        /* Create a new bonjour interface */
        bonjour_cfg_t bj_cfg = {
            .netdevice = *netdevice,
        };
        rc = facemgr_create_interface(facemgr, NULL, "bonjour", &bj_cfg, &bj);
        if (rc < 0) {
            ERROR("Error creating 'Bonjour' interface for '%s'\n", netdevice->name);
            return -1;
        }
    }

    DEBUG("sending event to bonjour interface");

    /* Send an event to the interface (GET ?) */
    // XXX error handling
    return interface_on_event(bj, NULL);
}
#endif /* __linux__ */

#ifdef WITH_ANDROID_UTILITY
int facemgr_query_android_utility(facemgr_t * facemgr, netdevice_t netdevice)
{
    /* Send an event to the interface */
    facelet_t * facelet = facelet_create();
    if (!facelet)
        goto ERR_MALLOC;

    int rc = facelet_set_netdevice(facelet, netdevice);
    if (rc < 0)
        goto ERR_ND;

    rc = interface_on_event(facemgr->au, facelet);
    if (rc < 0) {
        // XXX error handling
        goto ERR_EVENT;
    }

    return 0;

ERR_EVENT:
ERR_ND:
    facelet_free(facelet);
ERR_MALLOC:
    return -1;
}
#endif /* WITH_ANDROID_UTILITY */


/**
 * \brief Performs a cache lookup to find matching facelets
 * \param [in] facelet_cache - Facelet cache on which to perform lookup
 * \param [in] facelet - Facelet to lookup
 * \param [out] cached_facelet - Pointer used to return a newly allocated
 *      facelet array corresponding to the result of the cache lookup.
 * \return The number of entries in the array in case of success (positive
 *      value), or -1 in case of error.
 */
int
facelet_cache_lookup(const facelet_set_t * facelet_cache, facelet_t * facelet,
        facelet_t ***cached_facelets)
{
    assert(facelet);

    /* ...otherwise, we iterate over the facelet
     * cache to find matching elements.
     */
    facelet_t ** facelet_array;
    int n = facelet_set_get_array(facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facelet_cache_lookup] Error during cache match");
        return -1;
    }
    if (cached_facelets)
        *cached_facelets = malloc(n * sizeof(facelet_t*));

    int num_match = 0;
    for (unsigned i = 0; i < n; i++) {
#if 0
        char facelet_s[MAXSZ_FACELET];
        facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet_array[i]);
        DEBUG("cache entry #%d/%di = %s", i+1, n, facelet_s);
#endif
        if (!facelet_match(facelet_array[i], facelet)) {
            continue;
        }
        if (cached_facelets)
            (*cached_facelets)[num_match] = facelet_array[i];
        num_match++;
    }
    free(facelet_array);
    return num_match;
}


/**
 * \brief Checks whether the facelet satisfies face creation rules
 * \param [in] facemgr - Pointer to the face manager instance
 * \param [in] facelet - Pointer to the facelet to process
 * \return 0 in case of success, -2 if we don't have enough information to
 * decide, -3 if the face does not satisfy rules, and -1 in case of error
 */
int
facemgr_facelet_satisfy_rules(facemgr_t * facemgr, facelet_t * facelet)
{
    /* As key, netdevice and family should always be present */
    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_facelet_satisfy_rules] Error retrieving netdevice from facelet");
        return -1;
    }

    int family = AF_UNSPEC;
    if (facelet_has_family(facelet)) {
        if (facelet_get_family(facelet, &family) < 0) {
            ERROR("[facemgr_facelet_satisfy_rules] Error retrieving family from facelet");
            return -1;
        }
    }

    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
#ifndef WITH_ANDROID_UTILITY
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_facelet_satisfy_rules] Error retrieving netdevice_type from facelet");
        return -2;
    }
#endif /* WITH_ANDROID_UTILITY */

    /* Default ignore list */
    if ((netdevice_type == NETDEVICE_TYPE_LOOPBACK) || (netdevice_type == NETDEVICE_TYPE_UNDEFINED)) {
        DEBUG("Ignored interface '%s/%s'...", netdevice.name,
                netdevice_type_str[netdevice_type]);
        return -3;
    }

    /* Ignore */
    bool ignore;
    if (facemgr_cfg_get_ignore(facemgr->cfg, &netdevice, netdevice_type,
                &ignore) < 0)
        return -1;
    if (ignore) {
        DEBUG("Ignored interface '%s/%s'...", netdevice.name,
                netdevice_type_str[netdevice_type]);
        return -3;
    }

    switch(family) {
        case AF_INET:
        {
            bool ipv4;
            if (facemgr_cfg_get_ipv4(facemgr->cfg, &netdevice, netdevice_type,
                        &ipv4) < 0)
                return -1;
            if (!ipv4) {
                DEBUG("Ignored IPv4 facelet...");
                return -3;
            }
            break;
        }

        case AF_INET6:
        {
            bool ipv6;
            if (facemgr_cfg_get_ipv6(facemgr->cfg, &netdevice, netdevice_type,
                        &ipv6) < 0)
                return -1;
            if (!ipv6) {
                DEBUG("Ignored IPv6 facelet...");
                return -3;
            }
            break;
        }

        default:
            DEBUG("Ignored facelet with unknown family");
            return -2;
    }

    return 0;
}

#ifdef WITH_ANDROID_UTILITY
/**
 * \brief Complements facelet information through Android Utility interface
 * \return 0 if request was successful, -1 in case of error, and -2 if the
 *      interface is not applicable
 *
 * This function returnds _after_ completion.
 */
int
facemgr_complement_facelet_au(facemgr_t * facemgr, facelet_t * facelet)
{

    if (facelet_has_netdevice_type(facelet))
        return -2;

    if (facelet_is_au_done(facelet))
        return -2;

    netdevice_t netdevice = NETDEVICE_EMPTY;

    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_bj] Error retrieving netdevice from facelet");
        return -1;
    }

    DEBUG("Querying android utility...");

    /* /!\ Synchronous code here /!\ */
    if (facemgr_query_android_utility(facemgr, netdevice) < 0) {
        return -1;
    }

    facelet_set_au_done(facelet);
    return 0;
}
#endif /* WITH_ANDROID_UTILITY */

#ifdef __linux__
/**
 * \brief Complements facelet information through Bonjour interface.
 * \return 0 if request was successful, -1 in case of error, and -2 if the
 *      interface is not applicable
 *
 * This function returnds _before_ completion as bonjour querying is
 * asynchronous.
 */
int
facemgr_complement_facelet_bj(facemgr_t * facemgr, facelet_t * facelet)
{
    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_bj] Error retrieving netdevice from facelet");
        return -1;
    }

    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
#ifndef WITH_ANDROID_UTILITY
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_bj] Error retrieving netdevice_type from facelet");
        return -2;
    }
#endif /* WITH_ANDROID_UTILITY */

    bool discovery;
    if (facemgr_cfg_get_discovery(facemgr->cfg, &netdevice, netdevice_type,
                &discovery) < 0)
        return -2;

    DEBUG("Discovery: %s", discovery ? "ON" : "OFF");

    if (!discovery)
        return -2;

    facemgr_face_type_t face_type = FACEMGR_FACE_TYPE_UNDEFINED;
    if (facelet_get_face_type(facelet, &face_type) < 0) {
        ERROR("[facemgr_complement_facelet_bj] Error retrieving face type from facelet");
        return -1;
    }

    bool discovery_needed = (face_type.layer == FACE_TYPE_LAYER_4) &&
        ((!facelet_has_remote_addr(facelet)) || (!facelet_has_remote_port(facelet)));

    DEBUG("Discovery needed: %s", discovery ? "ON" : "OFF");

    if (!discovery_needed) {
        return -2;
    }

    if (!facelet_has_local_addr(facelet)) {
        DEBUG("No discovery possible without local address");
        return -2;
    }

    if (facelet_is_bj_done(facelet)) {
        DEBUG("Bonjour already queried");
        return -2;
    }

    facelet_set_bj_done(facelet);
    return facemgr_query_bonjour(facemgr, &netdevice);
}
#endif /* __linux__ */

/**
 * \brief Complements facelet information through Manual settings.
 * \return 0 if request was successful, -1 in case of error, and -2 if the
 *      interface is not applicable
 *
 * This function returnds _before_ completion as bonjour querying is
 * asynchronous.
 */
int
facemgr_complement_facelet_manual(facemgr_t * facemgr, facelet_t * facelet)
{

    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error retrieving netdevice from facelet");
        return -1;
    }

    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
#ifndef WITH_ANDROID_UTILITY
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error retrieving netdevice_type from facelet");
        return -2;
    }
#endif /* WITH_ANDROID_UTILITY */

    int family = AF_UNSPEC;
    if (facelet_has_family(facelet)) {
        if (facelet_get_family(facelet, &family) < 0) {
            ERROR("[facemgr_complement_facelet_manual] Error retrieving family from facelet");
            return -1;
        }
    }

    /* Do not query manual is there is a change to go through bonjour */
    bool discovery;
    if (facemgr_cfg_get_discovery(facemgr->cfg, &netdevice, netdevice_type,
                &discovery) < 0)
        return -2;

    facemgr_face_type_t face_type = FACEMGR_FACE_TYPE_UNDEFINED;
    if (facelet_get_face_type(facelet, &face_type) < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error retrieving face type from facelet");
        return -1;
    }

#if 0 /* Wrong if we need to complement local addr / port */
    bool discovery_needed = (face_type.layer == FACE_TYPE_LAYER_4) &&
        ((!facelet_has_remote_addr(facelet)) || (!facelet_has_remote_port(facelet)));

    if (!discovery_needed) {
        DEBUG("manual settings not considered as no discovery is needed");
        return -2;
    }
#endif

    if (discovery && !facelet_is_bj_done(facelet)) {
        DEBUG("manual settings not considered as discovery is enabled and Bonjour has not yet been done");
        return -2;
    }

    DEBUG("Applying manual settings...");
    /*
     * Manual overlay specification (remote addr/port)
     * We never override a result we have obtained through bonjour
     */
    if (!facelet_has_remote_addr(facelet)) {
        ip_address_t remote_addr;
        if (facemgr_cfg_get_overlay_remote_addr(facemgr->cfg,
                &netdevice, netdevice_type, family, &remote_addr) < 0) {
            ERROR("[facemgr_complement_facelet_manual] Error getting remote addr information from cfg");
            return -1;
        }
        if (ip_address_empty(&remote_addr)) {
            ERROR("[facemgr_complement_facelet_manual] Got empty remote addr information from cfg");
        } else {
            DEBUG(" - remote address");
            facelet_set_remote_addr(facelet, remote_addr);
        }
    }

    if (!facelet_has_remote_port(facelet)) {
        uint16_t remote_port;
        int rc = facemgr_cfg_get_overlay_remote_port(facemgr->cfg,
                &netdevice, netdevice_type, family, &remote_port);
        if (rc < 0) {
            ERROR("[facemgr_complement_facelet_manual] Error getting remote port information from cfg");
            return -1;
        }
        DEBUG(" - remote port");
        facelet_set_remote_port(facelet, remote_port);
    }

    /*
     * Complementing local addr/port XXX this should be done somewhere
     * else : manual settings have the lowest priority
     *
     * Local IP address is specific as it allows to override the source
     * address just before creating the face... we would need to check
     * whether this is an address that belong to us... it might be used
     * to arbitrate amongst several IP addresses instead...
     */
    ip_address_t local_addr;
    if (facemgr_cfg_get_overlay_local_addr(facemgr->cfg, &netdevice,
            netdevice_type, family, &local_addr) < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error getting local addr information from cfg");
        return -1;
    }
    if (ip_address_empty(&local_addr)) {
        ERROR("[facemgr_complement_facelet_manual] Got empty local addr information from cfg");
    } else {
        DEBUG(" - local addres");
        facelet_set_local_addr(facelet, local_addr);
    }

    /* Sets a default local port, so far nobody sets it */
    uint16_t local_port;
    if (facemgr_cfg_get_overlay_local_port(facemgr->cfg,
            &netdevice, netdevice_type, family, &local_port) < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error getting local port information from cfg");
        return -1;
    }
    DEBUG(" - local port");
    facelet_set_local_port(facelet, local_port);
    return 0;
}

int
facemgr_complement_facelet(facemgr_t * facemgr, facelet_t * facelet)
{
    int rc;

    DEBUG("[facemgr_complement_facelet]");
    if (!facelet_has_key(facelet))
        return -2;

#ifdef WITH_ANDROID_UTILITY
    rc = facemgr_complement_facelet_au(facemgr, facelet);
    if (rc != -2)
        return rc;
#endif /* WITH_ANDROID_UTILITY */

#if 0
    if (!facelet_has_netdevice_type(facelet)) {
        netdevice_t netdevice = NETDEVICE_EMPTY;
        rc = facelet_get_netdevice(facelet, &netdevice);
        if (rc < 0) {
            ERROR("[facemgr_complement_facelet] Error retrieving netdevice from facelet");
            return -1;
        }
        facelet_set_netdevice_type(facelet, facemgr_get_netdevice_type(facemgr, netdevice.name));
    }
#endif

    /* We continue only if the current call was not applicable. In the current
     * setting we have no interface that can be requested in parallel, and no
     * need to. This might evolve in future releases.
     */

#ifdef __linux__
    rc = facemgr_complement_facelet_bj(facemgr, facelet);
    if (rc != -2)
        return rc;
#endif /* __linux__ */

    DEBUG("[facemgr_complement_facelet] Complement manual");

    rc = facemgr_complement_facelet_manual(facemgr, facelet);
    if (rc != -2)
        return rc;

    INFO("[facemgr_complement_facelet] No more interfaces to query... incomplete face");
    return 0;
}

int facemgr_assign_face_type(facemgr_t * facemgr, facelet_t * facelet)
{
    DEBUG("[facemgr_assign_face_type]");
    /* As key, netdevice and family should always be present */
    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_assign_face_type] Error retrieving netdevice from facelet");
        return -1;
    }

    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
#ifndef WITH_ANDROID_UTILITY
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_assign_face_type] Error retrieving netdevice_type from facelet");
        return -2;
    }
#endif /* WITH_ANDROID_UTILITY */

    facemgr_face_type_t face_type = FACEMGR_FACE_TYPE_UNDEFINED;
    if (facemgr_cfg_get_face_type(facemgr->cfg, &netdevice, netdevice_type, &face_type) < 0)
        return rc;
    facelet_set_face_type(facelet, face_type);
    DEBUG("[facemgr_assign_face_type] %s", FACEMGR_FACE_TYPE_STR(face_type));
    return 0;
}

/*
 * This function performs one step of the state machine associated to the
 * facelet, from initial creation, to synchronization with the forwarder.
 *
 * We assume the facelet is already present in the cache
 */
int
facemgr_process_facelet(facemgr_t * facemgr, facelet_t * facelet)
{
    int rc;
    facelet_error_reason_t reason = FACELET_ERROR_REASON_INTERNAL_ERROR;

    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
            /*
             * All new faces are marked UNCERTAIN. We need to check whether we
             * have sufficient information to check rules, if not proceed,
             * otherwise possibly mark the face as IGNORED. Otherwise, we verify
             * the completeness of the information we have, and continue towards
             * being able to mark the face as CREATE.
             */
            rc = facemgr_facelet_satisfy_rules(facemgr, facelet);
            switch(rc) {
                case -3:
                    /* Does not satisfy rules */
                    DEBUG("[facemgr_process_facelet] Does not satisfy rules");
                    facelet_set_status(facelet, FACELET_STATUS_IGNORED);
                    return 0;

                case -2:
                    DEBUG("[facemgr_process_facelet] Complementing facelet is required");
                    if (facemgr_complement_facelet(facemgr, facelet) < 0) {
                        ERROR("[facemgr_process_facelet] Error while attempting to complement face for fields required by face creation");
                        goto ERR;
                    }
                    return 0;

                case 0:
                    /* Ok pass rules */
                    break;

                default:
                    /* -1 - Error */
                    goto ERR;
            }

            if (facemgr_assign_face_type(facemgr, facelet) < 0) {
                ERROR("[facemgr_process_facelet] Could not assign face type");
                goto ERR;
            }
            facelet_set_status(facelet, FACELET_STATUS_INCOMPLETE);
            /* Continue in case facelet satisfies rules */

        case FACELET_STATUS_INCOMPLETE:
            if (!facelet_validate_face(facelet)) {
                /* We need additional information */
                if (facemgr_complement_facelet(facemgr, facelet) < 0) {
                    ERROR("[facemgr_process_facelet] Error while attempting to complement face for fields required by face creation");
                    goto ERR;
                }
            }
            if (!facelet_validate_face(facelet))
                return 0;

            facelet_set_status(facelet, FACELET_STATUS_CREATE);
            /* Continue in case we need to proceed to creation */

        case FACELET_STATUS_CREATE:
            facelet_set_event(facelet, FACELET_EVENT_CREATE);
            rc = interface_on_event(facemgr->hl, facelet);
            if (rc < 0) {
                ERROR("[facemgr_process_facelet] Failed to create face");
                reason = -rc;
                goto ERR;
            }

            /* This works assuming the call to hicn-light is blocking */
            facelet_set_status(facelet, FACELET_STATUS_CLEAN);
            break;


        case FACELET_STATUS_UPDATE:
            facelet_set_event(facelet, FACELET_EVENT_UPDATE);
            rc = interface_on_event(facemgr->hl, facelet);
            if (rc < 0) {
                ERROR("[facemgr_process_facelet] Failed to update face");
                reason = -rc;
                goto ERR;
            }

            /* This works assuming the call to hicn-light is blocking */
            facelet_set_status(facelet, FACELET_STATUS_CLEAN);
            break;

        case FACELET_STATUS_DELETE:
            facelet_set_event(facelet, FACELET_EVENT_DELETE);
            rc = interface_on_event(facemgr->hl, facelet);
            if (rc < 0) {
                ERROR("[facemgr_process_facelet] Failed to delete face");
                reason = -rc;
                goto ERR;
            }

#if 0
            if (facelet_get_id(facelet) > 0) {
                if (facelet_set_remove(facemgr->facelet_cache, facelet, NULL) < 0) {
                    ERROR("[facemgr_process_facelet] Could not remove deleted facelet from cache");
                    return -1;
                }
                facelet_free(facelet);
            } else {
#endif
                /* This works assuming the call to hicn-light is blocking */
                DEBUG("[facemgr_process_facelet] Cleaning cached data");
                facelet_unset_local_addr(facelet);
                facelet_unset_local_port(facelet);
                if (facelet_get_id(facelet) == 0) {
                    facelet_unset_remote_addr(facelet);
                    facelet_unset_remote_port(facelet);
                    facelet_clear_routes(facelet);
                }

                facelet_unset_admin_state(facelet);
                facelet_unset_state(facelet);
                facelet_unset_bj_done(facelet);
#ifdef WITH_ANDROID_UTILITY
                facelet_unset_au_done(facelet);
#endif /* WITH_ANDROID_UTILITY */

                facelet_set_status(facelet, FACELET_STATUS_DELETED);
#if 0
            }
#endif
            break;

        case FACELET_STATUS_CLEAN:
        case FACELET_STATUS_IGNORED:
        case FACELET_STATUS_DOWN:
        case FACELET_STATUS_DELETED:
            /* Nothing to do */
            break;

        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet] Unexpected facelet status");
            goto ERR;
    }

    facelet_unset_error(facelet);
    return 0;

ERR:
    facelet_set_error(facelet, reason);
    return -1;
}

int
facemgr_reattempt_timeout(facemgr_t * facemgr, int fd, void * data)
{
    bool has_error = false;

    assert(data == NULL);

    /* Free all facelets from cache */
    facelet_t ** facelet_array;
    int n = facelet_set_get_array(facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_reattempt_timeout] Could not retrieve facelets in cache");
        has_error = true;
    } else {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * facelet = facelet_array[i];

            if (!facelet_get_error(facelet))
                continue;

            char buf[MAXSZ_FACELET];
            facelet_snprintf(buf, MAXSZ_FACELET, facelet);
            DEBUG("Reattempt to process failed facelet %s", buf);
            if (facemgr_process_facelet(facemgr, facelet) < 0) {
                ERROR("[facemgr_reattempt_timeout] Error processing facelet");
                has_error = true;
                continue;
            }
            facelet_unset_error(facelet);
        }
        free(facelet_array);
    }

    if (has_error)
        return 0;

    DEBUG("Cancelling timer");
    if (facemgr->callback(facemgr->callback_owner,
            FACEMGR_CB_TYPE_UNREGISTER_TIMER, &facemgr->timer_fd) < 0) {
        ERROR("[facemgr_reattempt_timeout] Error unregistering reattempt timer");
        return -1;
    }
    facemgr->timer_fd = 0;
    return 0;
}

int
facemgr_start_reattempts(facemgr_t * facemgr)
{
    if (facemgr->timer_fd > 0)
        return 0;

    timer_callback_data_t timer_callback = {
        .delay_ms = DEFAULT_REATTEMPT_DELAY_MS,
        .owner = facemgr,
        .callback = (fd_callback_t)facemgr_reattempt_timeout,
        .data = NULL,
    };
    facemgr->timer_fd = facemgr->callback(facemgr->callback_owner,
            FACEMGR_CB_TYPE_REGISTER_TIMER, &timer_callback);
    return (facemgr->timer_fd > 0);
}

/**
 * \brief Process facelet CREATE event
 * \param [in] facemgr - Pointer to the face manager instance
 * \param [in] facelet - Pointer to the facelet event to process
 * \return 0 if everything went correctly, or -1 in case of error.
 *         -2 means we ignored the face purposedly
 */
int
facemgr_process_facelet_create(facemgr_t * facemgr, facelet_t * facelet)
{
    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet); 
    DEBUG("[facemgr_process_facelet_create] %s", facelet_s);
    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
        case FACELET_STATUS_INCOMPLETE:
        case FACELET_STATUS_CREATE:
            /* No change */
            DEBUG("[facemgr_process_facelet_create] UNCHANGED STATUS");
            break;
        case FACELET_STATUS_UPDATE:
        case FACELET_STATUS_DELETE:
            /*
             * Unlikely. The face had been created and is planned to
             * be deleted. Schedule for creation (we should have all
             * needed information), but make sure to handle errors
             * correctly if the face is still present.
             * TODO What if some fields have been updated ?
             */
            DEBUG("[facemgr_process_facelet_create] SET STATUS TO CREATE");
            facelet_set_status(facelet, FACELET_STATUS_CREATE);
            break;
        case FACELET_STATUS_CLEAN:
        case FACELET_STATUS_IGNORED:
            /*
             * We should have nothing to do unless some fields have
             * been updated.
             */
            DEBUG("[facemgr_process_facelet_create] NOTHING TO DO");
            break;

        case FACELET_STATUS_DOWN:
        case FACELET_STATUS_DELETED:
            /*
             * Unless rules have changed, we only need to recover
             * missing information, and proceed to face creation.
             * Rule changes should be handled separately.
             */
            DEBUG("[facemgr_process_facelet_create] SET STATUS TO INCOMPLETE");
            facelet_set_status(facelet, FACELET_STATUS_INCOMPLETE);
            break;
        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_create] Unexpected facelet status");
            return -1;
    }


    DEBUG("[facemgr_process_facelet_create] Processing facelet");
    if (facemgr_process_facelet(facemgr, facelet) < 0) {
        ERROR("[facemgr_process_facelet_create] Error processing facelet");
        return -1;
    }

    return 0;
}

/*
 * \return 0 in case of success and no static facelet was added, 1 if a static
 * facelet was added, and -1 in case of error.
 */
int
facemgr_consider_static_facelet(facemgr_t * facemgr, facelet_t * facelet)
{
    /*
     * We need to analyze the facelet and eventually:
     *  - add it in our static list
     *  - replicate it on multipath interfaces
     */
    netdevice_type_t netdevice_type;
    if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0)
        return -1;

    if ((netdevice_type == NETDEVICE_TYPE_UNDEFINED) ||
            (netdevice_type == NETDEVICE_TYPE_LOOPBACK))
        return 0;

    if ((facelet_get_route_array(facelet, NULL) == 0))
        return 0;

    /*
     * How to differenciate facelet created by face manager from user
     * created ones ? This cannot be a flag in the facelet as it needs
     * to work across restarts of the face manager...
     * Also we might have two default routes.
     *
     * TODO:
     * - The static one should not be a duplicate of the one we would
     * create by default....
     * - This should anyways be detected...
     *
     * One solution would be to install the default ones as static but
     * this requires to implement a priority scheme between some of the
     * static routes so that the override mechanism continues to work as
     * usual.
     *
     * Current, we recognize the routes created by default by the face
     * maanger thanks to the routing prefixes (a single default route).
     */

    facelet_t * static_facelet = facelet_dup(facelet);
    facelet_set_event(static_facelet, FACELET_EVENT_CREATE);
    facelet_unset_netdevice(static_facelet);
    facelet_unset_netdevice_type(static_facelet);
    facelet_unset_local_addr(static_facelet);
    facelet_unset_local_port(static_facelet);

    facelet_t * facelet_found = NULL;
    if (facelet_array_get(facemgr->static_facelets, static_facelet, &facelet_found) < 0) {
        ERROR("[facemgr_consider_static_facelet] Error checking whether static facelet already exists or not");
        return -1;
    }

    /* Skip addition if facelet exists */
    if (facelet_found)
        return 0;

    facemgr->cur_static_id++;

    facelet_set_id(static_facelet, facemgr->cur_static_id);
    facelet_set_id(facelet, facemgr->cur_static_id);

    if (facelet_array_add(facemgr->static_facelets, static_facelet) < 0) {
        ERROR("[facemgr_consider_static_facelet] Could not add facelet to static array");
        facelet_free(static_facelet);
        return -1;
    }

    char facelet_s[MAXSZ_FACELET];
    int rc = facelet_snprintf(facelet_s, MAXSZ_FACELET, static_facelet);
    if (rc >= MAXSZ_FACELET)
        ERROR("[facemgr_consider_static_facelet] Unexpected truncation of facelet string");
    if (rc < 0)
        ERROR("[facemgr_consider_static_facelet] Error during facelet string output");
    DEBUG("[facemgr_consider_static_facelet] Successfully added facelet to static array %s", facelet_s);

#if 1
    /* Force application of the static face on all existing interfaces */
    facelet_t ** facelet_array;
    int n = facelet_set_get_array(facemgr->facelet_cache, &facelet_array);
    if (n >= 0) {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * cached_facelet = facelet_array[i];

            netdevice_type_t netdevice_type;
            if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
                ERROR("[facemgr_consider_static_facelet] Error retrieving netdevice type from cached facelet");
                continue;
            }
            if ((netdevice_type == NETDEVICE_TYPE_LOOPBACK) || (netdevice_type == NETDEVICE_TYPE_UNDEFINED))
                continue;

            facelet_t * new_facelet = facelet_dup(cached_facelet);
            facelet_unset_remote_addr(new_facelet);
            facelet_unset_remote_port(new_facelet);
            facelet_unset_admin_state(new_facelet);
            facelet_unset_state(new_facelet);
            facelet_unset_bj_done(new_facelet);
            facelet_clear_routes(new_facelet);
#ifdef WITH_ANDROID_UTILITY
            facelet_unset_au_done(new_facelet);
#endif /* WITH_ANDROID_UTILITY */

            /* We try to apply static_facelet over facelet */
            if (!facelet_match(new_facelet, static_facelet)) {
                facelet_free(new_facelet);
                continue;
            }

            if (facelet_merge(new_facelet, static_facelet) < 0) {
                ERROR("[facemgr_consider_static_facelet] Error merging facelets");
                facelet_free(new_facelet);
                continue;
            }

            /*
             * We need to set the id before checking for existence as tuple used
             * is (id, netdevice, family)
             */
            facelet_set_id(new_facelet, facemgr->cur_static_id);

            facelet_found = NULL;
            if (facelet_set_get(facemgr->facelet_cache, new_facelet, &facelet_found) < 0) {
                ERROR("[facemgr_consider_static_facelet] Error checking whether new static facelet already exists or not");
                continue;
            }


            /* Skip addition if facelet exists */
            if (facelet_found) {
                facelet_free(new_facelet);
                continue;
            }

            facelet_set_attr_clean(new_facelet);
            facelet_set_status(facelet, FACELET_STATUS_UNDEFINED);

            if (facemgr_on_event(facemgr, new_facelet) < 0) {
                ERROR("[facemgr_process_facelet_create_no_family] Error creating static facelet for existing face");
                continue;
            }

            INFO("Successfully created static facelet for existing face");
        }
        free(facelet_array);
    }
#endif

    return 1;
}

/**
 * \brief Process facelet GET event
 * \param [in] facemgr - Pointer to the face manager instance
 * \param [in] facelet - Pointer to the facelet event to process
 * \return 0 if everything went correctly, or -1 in case of error.
 *         -2 means we ignored the face purposedly
 */
int
facemgr_process_facelet_get(facemgr_t * facemgr, facelet_t * facelet)
{
    assert(facelet);

    if (!facelet_has_netdevice(facelet))
        return -2;

    netdevice_t netdevice;
    if (facelet_get_netdevice(facelet, &netdevice) < 0)
        return -1;
    if (!IS_VALID_NETDEVICE(netdevice))
        return -2;

    facelet_set_status(facelet, FACELET_STATUS_CLEAN);

    /* Skip if face exists */
    int n = facelet_cache_lookup(facemgr->facelet_cache, facelet, NULL);
    if (n < 0) {
        ERROR("[facemgr_process_facelet_get] Error during cache lookup");
        return -1;
    }
    assert (n <= 1);
    if (n > 0)
        return 0;

    /* Process untagged faces */
    netdevice_type_t netdevice_type;
    if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
        facelet_set_netdevice_type(facelet, facemgr_get_netdevice_type(facemgr, netdevice.name));
        if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
            /* Inspect local address */
            int family;
            ip_address_t local;
            if (facelet_get_family(facelet, &family) < 0) {
                ERROR("[facemgr_process_facelet_get] Error getting facelet family");
                return -1;
            }
            if (facelet_get_local_addr(facelet, &local) < 0) {
                ERROR("[facemgr_process_facelet_get] Error getting facelet local address");
                return -1;
            }
            switch(family) {
                case AF_INET:
                    if (ip_address_cmp(&local, &IPV4_LOOPBACK, family) == 0) {
                        facelet_set_netdevice_type(facelet, NETDEVICE_TYPE_LOOPBACK);
                    } else {
                        return -2;
                    }
                    break;
                case AF_INET6:
                    if (ip_address_cmp(&local, &IPV6_LOOPBACK, family) == 0) {
                        facelet_set_netdevice_type(facelet, NETDEVICE_TYPE_LOOPBACK);
                    } else {
                        return -2;
                    }
                    break;
                default:
                    return -2;
            }
        }

        if ((netdevice_type == NETDEVICE_TYPE_UNDEFINED) || (netdevice_type == NETDEVICE_TYPE_LOOPBACK))
            return 0;

        if (facemgr_process_facelet(facemgr, facelet) < 0) {
            ERROR("[facemgr_process_facelet_get] Error processing facelet");
            return -1;
        }
    }

    if ((netdevice_type == NETDEVICE_TYPE_UNDEFINED) || (netdevice_type == NETDEVICE_TYPE_LOOPBACK))
        return 0;

    if (facelet_set_add(facemgr->facelet_cache, facelet) < 0) {
        ERROR("[facemgr_process_facelet_get] Error adding received facelet to cache");
        return -1;
    }

    n = facemgr_consider_static_facelet(facemgr, facelet);
    if (n < 0) {
        ERROR("[facemgr_process_facelet_get] Could not add facelet to static array");
        return -1;
    }


    return 0;
}

/**
 * \brief Process facelet UPDATE event
 * \param [in] facemgr - Pointer to the face manager instance
 * \param [in] facelet - Pointer to the facelet event to process
 * \return 0 if everything went correctly, or -1 in case of error.
 *         -2 means we ignored the face purposedly
 */
int
facemgr_process_facelet_update(facemgr_t * facemgr, facelet_t * facelet)
{
    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet);
    DEBUG("[facemgr_process_facelet_update] %s", facelet_s);
    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
        case FACELET_STATUS_INCOMPLETE:
        case FACELET_STATUS_CREATE:
        case FACELET_STATUS_UPDATE:
            /* No change */
            DEBUG("[facemgr_process_facelet_update] UNCHANGED STATUS");
            break;
        case FACELET_STATUS_CLEAN:
            DEBUG("[facemgr_process_facelet_update] SET STATUS TO UPDATE");
            facelet_set_status(facelet, FACELET_STATUS_UPDATE);
            break;
        case FACELET_STATUS_DOWN:
        case FACELET_STATUS_DELETE:
        case FACELET_STATUS_DELETED:
        case FACELET_STATUS_IGNORED:
            /* Reconsider face creation in light of new information */
            DEBUG("[facemgr_process_facelet_update] SET STATUS TO UNCERTAIN");
            facelet_set_status(facelet, FACELET_STATUS_UNCERTAIN);
            break;
        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_update] Unexpected facelet status");
            return -1;
    }

    DEBUG("[facemgr_process_facelet_update] Processing facelet");
    if (facemgr_process_facelet(facemgr, facelet) < 0) {
        ERROR("[facemgr_process_facelet_update] Error processing facelet");
        return -1;
    }

    return 0;
}

/**
 * \brief Process facelet DELETE event
 * \param [in] facemgr - Pointer to the face manager instance
 * \param [in] facelet - Pointer to the facelet event to process
 * \return 0 if everything went correctly, or -1 in case of error.
 *         -2 means we ignored the face purposedly
 */
int
facemgr_process_facelet_delete(facemgr_t * facemgr, facelet_t * facelet)
{
    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
        case FACELET_STATUS_INCOMPLETE:
        case FACELET_STATUS_IGNORED:
        case FACELET_STATUS_DOWN:
        case FACELET_STATUS_CREATE:
#if 0
            /* Facelets created from static get deleted */
            if (facelet_get_id(facelet) > 0) {
                if (facelet_set_remove(facemgr->facelet_cache, facelet, NULL) < 0) {
                    ERROR("[facemgr_process_facelet] Could not remove deleted facelet from cache");
                    return -1;
                }
                facelet_free(facelet);
            } else {
#endif
                /* Face has not been created */
                DEBUG("[facemgr_process_facelet] Cleaning cached data");
                facelet_unset_local_addr(facelet);
                facelet_unset_local_port(facelet);
                if (facelet_get_id(facelet) == 0) {
                    facelet_unset_remote_addr(facelet);
                    facelet_unset_remote_port(facelet);
                    facelet_clear_routes(facelet);
                }
                facelet_unset_admin_state(facelet);
                facelet_unset_state(facelet);
                facelet_unset_bj_done(facelet);
#ifdef WITH_ANDROID_UTILITY
                facelet_unset_au_done(facelet);
#endif /* WITH_ANDROID_UTILITY */
                facelet_unset_error(facelet);
                facelet_set_status(facelet, FACELET_STATUS_DELETED);
#if 0
            }
#endif
            break;

        case FACELET_STATUS_UPDATE:
        case FACELET_STATUS_CLEAN:
            facelet_set_status(facelet, FACELET_STATUS_DELETE);
            if (facemgr_process_facelet(facemgr, facelet) < 0) {
                ERROR("[facemgr_process_facelet_delete] Error processing facelet");
                return -1;
            }
            break;

        case FACELET_STATUS_DELETE:
        case FACELET_STATUS_DELETED:
            /* Nothing to do */
            break;

        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_delete] Unexpected facelet status");
            return -1;
    }

    return 0;
}

int
facemgr_process_facelet_create_no_family(facemgr_t * facemgr, facelet_t * facelet)
{

#ifdef WITH_DEFAULT_PRIORITIES
    /* Assign default priority based on face type */
    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
    if (facelet_get_netdevice_type(facelet, &netdevice_type) < 0) {
        ERROR("[facemgr_process_facelet_create_no_family] Error getting netdevice_type: no default priority set.");
        goto ERR_PRIORITY;
    }
    if (facelet_set_priority(facelet, facemgr->default_priority[netdevice_type]) < 0) {
        ERROR("[facemgr_process_facelet_create_no_family] Error setting default priority");
    }
ERR_PRIORITY:
#endif /* WITH_DEFAULT_PRIORITIES */

    DEBUG("[facemgr_process_facelet_create_no_family] Default v4");
    /* Create default v4 and v6 facelets */
    facelet_t * facelet_v4 = facelet_dup(facelet);
    if (!facelet_v4) {
        ERROR("[facemgr_process_facelet_create_no_family] Error allocating default IPv4 face");
    } else {
        facelet_set_family(facelet_v4, AF_INET);
        facelet_set_attr_clean(facelet_v4);
        if (facemgr_on_event(facemgr, facelet_v4) < 0) {
            ERROR("[facemgr_process_facelet_create_no_family] Error creating default IPv4 face");
            //facelet_free(facelet_v4);
        }
    }

    DEBUG("[facemgr_process_facelet_create_no_family] Default v6");
    facelet_t * facelet_v6 = facelet_dup(facelet);
    if (!facelet_v6) {
        ERROR("[facemgr_process_facelet_create_no_family] Error allocating default IPv6 face");
    } else {
        facelet_set_family(facelet_v6, AF_INET6);
        facelet_set_attr_clean(facelet_v6);
        if (facemgr_on_event(facemgr, facelet_v6) < 0) {
            ERROR("[facemgr_process_facelet_create_no_family] Error creating default IPv6 face");
            //facelet_free(facelet_v6);
        }
    }

    /* Create additional connections
     *
     * This is where we spawn multiple facelets based on the
     * configured "static routes" in addition to the default
     * routes managed by the face manager.
     */
    DEBUG("[facemgr_process_facelet_create_no_family] Loop static");
    for (unsigned i = 0; i < facelet_array_len(facemgr->static_facelets); i++) {
        facelet_t * static_facelet;
        if (facelet_array_get_index(facemgr->static_facelets, i, &static_facelet) < 0) {
            ERROR("[facemgr_process_facelet_create_no_family] Error getting static facelet");
            continue;
        }

        /*
         * We don't enforce any present or absent fields. A match
         * operation will be performed deciding whether to create
         * the facelet (if it bring additional information to the
         * ingress one) or not.
         */
        /* We try to apply static_facelet over facelet */
        if (!facelet_match(facelet, static_facelet)) {
            continue;
        }

        facelet_t * facelet_new = facelet_dup(facelet);
        if (!facelet_new) {
            ERROR("[facemgr_process_facelet_create_no_family] Error allocating static facelet");
            continue;
        } else {
            if (facelet_merge(facelet_new, static_facelet) < 0) {
                ERROR("[facemgr_process_facelet_create_no_family] Error merging facelets");
                facelet_free(facelet_new);
                continue;
            }
            facelet_set_id(facelet_new, facelet_get_id(static_facelet));
            facelet_set_attr_clean(facelet_new);
            facelet_set_status(facelet, FACELET_STATUS_UNDEFINED);

            if (facemgr_on_event(facemgr, facelet_new) < 0) {
                ERROR("[facemgr_process_facelet_create_no_family] Error creating default IPv6 face");
                //facelet_free(facelet_new);
            }
        }
    }

    return 0;
}

/**
 * \brief Process incoming events from interfaces
 *
 * Implementation notes:
 *  - Any event or timeout due to an interface triggers either a local cache
 *  update, as well a face operations needed to resync the state.
 */
int
facemgr_on_event(facemgr_t * facemgr, facelet_t * facelet_in)
{
    bool remove_facelet = true;
    bool dump = true;
    int ret = 0;
    int rc;
    assert(facelet_in);

    /* Update Netdevice type */
    if ((facelet_get_event(facelet_in) != FACELET_EVENT_GET) &&
            facelet_has_netdevice(facelet_in) &&
            (!facelet_has_netdevice_type(facelet_in))) {
        netdevice_t netdevice = NETDEVICE_EMPTY;

        rc = facelet_get_netdevice(facelet_in, &netdevice);
        if (rc < 0) {
            ERROR("[facemgr_on_event] Error retrieving netdevice from facelet");
            return -1;
        }
        facelet_set_netdevice_type(facelet_in, facemgr_get_netdevice_type(facemgr, netdevice.name));
    }

#if 0
    netdevice_type_t netdevice_type;
    if (facelet_get_netdevice_type(facelet_in, &netdevice_type) < 0) {
        return 0;
    }

    if ((netdevice_type == NETDEVICE_TYPE_UNDEFINED) ||
            (netdevice_type == NETDEVICE_TYPE_LOOPBACK))
        return 0;
#endif

    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet_in);

    facelet_t ** cached_facelets = NULL;
    assert(facelet_in);

    if (facelet_get_status(facelet_in) == FACELET_STATUS_UNDEFINED) {
        facelet_set_status(facelet_in, FACELET_STATUS_UNCERTAIN);
    }

    int n = facelet_cache_lookup(facemgr->facelet_cache, facelet_in, &cached_facelets);
    if (n < 0) {
        ERROR("[facemgr_on_event] Error during cache lookup");
        free(facelet_in);
        return -1;
    }
    if (n == 0) {
        /* This is a new facelet...  we expect a CREATE event. */
        switch(facelet_get_event(facelet_in)) {
            case FACELET_EVENT_CREATE:
            {
                /*
                 * This is the first time we hear about a facelet, it will
                 * likely not have an address family
                 *
                 * Assumption: we should always see the link before the address
                 * assignment
                 */
                DEBUG("[facemgr_on_event] CREATE NEW %s", facelet_s);

                if (!facelet_has_family(facelet_in)) {
                    facemgr_assign_face_type(facemgr, facelet_in);
                    if (facemgr_process_facelet_create_no_family(facemgr, facelet_in) < 0) {
                        ERROR("[facemgr_on_event] Error processing new interface event");
                        goto ERR;
                    }
                    goto DUMP_CACHE;
                }

                if (facelet_set_add(facemgr->facelet_cache, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error adding facelet to cache");
                    goto ERR;
                }

                if (facemgr_process_facelet_create(facemgr, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet CREATE event");
                    ret = -1;
                }

                remove_facelet = false;

                break;
            }

            case FACELET_EVENT_GET:
                /* Insert new facelet in cached */
                //DEBUG("[facemgr_on_event] GET NEW %s", facelet_s);
                rc = facemgr_process_facelet_get(facemgr, facelet_in);
                if (rc == 0)
                    remove_facelet = false;
                dump = false;
                if (rc == -1) {
                    ERROR("[facemgr_on_event] Error processing GET event");
                    goto ERR;
                }
                break;

            case FACELET_EVENT_UPDATE:
                /* Might be because we previously ignored the facelet... */
                //ERROR("[facemgr_on_event] Unexpected UPDATE... face does not exist");
                //goto ERR;

#ifdef WITH_DEFAULT_PRIORITIES
                if (facelet_has_netdevice_type(facelet_in) && !facelet_has_netdevice(facelet_in) && facelet_has_priority(facelet_in)) {
                    /* Remember last priority choice for newly created facelets */
                    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
                    u32 priority = 0;
                    if (facelet_get_netdevice_type(facelet_in, &netdevice_type) < 0) {
                        ERROR("[facelet_on_event] Error getting netdevice_type");
                        goto ERR;
                    }
                    if (facelet_get_priority(facelet_in, &priority) < 0) {
                        ERROR("[facelet_on_event] Error getting priority");
                        goto ERR;
                    }
                    facemgr->default_priority[netdevice_type] = priority;
                }
#endif /* WITH_DEFAULT_PRIORITIES */

                DEBUG("[facemgr_on_event] UPDATE NEW %s", facelet_s);
                INFO("Ignored UPDATE for non-existing face");
                break;

            case FACELET_EVENT_DELETE:
                DEBUG("[facemgr_on_event] DELETE NEW %s", facelet_s);
                ERROR("[facemgr_on_event] Unexpected DELETE... face does not exist");
                goto ERR;

            case FACELET_EVENT_SET_UP:
            case FACELET_EVENT_SET_DOWN:
                ERROR("[facemgr_on_event] Unexpected event on a face that does not exist");
                goto ERR;

            case FACELET_EVENT_UNDEFINED:
            case FACELET_EVENT_N:
                ERROR("[facemgr_on_event] Unexpected UNDEFINED event.");
                ret = -1;
                goto ERR;

        }
        goto DUMP_CACHE;
    }

    /*
     * From now on, it should not make any difference whether we have one or
     * more facelet.
     */
    for (unsigned i = 0; i < n; i ++) {
        /*
         * We merge each cached facelet with incoming one, and perform state
         * reconciliation by sending appropriate updates to the forwarder
         */
        facelet_t * facelet = cached_facelets[i];

        char facelet_old_s[MAXSZ_FACELET];
        facelet_snprintf(facelet_old_s, MAXSZ_FACELET, facelet);
        //DEBUG("Facelet from cache #%d %s", i, facelet_s);

        switch(facelet_get_event(facelet_in)) {
            case FACELET_EVENT_CREATE:
                /*
                 * This can occur for a facelet already in cache but that has
                 * been previously deleted... we need to be able to consider
                 * static facelets in this situation too...
                 */
                DEBUG("[facemgr_on_event] CREATE EXISTING %s", facelet_s);

                if (!facelet_has_family(facelet_in)) {
                    if (facemgr_process_facelet_create_no_family(facemgr, facelet_in) < 0) {
                        ERROR("[facemgr_on_event] Error processing new interface event");
                        goto ERR;
                    }
                    goto DUMP_CACHE;
                }

                // This case will occur when we try to re-create existing faces,
                // eg. in the situation of a forwarder restarting.
                // likely this occurs when the interface receives a (potentially new) address
                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }

                if (facemgr_process_facelet_create(facemgr, facelet) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet CREATE event");
                    ret = -1;
                }

                continue;

            case FACELET_EVENT_GET: /* should be an INFORM message */
                /*
                 * This happens due to polling of the forwarder (or when it
                 * restarts)
                 */
                //DEBUG("[facemgr_on_event] GET EXISTING %s", facelet_old_s);
                //DEBUG("                           WITH %s", facelet_s);
                //ERROR("[facemgr_on_event] GET event for a face that already exists...");
                dump = false;
                continue;

            case FACELET_EVENT_UPDATE:
                DEBUG("[facemgr_on_event] UPDATE EXISTING %s", facelet_old_s);
                DEBUG("                              WITH %s", facelet_s);

#ifdef WITH_DEFAULT_PRIORITIES
                if (facelet_has_netdevice_type(facelet_in) && !facelet_has_netdevice(facelet_in) && facelet_has_priority(facelet_in)) {
                    /* Remember last priority choice for newly created facelets */
                    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
                    u32 priority = 0;
                    if (facelet_get_netdevice_type(facelet_in, &netdevice_type) < 0) {
                        ERROR("[facelet_on_event] Error getting netdevice_type");
                        goto ERR;
                    }
                    if (facelet_get_priority(facelet_in, &priority) < 0) {
                        ERROR("[facelet_on_event] Error getting priority");
                        goto ERR;
                    }
                    facemgr->default_priority[netdevice_type] = priority;
                }
#endif /* WITH_DEFAULT_PRIORITIES */

                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }
                if (facemgr_process_facelet_update(facemgr, facelet) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet UPDATE event");
                    ret = -1;
                }
                continue;

            case FACELET_EVENT_DELETE:
                DEBUG("[facemgr_on_event] DELETE EXISTING %s", facelet_old_s);
                DEBUG("                              WITH %s", facelet_s);
                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }
                if (facemgr_process_facelet_delete(facemgr, facelet) < 0) {
                        ERROR("[facemgr_on_event] Error processing facelet DELETE event");
                    ret = -1;
                }
                continue;

            case FACELET_EVENT_SET_UP:
                ERROR("[facemgr_on_event] Not implemented\n");
                ret = -1;
                continue;

            case FACELET_EVENT_SET_DOWN:
                DEBUG("[facemgr_on_event] SET DOWN EXISTING %s", facelet_old_s);
                DEBUG("                                WITH %s", facelet_s);
                /* We don't even need to merge */
                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }
                if (facemgr_process_facelet_delete(facemgr, facelet) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet DELETE event");
                    continue;
                }
                continue;

            case FACELET_EVENT_UNDEFINED:
            case FACELET_EVENT_N:
                ERROR("[facemgr_on_event] Unexpected UNDEFINED event.");
                ret = -1;
                goto ERR;

        }

    }
    goto DUMP_CACHE;

ERR:
    ret = -1;

DUMP_CACHE:
#if 1
    if (dump) {
        DEBUG("    <CACHE>");
        facelet_set_dump(facemgr->facelet_cache);
        DEBUG("    </CACHE>");
        DEBUG("</EVENT ret=%d>", ret);
        DEBUG("----------------------------------");
    }
#endif

    free(cached_facelets);

    if (remove_facelet)
        facelet_free(facelet_in);

    if (ret == -1) {
        INFO("Error... starting reattempts");
        facemgr_start_reattempts(facemgr);
    }

    return ret;
}

int facemgr_callback(facemgr_t * facemgr, interface_cb_type_t type, void * data)
{
    switch(type) {
        case INTERFACE_CB_TYPE_RAISE_EVENT:
            return facemgr_on_event(facemgr, data);

        case INTERFACE_CB_TYPE_REGISTER_FD:
        {
            /* Remember fd for further release */
            fd_callback_data_t * fd_callback_data = data;
            interface_t * interface = (interface_t*)(fd_callback_data->owner);

            interface_map_data_t * interface_map_data = NULL;
            if (interface_map_get(facemgr->interface_map, interface->name, &interface_map_data) < 0) {
                ERROR("[facemgr_callback] Error getting interface map data");
                return -1;
            }
            if (!interface_map_data) {
                ERROR("[facemgr_callback] No entry in interface map data");
                return -1;
            }
            interface_map_data->fds[interface_map_data->num_fds++] = fd_callback_data->fd;

            return facemgr->callback(facemgr->callback_owner,
                    FACEMGR_CB_TYPE_REGISTER_FD, data);
        }

        case INTERFACE_CB_TYPE_UNREGISTER_FD:
        {
            fd_callback_data_t * fd_callback_data = data;
            interface_t * interface = (interface_t*)(fd_callback_data->owner);

            interface_map_data_t * interface_map_data = NULL;
            if (interface_map_get(facemgr->interface_map, interface->name, &interface_map_data) < 0) {
                ERROR("[facemgr_callback] Error getting interface map data");
                return -1;
            }
            if (!interface_map_data) {
                ERROR("[facemgr_callback] No entry in interface map data");
                return -1;
            }

            for (unsigned i = 0; i < interface_map_data->num_fds; i++) {
                if (interface_map_data->fds[i] == fd_callback_data->fd) {
                    interface_map_data->fds[i] = interface_map_data->fds[--interface_map_data->num_fds];
                    break;
                }
            }

            return facemgr->callback(facemgr->callback_owner,
                    FACEMGR_CB_TYPE_UNREGISTER_FD, data);
        }

        case INTERFACE_CB_TYPE_REGISTER_TIMER:
            return facemgr->callback(facemgr->callback_owner,
                    FACEMGR_CB_TYPE_REGISTER_TIMER, data);

        case INTERFACE_CB_TYPE_UNREGISTER_TIMER:
            return facemgr->callback(facemgr->callback_owner,
                    FACEMGR_CB_TYPE_UNREGISTER_TIMER, data);

    }
    return -1;
}

int
facemgr_bootstrap(facemgr_t * facemgr)
{
    int rc;

    DEBUG("Registering interfaces...");
    rc = interface_register(&hicn_light_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering hicn_light interface");
        goto ERR_REGISTER;
    }

#ifdef __APPLE__
    rc = interface_register(&network_framework_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering network_framework interface");
        goto ERR_REGISTER;
    }
#endif /* __APPLE__ */

#ifdef __linux__
    rc = interface_register(&netlink_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering netlink interface");
        goto ERR_REGISTER;
    }

    rc = interface_register(&bonjour_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering bonjour interface");
        goto ERR_REGISTER;
    }
#endif /* __linux__ */

#ifdef WITH_ANDROID_UTILITY
    rc = interface_register(&android_utility_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering android_utility interface");
        goto ERR_REGISTER;
    }
#endif /* WITH_ANDROID_UTILITY */

#ifdef WITH_PRIORITY_CONTROLLER
    INFO("[facemgr_bootstrap] registering priority_controller interface");
    rc = interface_register(&priority_controller_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering priority_controller interface");
        goto ERR_REGISTER;
    }
#endif

#ifdef WITH_EXAMPLE_DUMMY
    rc = interface_register(&dummy_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering dummy interface");
        goto ERR_REGISTER;
    }
#endif

#ifdef WITH_EXAMPLE_UPDOWN
    rc = interface_register(&updown_ops);
    if (rc < 0) {
        ERROR("[facemgr_bootstrap] Error registering updown interface");
        goto ERR_REGISTER;
    }
#endif

    rc = facemgr_create_interface(facemgr, "hl", "hicn_light", NULL, &facemgr->hl);
    if (rc < 0) {
        ERROR("Error creating 'hICN forwarder (hicn-light)' interface\n");
        goto ERR_HL_CREATE;
    }

#ifdef __APPLE__
    network_framework_cfg_t nf_cfg = {
    };
    rc = facemgr_create_interface(facemgr, "nf", "network_framework", &nf_cfg, &facemgr->nf);
    if (rc < 0) {
        ERROR("Error creating 'Apple Network Framework' interface\n");
        goto ERR_NF_CREATE;
    }
#endif /* __APPLE__ */

#ifdef __linux__
    rc = facemgr_create_interface(facemgr, "nl", "netlink", NULL, &facemgr->nl);
    if (rc < 0) {
        ERROR("Error creating 'Netlink' interface\n");
        goto ERR_NL_CREATE;
    }
#endif /* __linux__ */

#ifdef WITH_ANDROID_UTILITY
    android_utility_cfg_t au_cfg = {
        .jvm = facemgr->jvm,
    };
    rc = facemgr_create_interface(facemgr, "au", "android_utility", &au_cfg, &facemgr->au);
    if (rc < 0) {
        ERROR("Error creating 'Android Utility' interface\n");
        goto ERR_AU_CREATE;
    }
#endif /* WITH_ANDROID_UTILITY */

#ifdef WITH_PRIORITY_CONTROLLER
    INFO("[facemgr_bootstrap] creating priority_controller interface");
    rc = facemgr_create_interface(facemgr, "pc", "priority_controller", NULL, &facemgr->pc);
    if (rc < 0) {
        ERROR("Error creating 'Priority Controller' interface\n");
        goto ERR_PC_CREATE;
    }
#endif

#ifdef WITH_EXAMPLE_DUMMY
    rc = facemgr_create_interface(facemgr, "dummy0", "dummy", NULL, &facemgr->dummy);
    if (rc < 0) {
        ERROR("Error creating 'dummy' interface\n");
        goto ERR_DUMMY_CREATE;
    }
#endif

#ifdef WITH_EXAMPLE_UPDOWN
    rc = facemgr_create_interface(facemgr, "updown0", "updown", NULL, &facemgr->updown);
    if (rc < 0) {
        ERROR("Error creating 'updown' interface\n");
        goto ERR_UPDOWN_CREATE;
    }
#endif

    DEBUG("Facemgr successfully initialized...");

    return 0;

#ifdef WITH_EXAMPLE_UPDOWN
    facemgr_delete_interface(facemgr, facemgr->updown);
ERR_UPDOWN_CREATE:
#endif
#ifdef WITH_EXAMPLE_DUMMY
    facemgr_delete_interface(facemgr, facemgr->dummy);
ERR_DUMMY_CREATE:
#endif
#ifdef WITH_ANDROID_UTILITY
    facemgr_delete_interface(facemgr, facemgr->au);
ERR_AU_CREATE:
#endif /* WITH_ANDROID_UTILITY */
#ifdef WITH_PRIORITY_CONTROLLER
    facemgr_delete_interface(facemgr, facemgr->pc);
ERR_PC_CREATE:
#endif
#ifdef __linux__
    facemgr_delete_interface(facemgr, facemgr->nl);
ERR_NL_CREATE:
#endif /* __linux__ */
#ifdef __APPLE__
    facemgr_delete_interface(facemgr, facemgr->nf);
ERR_NF_CREATE:
#endif /* __APPLE__ */
    facemgr_delete_interface(facemgr, facemgr->hl);
ERR_HL_CREATE:
ERR_REGISTER:
    return -1;
}

void facemgr_stop(facemgr_t * facemgr)
{
    // FIXME we should iterate on interface map

#ifdef __APPLE__
    facemgr_delete_interface(facemgr, facemgr->nf);
#endif /* __APPLE__ */


#ifdef __linux__
    facemgr_delete_interface(facemgr, facemgr->nl);

    /* Delete all bonjour interfaces */
    interface_t ** bonjour_array = NULL;
    int n = bonjour_map_get_value_array(facemgr->bonjour_map, &bonjour_array);
    if (n >= 0) {
        netdevice_t ** netdevice_array = NULL;
        int m = bonjour_map_get_key_array(facemgr->bonjour_map, &netdevice_array);
        if (m >= 0) {
            assert(m == n);
            for (int i = 0; i < n; i++) { /* Fail silently */
                DEBUG("Deleting bonjour interface associated to %s (%p)",
                        netdevice_array[i]->name, bonjour_array[i]);
                facemgr_delete_interface(facemgr, bonjour_array[i]);
            }
            free(netdevice_array);
        }
        free(bonjour_array);
    }
#endif /* __linux__ */

#ifdef WITH_ANDROID_UTILITY
    facemgr_delete_interface(facemgr, facemgr->au);
#endif /* WITH_ANDROID_UTILITY */

#ifdef WITH_PRIORITY_CONTROLLER
    facemgr_delete_interface(facemgr, facemgr->pc);
#endif

    facemgr_delete_interface(facemgr, facemgr->hl);

#ifdef WITH_EXAMPLE_DUMMY
    facemgr_delete_interface(facemgr, facemgr->dummy);
#endif

#ifdef WITH_EXAMPLE_UPDOWN
    facemgr_delete_interface(facemgr, facemgr->updown);
#endif
}

#ifdef __ANDROID__
void facemgr_set_jvm(facemgr_t * facemgr, JavaVM *jvm)
{
    facemgr->jvm = jvm;
}
#endif /* __ANDROID__ */

void
facemgr_set_callback(facemgr_t * facemgr, void * callback_owner, facemgr_cb_t callback)
{
    facemgr->callback = callback;
    facemgr->callback_owner = callback_owner;
}

void facemgr_list_facelets(const facemgr_t * facemgr, facemgr_list_facelets_cb_t cb, void * user_data)
{
    facelet_t ** facelet_array;
    if (!cb)
        return;
    int n = facelet_set_get_array(facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_list_facelets] Could not retrieve facelets in cache");
        return;
    }
    for (unsigned i = 0; i < n; i++) {
        facelet_t * facelet = facelet_array[i];
        cb(facemgr, facelet, user_data);
    }
    free(facelet_array);
}

int
facemgr_list_facelets_json(const facemgr_t * facemgr, char ** buffer)
{
    char * cur;
    char * s;
    int rc;

    facelet_t ** facelet_array;
    int n = facelet_set_get_array(facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_list_facelets_json] Could not retrieve facelets in cache");
        return -1;
    }
    /* This should be enough for JSON overhead, refine later */
    size_t size = 2 * n * MAXSZ_FACELET;
    *buffer = malloc(size);
    if (!buffer) {
        ERROR("[facemgr_list_facelets_json] Could not allocate JSON s");
        free(facelet_array);
        return -1;
    }
    s = *buffer;
    cur = s;

    rc = snprintf(cur, s + size - cur, "{\"facelets\": [\n");
    if (rc < 0)
        goto ERR;
    cur += rc;
    if (size != 0 && cur >= s + size)
        goto END;

    for (unsigned i = 0; i < n; i++) {
        facelet_t * facelet = facelet_array[i];

        rc = facelet_snprintf_json(cur, s + size - cur, facelet, /* indent */ 1);
        if (rc < 0)
            goto ERR;
        cur += rc;
        if (size != 0 && cur >= s + size)
            goto END;

        rc = snprintf(cur, s + size - cur, (i == n-1) ? "\n" : ",\n");
        if (rc < 0)
            goto ERR;
        cur += rc;
        if (size != 0 && cur >= s + size)
            goto END;
    }

    rc = snprintf(cur, s + size - cur, "]}\n");
    if (rc < 0)
        goto ERR;
    cur += rc;
    if (size != 0 && cur >= s + size)
        goto END;

END:
    free(facelet_array);
    return (int)(cur - s);

ERR:
    free(facelet_array);
    return rc;
}

