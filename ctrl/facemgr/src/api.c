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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <hicn/facemgr/api.h>
#include <hicn/facemgr/cfg.h>
#include <hicn/util/log.h>

#ifdef __APPLE__
#include "interfaces/network_framework/network_framework.h"
#endif /* __APPLE__ */

#ifdef __linux__
#include "interfaces/bonjour/bonjour.h"
#endif /* __linux__ */

#ifdef __ANDROID__
#include <hicn/android_utility/android_utility.h>
#endif /* __ANDROID__ */

#include <hicn/ctrl/face.h>
#include <hicn/facemgr/facelet.h>
#include "common.h"
#include "interface.h"
#include "util/map.h"
#include "util/set.h"

#define RAND_NAME_LEN 5

#define DEFAULT_PORT 9695

#define DEFAULT_REATTEMPT_DELAY_MS 250
#define MAX_FDS 10

typedef struct {
    interface_t * interface;
    int fds[MAX_FDS];
    size_t num_fds;
} interface_map_data_t;

TYPEDEF_SET_H(facelet_cache, facelet_t *);
TYPEDEF_SET(facelet_cache, facelet_t *, facelet_cmp, facelet_snprintf);

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
#ifdef __ANDROID__
extern interface_ops_t android_utility_ops;
#endif /* __ANDROID__ */
#ifdef WITH_EXAMPLE_DUMMY
extern interface_ops_t dummy_ops;
#endif
#ifdef WITH_EXAMPLE_UPDOWN
extern interface_ops_t updown_ops;
#endif
extern interface_ops_t hicn_light_ops;


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
    interface_map_t interface_map;

    /* Faces under construction */
    facelet_cache_t facelet_cache;

    /********************************************************/
    /* Interfaces - Those should be fully replaced by a map */

    interface_t * hl;

#ifdef __ANDROID__
    interface_t * au; /* android_utility */
#endif /* __ANDROID__ */

#ifdef __APPLE__
    interface_t * nf; /* network_framework */
#endif /* __APPLE__ */

#ifdef __linux__
    interface_t * nl; /* netlink */

    /*
     * We maintain a map of dynamically created bonjour interfaces, one for each
     * found netdevice
     */
    bonjour_map_t bonjour_map;
#endif /* __linux__ */

#ifdef WITH_EXAMPLE_DUMMY
    interface_t * dummy;
#endif
#ifdef WITH_EXAMPLE_UPDOWN
    interface_t * updown;
#endif
    int timer_fd; /* Timer used for reattempts */
};

int
facemgr_initialize(facemgr_t * facemgr)
{
    int rc;

    rc = interface_map_initialize(&facemgr->interface_map);
    if (rc < 0)
        goto ERR_INTERFACE_MAP;

    rc = facelet_cache_initialize(&facemgr->facelet_cache);
    if (rc < 0)
        goto ERR_FACE_CACHE_PENDING;

#ifdef __linux__
    rc = bonjour_map_initialize(&facemgr->bonjour_map);
    if (rc < 0)
        goto ERR_BJ;
#endif /* __linux */

    facemgr->cfg = facemgr_cfg_create();
    if (!facemgr->cfg)
        goto ERR_CFG;

    facemgr->timer_fd = 0;

    return 0;

ERR_CFG:
#ifdef __linux__
    bonjour_map_finalize(&facemgr->bonjour_map);
ERR_BJ:
#endif /* __linux__ */
    facelet_cache_finalize(&facemgr->facelet_cache);
ERR_FACE_CACHE_PENDING:
    interface_map_finalize(&facemgr->interface_map);
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

    rc = interface_map_finalize(&facemgr->interface_map);
    if (rc < 0) {
        ERROR("[facemgr_finalize] Could not finalize interface_map");
        ret = -1;
    }

    /* Free all facelets from cache */
    facelet_t ** facelet_array;
    int n = facelet_cache_get_array(&facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_finalize] Could not retrieve facelets in cache");
    } else {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * facelet = facelet_array[i];
            if (facelet_cache_remove(&facemgr->facelet_cache, facelet, NULL)) {
                ERROR("[facemgr_finalize] Could not purge facelet from cache");
            }
            facelet_free(facelet);
        }
        free(facelet_array);
    }

    rc = facelet_cache_finalize(&facemgr->facelet_cache);
    if (rc < 0)
        ret = -1;

#ifdef __linux__
    rc = bonjour_map_finalize(&facemgr->bonjour_map);
    if (rc < 0)
        ret = -1;
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

    if (interface_map_add(&facemgr->interface_map, interface->name, interface_map_data) < 0)
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

ERR_MAP_ADD:
    free(interface_map_data);
ERR_MAP_DATA:
    interface_finalize(interface);
ERR_INIT:
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
    rc = interface_map_remove(&facemgr->interface_map, interface->name, &interface_map_data);
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

    int rc = bonjour_map_get(&facemgr->bonjour_map, netdevice, &bj);
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
    return interface_on_event(bj, NULL);
}
#endif /* __linux__ */

#ifdef __ANDROID__
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
    if (rc < 0)
        goto ERR_EVENT;

    return 0;

ERR_EVENT:
ERR_ND:
    facelet_free(facelet);
ERR_MALLOC:
    return -1;
}
#endif /* __ANDROID__ */


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
facelet_cache_lookup(const facelet_cache_t * facelet_cache, facelet_t * facelet,
        facelet_t ***cached_facelets)
{
    /*
     * If the facelet is uniquely identified by its key, it is used to perform
     * an efficient lookup directly...
     */
    if (facelet_has_key(facelet)) {
        facelet_t * found = NULL;
        if (facelet_cache_get(facelet_cache, facelet, &found) < 0) {
            ERROR("[facelet_cache_lookup] Error during cache lookup");
            return -1;
        }
        if (!found)
            return 0;
        *cached_facelets = malloc(sizeof(facelet_t*));
        *cached_facelets[0] = found;
        return 1;
    }

    /* ...otherwise, we iterate over the facelet
     * cache to find matching elements.
     */
    facelet_t ** facelet_array;
    int n = facelet_cache_get_array(facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facelet_cache_lookup] Error during cache match");
        return -1;
    }
    *cached_facelets = malloc(n * sizeof(facelet_t*));

    int num_match = 0;
    for (unsigned i = 0; i < n; i++) {
        char buf[128];
        facelet_snprintf(buf, 128, facelet_array[i]);
        facelet_snprintf(buf, 128, facelet);

        if (!facelet_match(facelet_array[i], facelet)) {
            continue;
        }
        (*cached_facelets)[num_match++] = facelet_array[i];
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
//#ifdef __ANDROID__
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_facelet_satisfy_rules] Error retrieving netdevice_type from facelet");
        return -2;
    }
//#endif /* __ANDROID__ */

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

#ifdef __ANDROID__
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
#endif /* __ANDROID__ */

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
//#ifdef __ANDROID__
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_bj] Error retrieving netdevice_type from facelet");
        return -2;
    }
//#endif /* __ANDROID__ */

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
//#ifdef __ANDROID__
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_complement_facelet_manual] Error retrieving netdevice_type from facelet");
        return -2;
    }
//#endif /* __ANDROID__ */

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

    bool discovery_needed = (face_type.layer == FACE_TYPE_LAYER_4) &&
        ((!facelet_has_remote_addr(facelet)) || (!facelet_has_remote_port(facelet)));

    if (!discovery_needed) {
        DEBUG("manual settings not considered as no discovery is needed");
        return -2;
    }

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

    if (!facelet_has_key(facelet))
        return -2;

#if 0
#ifdef __ANDROID__
    rc = facemgr_complement_facelet_au(facemgr, facelet);
    if (rc != -2)
        return rc;
#endif /* __ANDROID__ */
#endif
    if (!facelet_has_netdevice_type(facelet)) {
        netdevice_t netdevice = NETDEVICE_EMPTY;
        rc = facelet_get_netdevice(facelet, &netdevice);
        if (rc < 0) {
            ERROR("[facemgr_complement_facelet] Error retrieving netdevice from facelet");
            return -1;
        }
        facelet_set_netdevice_type(facelet, facemgr_get_netdevice_type(facemgr, netdevice.name));
    }

    /* We continue only if the current call was not applicable. In the current
     * setting we have no interface that can be requested in parallel, and no
     * need to. This might evolve in future releases.
     */

#ifdef __linux__
    rc = facemgr_complement_facelet_bj(facemgr, facelet);
    if (rc != -2)
        return rc;
#endif /* __linux__ */

    DEBUG("Complement manual");

    rc = facemgr_complement_facelet_manual(facemgr, facelet);
    if (rc != -2)
        return rc;

    INFO("[facemgr_complement_facelet] No more interfaces to query... incomplete face");
    return 0;
}

int facemgr_assign_face_type(facemgr_t * facemgr, facelet_t * facelet)
{
    /* As key, netdevice and family should always be present */
    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0) {
        ERROR("[facemgr_facelet_satisfy_rules] Error retrieving netdevice from facelet");
        return -1;
    }

    netdevice_type_t netdevice_type = NETDEVICE_TYPE_UNDEFINED;
//#ifdef __ANDROID__
    /*
     * In addition to netdevice, netdevice_type should be present to correctly
     * apply rules
     */
    rc = facelet_get_netdevice_type(facelet, &netdevice_type);
    if (rc < 0) {
        ERROR("[facemgr_facelet_satisfy_rules] Error retrieving netdevice_type from facelet");
        return -2;
    }
//#endif /* __ANDROID__ */

    facemgr_face_type_t face_type = FACEMGR_FACE_TYPE_UNDEFINED;
    if (facemgr_cfg_get_face_type(facemgr->cfg, &netdevice, netdevice_type, &face_type) < 0)
        return rc;
    facelet_set_face_type(facelet, face_type);
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
                    facelet_set_status(facelet, FACELET_STATUS_IGNORED);
                    return 0;

                case -2:
                    /* Not enough information: AU in fact */
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
            if (interface_on_event(facemgr->hl, facelet) < 0) {
                ERROR("[facemgr_process_facelet] Failed to create face");
                goto ERR;
            }

            /* This works assuming the call to hicn-light is blocking */
            facelet_set_status(facelet, FACELET_STATUS_CLEAN);
            break;


        case FACELET_STATUS_UPDATE:
            facelet_set_event(facelet, FACELET_EVENT_UPDATE);
            if (interface_on_event(facemgr->hl, facelet) < 0) {
                ERROR("[facemgr_process_facelet] Failed to update face");
                goto ERR;
            }

            /* This works assuming the call to hicn-light is blocking */
            facelet_set_status(facelet, FACELET_STATUS_CLEAN);
            break;

        case FACELET_STATUS_DELETE:
            facelet_set_event(facelet, FACELET_EVENT_DELETE);
            if (interface_on_event(facemgr->hl, facelet) < 0) {
                ERROR("[facemgr_process_facelet] Failed to delete face");
                goto ERR;
            }

            /* This works assuming the call to hicn-light is blocking */
            DEBUG("[facemgr_process_facelet] Cleaning cached data");
            facelet_unset_local_addr(facelet);
            facelet_unset_local_port(facelet);
            facelet_unset_remote_addr(facelet);
            facelet_unset_remote_port(facelet);
            facelet_unset_bj_done(facelet);
            //facelet_unset_au_done(facelet);

            facelet_set_status(facelet, FACELET_STATUS_DELETED);
            break;

        case FACELET_STATUS_CLEAN:
        case FACELET_STATUS_IGNORED:
        case FACELET_STATUS_DELETED:
            /* Nothing to do */
            break;

        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet] Unexpected facelet status");
            goto ERR;
    }

    facelet_set_status_error(facelet, false);
    return 0;

ERR:
    facelet_set_status_error(facelet, true);
    return -1;
}

int
facemgr_reattempt_timeout(facemgr_t * facemgr, int fd, void * data)
{
    bool has_error = false;

    assert(data == NULL);

    /* Free all facelets from cache */
    facelet_t ** facelet_array;
    int n = facelet_cache_get_array(&facemgr->facelet_cache, &facelet_array);
    if (n < 0) {
        ERROR("[facemgr_reattempt_timeout] Could not retrieve facelets in cache");
    } else {
        for (unsigned i = 0; i < n; i++) {
            facelet_t * facelet = facelet_array[i];

            if (!facelet_get_status_error(facelet))
                continue;

            char buf[MAXSZ_FACELET];
            facelet_snprintf(buf, MAXSZ_FACELET, facelet);
            DEBUG("Reattempt to process failed facelet %s", buf);
            if (facemgr_process_facelet(facemgr, facelet) < 0) {
                ERROR("[facemgr_reattempt_timeout] Error processing facelet");
                has_error = true;
                continue;
            }
            facelet_set_status_error(facelet, false);
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
    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
        case FACELET_STATUS_INCOMPLETE:
        case FACELET_STATUS_CREATE:
            /* No change */
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
            facelet_set_status(facelet, FACELET_STATUS_CREATE);
            break;
        case FACELET_STATUS_CLEAN:
        case FACELET_STATUS_IGNORED:
            /*
             * We should have nothing to do unless some fields have
             * been updated.
             */
            break;

        case FACELET_STATUS_DELETED:
            /*
             * Unless rules have changed, we only need to recover
             * missing information, and proceed to face creation.
             * Rule changes should be handled separately.
             */
            facelet_set_status(facelet, FACELET_STATUS_INCOMPLETE);
            break;
        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_create] Unexpected facelet status");
            return -1;
    }

    if (facemgr_process_facelet(facemgr, facelet) < 0) {
        ERROR("[facemgr_process_facelet_create] Error processing facelet");
        return -1;
    }

    return 0;
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
    if (facelet_has_netdevice(facelet)) {
        netdevice_t netdevice;
        if (facelet_get_netdevice(facelet, &netdevice) < 0)
            return -1;
        if (!IS_VALID_NETDEVICE(netdevice))
            return -2;
        facelet_set_status(facelet, FACELET_STATUS_CLEAN);
        return facelet_cache_add(&facemgr->facelet_cache, facelet);
    }
    return -2;
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
    switch(facelet_get_status(facelet)) {
        case FACELET_STATUS_UNCERTAIN:
        case FACELET_STATUS_INCOMPLETE:
        case FACELET_STATUS_CREATE:
        case FACELET_STATUS_UPDATE:
            /* No change */
            break;
        case FACELET_STATUS_CLEAN:
            facelet_set_status(facelet, FACELET_STATUS_UPDATE);
            break;
        case FACELET_STATUS_DELETE:
        case FACELET_STATUS_DELETED:
        case FACELET_STATUS_IGNORED:
            /* Reconsider face creation in light of new information */
            facelet_set_status(facelet, FACELET_STATUS_UNCERTAIN);
            break;
        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_update] Unexpected facelet status");
            return -1;
    }

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
        case FACELET_STATUS_CREATE:
            facelet_unset_local_addr(facelet);
            facelet_unset_local_port(facelet);
            facelet_unset_remote_addr(facelet);
            facelet_unset_remote_port(facelet);
            facelet_unset_bj_done(facelet);
            //facelet_unset_au_done(facelet);
            facelet_set_status(facelet, FACELET_STATUS_DELETED);
            break;
        case FACELET_STATUS_UPDATE:
        case FACELET_STATUS_CLEAN:
            facelet_set_status(facelet, FACELET_STATUS_DELETE);
            break;
        case FACELET_STATUS_DELETE:
        case FACELET_STATUS_IGNORED:
        case FACELET_STATUS_DELETED:
            /* Nothing to do */
            DEBUG("%s\n", facelet_status_str[facelet_get_status(facelet)]);
            break;
        case FACELET_STATUS_UNDEFINED:
        case FACELET_STATUS_N:
            ERROR("[facemgr_process_facelet_delete] Unexpected facelet status");
            return -1;
    }

    if (facemgr_process_facelet(facemgr, facelet) < 0) {
        ERROR("[facemgr_process_facelet_delete] Error processing facelet");
        return -1;
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
    int ret = 0;
    int rc;
    assert(facelet_in);

    char facelet_s[MAXSZ_FACELET];
    facelet_snprintf(facelet_s, MAXSZ_FACELET, facelet_in);
    DEBUG("EVENT %s", facelet_s);

    facelet_t ** cached_facelets = NULL;
    int n = facelet_cache_lookup(&facemgr->facelet_cache, facelet_in, &cached_facelets);
    if (n < 0) {
        ERROR("[facemgr_on_event] Error during cache lookup");
        free(facelet_in);
        return -1;
    }
    if (n == 0) {
        /* This is a new facelet...  we expect a CREATE event. */
        switch(facelet_get_event(facelet_in)) {
            case FACELET_EVENT_CREATE:

                facelet_set_status(facelet_in, FACELET_STATUS_UNCERTAIN);
                if (facelet_cache_add(&facemgr->facelet_cache, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error adding facelet to cache");
                    free(facelet_in);
                    free(cached_facelets);
                    return -1;
                }

                remove_facelet = false;

                if (facemgr_process_facelet_create(facemgr, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet CREATE event");
                    ret = -1;
                    goto ERR;
                }

                break;

            case FACELET_EVENT_GET:
                /* Insert new facelet in cached */
                rc = facemgr_process_facelet_get(facemgr, facelet_in);
                if (rc == 0)
                    remove_facelet = false;
                if (rc == -1) {
                    ERROR("[facemgr_on_event] Error processing GET event");
                    goto ERR;
                }
                break;

            case FACELET_EVENT_UPDATE:
                /* Might be because we previously ignored the facelet... */
                //ERROR("[facemgr_on_event] Unexpected UPDATE... face does not exist");
                //goto ERR;
                INFO("Ignored UPDATE for non-existing face");
                break;

            case FACELET_EVENT_DELETE:
                ERROR("[facemgr_on_event] Unexpected DELETE... face does not exist");
                goto ERR;

            case FACELET_EVENT_UNDEFINED:
                ERROR("[facemgr_on_event] Unexpected UNDEFINED event.");
                goto ERR;

            default: /* XXX Some events should be deprecated */
                ERROR("[facemgr_on_event] Deprecated event");
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
        switch(facelet_get_event(facelet_in)) {
            case FACELET_EVENT_CREATE:
                // This case will occur when we try to re-create existing faces,
                // eg. in the situation of a forwarder restarting.
                // likely this occurs when the interface receives a (potentially new) address
                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }

                if (facemgr_process_facelet_create(facemgr, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error processing facelet CREATE event");
                    ret = -1;
                }

                continue;

            case FACELET_EVENT_GET: /* should be an INFORM message */
                // FIXME, this might occur if the forwarder restarts and we
                // resync faces...
                ERROR("[facemgr_on_event] GET event for a face that already exists...");
                ret = -1;
                continue;

            case FACELET_EVENT_UPDATE:
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
                if (facelet_merge(facelet, facelet_in) < 0) {
                    ERROR("[facemgr_on_event] Error merging facelets");
                    continue;
                }
                if (facemgr_process_facelet_delete(facemgr, facelet) < 0) {
                        ERROR("[facemgr_on_event] Error processing facelet DELETE event");
                    ret = -1;
                }
                continue;

            default: /* XXX Some events should be deprecated */
                ERROR("[facemgr_on_event] Deprecated event");
                ret = -1;
        }

    }
    goto DUMP_CACHE;

ERR:
    ret = -1;

DUMP_CACHE:
#if 1
    DEBUG("    <CACHE>");
    facelet_cache_dump(&facemgr->facelet_cache);
    DEBUG("    </CACHE>");
    DEBUG("</EVENT ret=%d>", ret);
    DEBUG("----------------------------------");
#endif

    free(cached_facelets);

    if (remove_facelet)
        facelet_free(facelet_in);

    if (ret == -1)
        facemgr_start_reattempts(facemgr);

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
            if (interface_map_get(&facemgr->interface_map, interface->name, &interface_map_data) < 0) {
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
            if (interface_map_get(&facemgr->interface_map, interface->name, &interface_map_data) < 0) {
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
        ERROR("Could not register interfaces");
        goto ERR_REGISTER;
    }

#ifdef __APPLE__
    rc = interface_register(&network_framework_ops);
    if (rc < 0)
        goto ERR_REGISTER;
#endif /* __APPLE__ */

#ifdef __linux__
    rc = interface_register(&netlink_ops);
    if (rc < 0)
        goto ERR_REGISTER;
    rc = interface_register(&bonjour_ops);
    if (rc < 0)
        goto ERR_REGISTER;
#endif /* __linux__ */

#ifdef __ANDROID__
    rc = interface_register(&android_utility_ops);
    if (rc < 0)
        goto ERR_REGISTER;
#endif /* __ANDROID__ */

#ifdef WITH_EXAMPLE_DUMMY
    rc = interface_register(&dummy_ops);
    if (rc < 0)
        goto ERR_REGISTER;
#endif

#ifdef WITH_EXAMPLE_UPDOWN
    rc = interface_register(&updown_ops);
    if (rc < 0)
        goto ERR_REGISTER;
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

#ifdef __ANDROID__
    android_utility_cfg_t au_cfg = {
        .jvm = facemgr->jvm,
    };
    rc = facemgr_create_interface(facemgr, "au", "android_utility", &au_cfg, &facemgr->au);
    if (rc < 0) {
        ERROR("Error creating 'Android Utility' interface\n");
        goto ERR_AU_CREATE;
    }
#endif /* __ANDROID__ */

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

    /* FIXME facemgr_delete_interface */
#ifdef WITH_EXAMPLE_UPDOWN
    interface_free(facemgr->updown);
ERR_UPDOWN_CREATE:
#endif
#ifdef WITH_EXAMPLE_DUMMY
    interface_free(facemgr->dummy);
ERR_DUMMY_CREATE:
#endif
#ifdef __ANDROID__
    interface_free(facemgr->au);
ERR_AU_CREATE:
#endif /* __ANDROID__ */
#ifdef __linux__
    interface_free(facemgr->nl);
ERR_NL_CREATE:
#endif /* __linux__ */
#ifdef __APPLE__
    interface_free(facemgr->nf);
ERR_NF_CREATE:
#endif /* __APPLE__ */
    interface_free(facemgr->hl);
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
    int n = bonjour_map_get_value_array(&facemgr->bonjour_map, &bonjour_array);
    if (n >= 0) {
        netdevice_t ** netdevice_array = NULL;
        int m = bonjour_map_get_key_array(&facemgr->bonjour_map, &netdevice_array);
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

#ifdef __ANDROID__
    facemgr_delete_interface(facemgr, facemgr->au);
#endif /* __ANDROID__ */

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
    int n = facelet_cache_get_array(&facemgr->facelet_cache, &facelet_array);
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
    int n = facelet_cache_get_array(&facemgr->facelet_cache, &facelet_array);
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
    free(facelet_array);

    rc = snprintf(cur, s + size - cur, "]}\n");
    if (rc < 0)
        goto ERR;
    cur += rc;
    if (size != 0 && cur >= s + size)
        goto END;

END:
    free(facelet_array);
    return cur - s;

ERR:
    free(facelet_array);
    return rc;
}
