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
 * \file cfg.h
 * \brief Face manager configuration
 */
#ifndef FACEMGR_CFG_H
#define FACEMGR_CFG_H

#include <hicn/face.h>
#include <hicn/facemgr/facelet.h>
#include <hicn/util/log.h>

/* Face manager configuration */

#ifdef __ANDROID__
#define FACEMGR_FACE_TYPE_DEFAULT FACEMGR_FACE_TYPE_OVERLAY_UDP
#else
#define FACEMGR_FACE_TYPE_DEFAULT FACEMGR_FACE_TYPE_NATIVE_TCP
#endif /* __ANDROID__ */

#define DEFAULT_FACE_TYPE FACE_TYPE_AUTO
#define FACEMGR_CFG_DEFAULT_DISCOVERY true
//#define DEFAULT_IGNORE "lo"
#define FACEMGR_CFG_DEFAULT_IPV4 true
#define FACEMGR_CFG_DEFAULT_IPV6 false



typedef struct facemgr_cfg_s facemgr_cfg_t;

facemgr_cfg_t * facemgr_cfg_create();
void facemgr_cfg_free(facemgr_cfg_t * cfg);
int facemgr_cfg_initialize(facemgr_cfg_t * cfg);
int facemgr_cfg_finalize(facemgr_cfg_t * cfg);
void facemgr_cfg_dump(facemgr_cfg_t * cfg);

/* Rules */

typedef struct facemgr_cfg_rule_s facemgr_cfg_rule_t;

facemgr_cfg_rule_t * facemgr_cfg_rule_create();
void facemgr_cfg_rule_free(facemgr_cfg_rule_t * rule);
int facemgr_cfg_rule_initialize(facemgr_cfg_rule_t * rule);
int facemgr_cfg_rule_finalize(facemgr_cfg_rule_t * rule);

int facemgr_cfg_rule_set_match(facemgr_cfg_rule_t * rule,
        const char * interface_name, netdevice_type_t interface_type);

int facemgr_cfg_rule_set_face_type(facemgr_cfg_rule_t * cfg_rule, facemgr_face_type_t * face_type);
int facemgr_cfg_rule_unset_face_type(facemgr_cfg_rule_t * cfg_rule);

int facemgr_cfg_rule_set_discovery(facemgr_cfg_rule_t * cfg_rule, bool status);
int facemgr_cfg_rule_unset_discovery(facemgr_cfg_rule_t * cfg_rule);

int facemgr_cfg_rule_set_ignore(facemgr_cfg_rule_t * cfg_rule, bool status);
int facemgr_cfg_rule_unset_ignore(facemgr_cfg_rule_t * cfg_rule);

int facemgr_cfg_rule_set_ipv4(facemgr_cfg_rule_t * cfg_rule, bool status);
int facemgr_cfg_rule_unset_ipv4(facemgr_cfg_rule_t * cfg_rule);

int facemgr_cfg_rule_set_ipv6(facemgr_cfg_rule_t * cfg_rule, bool status);
int facemgr_cfg_rule_unset_ipv6(facemgr_cfg_rule_t * cfg_rule);

int facemgr_cfg_rule_set_overlay(facemgr_cfg_rule_t * rule, int family,
    ip_address_t * local_addr, uint16_t local_port,
    ip_address_t * remote_addr, uint16_t remote_port);
int facemgr_rule_unset_overlay(facemgr_cfg_rule_t * rule, int family);

/* General */
int facemgr_cfg_set_face_type(facemgr_cfg_t * cfg, facemgr_face_type_t * face_type);
int facemgr_cfg_unset_face_type(facemgr_cfg_t * cfg);
int facemgr_cfg_set_discovery(facemgr_cfg_t * cfg, bool status);
int facemgr_cfg_unset_discovery(facemgr_cfg_t * cfg);
int facemgr_cfg_set_ipv4(facemgr_cfg_t * cfg, bool status);
int facemgr_cfg_unset_ipv4(facemgr_cfg_t * cfg);
int facemgr_cfg_set_ipv6(facemgr_cfg_t * cfg, bool status);
int facemgr_cfg_unset_ipv6(facemgr_cfg_t * cfg);

int facemgr_cfg_set_overlay(facemgr_cfg_t * cfg, int family,
    ip_address_t * local_addr, uint16_t local_port,
    ip_address_t * remote_addr, uint16_t remote_port);
int facemgr_cfg_unset_overlay(facemgr_cfg_t * cfg, int family);


int facemgr_cfg_add_rule(facemgr_cfg_t * cfg, facemgr_cfg_rule_t * rule);
int facemgr_cfg_del_rule(facemgr_cfg_t * cfg, facemgr_cfg_rule_t * rule);
int facemgr_cfg_get_rule(const facemgr_cfg_t * cfg, const char * interface_name,
        netdevice_type_t interface_type, facemgr_cfg_rule_t ** rule);

/* Log */

/*
 * Query API
 *
 * Takes the overrides into account
 *
 * TODO : interface_types are currently not taken into account by this API
 */

int facemgr_cfg_get_face_type(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        facemgr_face_type_t * face_type);
int facemgr_cfg_get_discovery(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        bool * discovery);
int facemgr_cfg_get_ignore(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        bool * ignore);
int facemgr_cfg_get_ipv4(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        bool * ipv4);
int facemgr_cfg_get_ipv6(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        bool * ipv6);
int facemgr_cfg_get_overlay_local_addr(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        int family, ip_address_t * addr);
int facemgr_cfg_get_overlay_local_port(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        int family, u16 * port);
int facemgr_cfg_get_overlay_remote_addr(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        int family, ip_address_t * addr);
int facemgr_cfg_get_overlay_remote_port(const facemgr_cfg_t * cfg,
        const netdevice_t * netdevice, netdevice_type_t netdevice_type,
        int family, u16 * port);

int facemgr_cfg_rule_get(const facemgr_cfg_t * cfg, const netdevice_t netdevice,
        netdevice_type_t netdevice_type, facemgr_cfg_rule_t ** rule);
int facemgr_cfg_rule_get_face_type(const facemgr_cfg_rule_t * cfg_rule, facemgr_face_type_t * face_type);
int facemgr_cfg_rule_get_discovery(const facemgr_cfg_rule_t * cfg_rule, bool * status);
int facemgr_cfg_rule_get_ignore(const facemgr_cfg_rule_t * cfg_rule, bool * status);
int facemgr_cfg_rule_get_ipv4(const facemgr_cfg_rule_t * cfg_rule, bool * status);
int facemgr_cfg_rule_get_ipv6(const facemgr_cfg_rule_t * cfg_rule, bool * status);
int facemgr_cfg_rule_get_overlay_local_addr(const facemgr_cfg_rule_t * rule, int family,
        ip_address_t * addr);
int facemgr_cfg_rule_get_overlay_local_port(const facemgr_cfg_rule_t * rule, int family,
        uint16_t * port);
int facemgr_cfg_rule_get_overlay_remote_addr(const facemgr_cfg_rule_t * rule, int family,
        ip_address_t * addr);
int facemgr_cfg_rule_get_overlay_remote_port(const facemgr_cfg_rule_t * rule, int family,
        uint16_t * port);

int facemgr_cfg_add_static_facelet(facemgr_cfg_t * cfg, facelet_t * facelet);
int facemgr_cfg_remove_static_facelet(facemgr_cfg_t * cfg, facelet_t * facelet,
        facelet_t ** removed_facelet);
int facemgr_cfg_get_static_facelet_array(const facemgr_cfg_t * cfg, facelet_t *** array);

#endif /* FACEMGR_CFG_H */
