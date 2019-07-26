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
 * \file facemgr.h
 * \brief Face manager library interface
 */
#ifndef FACEMGR_H
#define FACEMGR_H

#include <string.h>
#include "common.h"
#include "face.h"
#include "face_cache.h"
#include "face_rules.h"
#include "interface.h"
#include "interface_map.h"
#include "util/ip_address.h"
#include "util/map.h"
#include "util/policy.h"
#ifndef __APPLE__
#include <event2/event.h>
#endif /* __APPLE__ */

/*
 * \brief Face manager context
 */
typedef struct {
#ifndef APPLE
    /* Event loop */
    struct event_base * loop;
#endif /* APPLE */

    interface_map_t interface_map;
    interface_t * hl;

#ifdef __APPLE__
    interface_t * nf;
#endif /* __APPLE__ */

#ifdef __linux__
    interface_t * nl;
#endif /* __linux__ */

#if 0
    interface_t * dummy;
#endif

    /* Overlay management */
    uint16_t overlay_v4_local_port;
    ip_address_t overlay_v4_remote_addr;
    uint16_t overlay_v4_remote_port;
    uint16_t overlay_v6_local_port;
    ip_address_t overlay_v6_remote_addr;
    uint16_t overlay_v6_remote_port;

    face_rules_t rules;
    face_cache_t face_cache;
} facemgr_t;

AUTOGENERATE_DEFS(facemgr);

int facemgr_bootstrap(facemgr_t * facemgr);

#endif /* FACEMGR_H */
