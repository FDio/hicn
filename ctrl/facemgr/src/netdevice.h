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
 * \file netdevice.h
 * \brief Netdevice abstraction
 */
#ifndef FACEMGR_NETDEVICE_H
#define FACEMGR_NETDEVICE_H

#include <net/if.h> // IFNAMSIZ

#include "common.h"

#define foreach_netdevice_type  \
    _(UNDEFINED)                \
    _(WIRED)                    \
    _(WIFI)                     \
    _(CELLULAR)                 \
    _(VPN)                      \
    _(N)

#define MAXSZ_NETDEVICE_TYPE 9
#define MAXSZ_NETDEVICE_TYPE_ MAXSZ_NETDEVICE_TYPE

typedef enum {
#define _(x) x,
foreach_netdevice_type
#undef _
} netdevice_type_t;

extern const char * netdevice_type_str[];


typedef struct {
    u32 index;
    char name[IFNAMSIZ];
} netdevice_t;

#endif /* FACEMGR_NETDEVICE_H */
