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
 * \file dummy.c
 * \brief Implementation of Dummy interface
 */

#include <stdlib.h>

#include "../../interface.h"
#include "../../common.h"
#include "../../event.h"
#include "../../face.h"
#include "../../facemgr.h"

#define DEFAULT_PORT 9695

int dummy_initialize(interface_t * interface, face_rules_t * rules, void **pdata) {
    ip_address_t local = IPV4_LOOPBACK;
    ip_address_t remote = IPV4_LOOPBACK;
    face_t * face = face_create_udp(&local, DEFAULT_PORT, &remote, DEFAULT_PORT, AF_INET);
    event_raise(EVENT_TYPE_CREATE, face, interface);
    return FACEMGR_SUCCESS;
}

int dummy_finalize(interface_t * interface) {
    return FACEMGR_SUCCESS;
}

interface_ops_t dummy_ops = {
    .type = "dummy",
    .is_singleton = true,
    .initialize = dummy_initialize,
    .finalize = dummy_finalize,
    .on_event = NULL,
};
