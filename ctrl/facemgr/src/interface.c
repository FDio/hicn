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
 * \file interface.c
 * \brief Implementation of interface base class.
 */

#include <stdlib.h>
#include <string.h>
#include "event.h"
#include "face_rules.h"
#include "interface.h"
#include "interface_ops_map.h"
#include "util/map.h"

static interface_ops_map_t * interface_ops_map = NULL;

int
interface_register(const interface_ops_t * ops)
{
    if (!interface_ops_map) {
        interface_ops_map = interface_ops_map_create();
        if (!interface_ops_map)
            return FACEMGR_FAILURE;
    }
    interface_ops_map_add(interface_ops_map, ops->type, ops);
    return FACEMGR_SUCCESS;
}

interface_t *
interface_create(const char * name, const char * type)
{

    interface_ops_t * ops;
    int rc = interface_ops_map_get(interface_ops_map, type, &ops);
    if (FACEMGR_IS_ERROR(rc)) {
        printf("Interface type not found %s\n", type);
        return NULL;
    }

    interface_t * interface = malloc(sizeof(interface_t));
    if (!interface)
        return NULL;

    interface->name = strdup(name);
    /* this should use type */
    interface->ops = ops;
    interface->callback = NULL;
    interface->callback_data = NULL;
    interface->data = NULL;

    return interface;
}

void
interface_free(interface_t * interface)
{
    free(interface->name);
    free(interface);
}

void
_interface_set_callback(interface_t * interface, callback_t callback, void * callback_data)
{
    interface->callback = callback;
    interface->callback_data = callback_data;
}

int
interface_initialize(interface_t * interface, struct face_rules_s * rules)
{
    if (!interface->ops->initialize)
        return FACEMGR_FAILURE;
    return interface->ops->initialize(interface, rules, &interface->data);
}

int
interface_finalize(interface_t * interface)
{
    if (!interface->ops->finalize)
        return FACEMGR_FAILURE;
    return interface->ops->finalize(interface);
}

int
interface_on_event(interface_t * interface, const event_t * event)
{
    if (!interface->ops->on_event)
        return FACEMGR_FAILURE;
    return interface->ops->on_event(interface, event);
}
