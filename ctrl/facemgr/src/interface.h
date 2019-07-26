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
 * \file interface.h
 * \brief Interface base class
 *
 * Interfaces are the priviledged way to extend the functionalities of the face
 * manager. They both provide input and/or output functionality to allow for
 * several components to interoperate, respectively by raising/receiving events
 * about changes in the underlying network.
 *
 * All communication happens through base operations (create, delete, etc.) over
 * a generic face abstraction.
 */
#ifndef FACEMGR_INTERFACE_H
#define FACEMGR_INTERFACE_H

#include <stdbool.h>

struct event_s;
typedef int (*callback_t)(struct event_s * event, void * callback_data);

struct interface_s;
struct face_rules_s;

/**
 * \brief Interface operations
 */
typedef struct {
    char * type;
    bool is_singleton;
    int (*initialize)(struct interface_s * interface, struct face_rules_s * rules, void ** pdata);
    int (*finalize)(struct interface_s * interface);
    int (*callback)(struct interface_s * interface);
    int (*on_event)(struct interface_s * interface, const struct event_s * event);
} interface_ops_t;

typedef struct interface_s {
    char * name;
    interface_ops_t * ops;
    callback_t callback;
    void * callback_data;
    void * data;
} interface_t;

/**
 * \brief Registers a new interface type
 * \param [in] ops - Virtual function table representing the interface
 *     operations.
 * \return Flag indicating the success (FACEMGR_SUCCESS=0), or failure (any
 *     other value) of the operation.
 */
int interface_register(const interface_ops_t * ops);

/**
 * \brief Create a new instance of an interface of a given type.
 * \param [in] name - Name of the newly create interface instance.
 * \param [in] type - Name of the interface type to create.
 * \return A a pointer to the newly created instance of the requested type, or
 *     NULL in case of failure.
 */
interface_t * interface_create(const char * name, const char * type);

/**
 * \brief Free an interface instance.
 * \param [in] interface - Pointer to the instance to free.
 */
void interface_free(interface_t * interface);

/**
 * This function is equivalent to interface_set_callback, which should be
 * preferred. The difference is the lack of explicit type casts which should
 * simplify the calling syntax.
 */

void _interface_set_callback(interface_t * interface, callback_t callback, void * callback_data);
#define interface_set_callback(interface, callback, callback_data) \
    _interface_set_callback(interface, (callback_t)callback, (void*)callback_data)

int interface_initialize(interface_t * interface, struct face_rules_s * rules);
int interface_finalize(interface_t * interface);

int interface_on_event(interface_t * interface, const struct event_s * event);

#endif /* FACEMGR_INTERFACE_H */
