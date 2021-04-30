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
#include <hicn/facemgr/loop.h>

typedef enum {
    INTERFACE_CB_TYPE_REGISTER_FD,
    INTERFACE_CB_TYPE_UNREGISTER_FD,
    INTERFACE_CB_TYPE_RAISE_EVENT,
    INTERFACE_CB_TYPE_REGISTER_TIMER,
    INTERFACE_CB_TYPE_UNREGISTER_TIMER,
} interface_cb_type_t;

typedef int (*interface_cb_t)(facemgr_t * facemgr, interface_cb_type_t type, void * data);

/**
 * \brief Interface operations
 */
struct interface_s;
typedef struct {
    /** The type given to the interfaces */
    char * type;
    /* Constructor */
    int (*initialize)(struct interface_s * interface, void * cfg);
    /* Destructor */
    int (*finalize)(struct interface_s * interface);
    /* Callback upon file descriptor event (iif previously registered) */
    int (*callback)(struct interface_s * interface, int fd, void * data);
    /* Callback upon face events coming from the face manager */
    int (*on_event)(struct interface_s * interface, struct facelet_s * facelet);
} interface_ops_t;

typedef struct interface_s {
    char * name;
    const interface_ops_t * ops;

    interface_cb_t callback;
    void * callback_owner;

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

int interface_unregister_all();

/**
 * \brief Unregister all interface types
 */
int interface_unregister_all();

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


void interface_set_callback(interface_t * interface, void * callback_owner, interface_cb_t callback);

int interface_initialize(interface_t * interface, void * cfg);

int interface_finalize(interface_t * interface);

int interface_on_event(interface_t * interface, struct facelet_s * facelet);

/**
 * \brief Raises a facelet event to the face manager
 * \param [in] interface - Interface that raised the event (or NULL if it was
 *      created but the face manager itself, or is a joined event)
 * \param [in] facelet - Facelet to communicate with the event
 * \return Error code
 */
int interface_callback(interface_t * interface, interface_cb_type_t type, void * data);

int interface_raise_event(interface_t * interface, facelet_t * facelet);

int interface_register_fd(interface_t * interface, int fd, void * data);

int interface_unregister_fd(interface_t * interface, int fd);

typedef int (*interface_fd_callback_t)(interface_t * interface, int fd, void * unused);

/**
 * \brief Registers a timer event
 * \param [in] interface - Pointer to the interface responsible for the timer
 * \param [in] delay_ms - Delay in milliseconds between timer events (first
 *      occurence happends after this delay)
 * \param [in] callback - Callback function to be triggered
 * \param [in] data - User data
 * \return A positive value uniquely identifying the timer, or -1 in case of
 *      error
 */
int interface_register_timer(interface_t * interface, unsigned delay_ms,
        interface_fd_callback_t callback, void * data);

/**
 * \brief Unregisters a timer event
 * \param [in] interface - Pointer to the interface responsible for the timer
 * \param [in] fd - Timer identifier
 * \return 0 in case of success, -1 otherwise
 */
int interface_unregister_timer(interface_t * interface, int fd);

#endif /* FACEMGR_INTERFACE_H */
