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
 * \file loop.h
 * \brief Face manager main loop
 */

#ifndef FACEMGR_LOOP_H
#define FACEMGR_LOOP_H

#include <hicn/facemgr/api.h>

/* fd & timer callbacks */

typedef int (*fd_callback_t)(void * owner, int fd, void * data);

typedef struct {
    int fd;
    void *owner;
    fd_callback_t callback;
    //int (*callback)(void * owner, int fd, void * data);
    void *data;
} fd_callback_data_t;

/* timer callbacks */
typedef struct {
    unsigned delay_ms;
    void *owner;
    fd_callback_t callback;
    //int (*callback)(void * owner, int fd, void * data);
    void *data;
} timer_callback_data_t;

/* loop */

typedef struct loop_s loop_t;

/**
 * \brief Creates a main loop
 * \return Pointer to the newly created loop, or NULL in case of error
 */
loop_t * loop_create();

/**
 * \brief Releases a loop instance and frees all associated memory
 * \param [in] loop - Pointer to the loop instance to free
 */
void loop_free(loop_t * loop);

/**
 * \brief Runs the loop instance to process events
 * \param [in] loop - Pointer to the loop instance
 * \return 0 if successful, -1 otherwise
 */
int loop_dispatch(loop_t * loop);

/**
 * \brief Terminates the dispatching of events
 * \param [in] loop - Pointer to the loop instance
 */
int loop_undispatch(loop_t * loop);

/**
 * \brief Breaks out of the loop
 * \param [in] loop - Pointer to the loop instance
 */
void loop_break(loop_t * loop);


/**
 * \brief Callback for loop helpers
 * \param [in] loop - Pointer to the loop instance
 * \param [in] type - Type of service to be requested
 * \param [in] data - Service specific data
 */
int loop_callback(loop_t * loop, facemgr_cb_type_t type, void * data);

#endif /* FACEMGR_LOOP_H */
