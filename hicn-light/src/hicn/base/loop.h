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

/* Global loop to be used in single threaded applications */
extern loop_t * MAIN_LOOP;

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
 * \brief Registers a new file descriptor to the event loop
 * \param [in] fd - File descriptor to register
 * \param [in] callback_owner - Pointer to the owner of the callack (first
 *      parameter of callback function)
 * \param [in] callback - Callback function
 * \param [in] callback_data - User data to pass alongside callback invocation
 * \return 0 in case of success, -1 otherwise
 */
int
loop_register_fd(loop_t * loop, int fd, void * callback_owner,
        fd_callback_t callback, void * callback_data);

/**
 * \brief Unregisters a file descriptor from the event loop
 * \param [in] fd - File descriptor to unregister
 * \return 0 in case of success, -1 otherwise
 */
int
loop_unregister_fd(loop_t * loop, int fd);

int
loop_register_timer(loop_t * loop, timer_callback_data_t * timer_callback_data);

int
loop_unregister_timer(loop_t * loop, int fd);

#endif /* FACEMGR_LOOP_H */
