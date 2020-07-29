/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef UTIL_LOOP_H
#define UTIL_LOOP_H

/* fd & timer callbacks */

typedef int (*fd_callback_t)(void *owner, int fd, void *data);

typedef struct {
    int fd;
    void *owner;
    fd_callback_t callback;
    void *data;
} fd_callback_data_t;

/* loop */

typedef struct loop_s loop_t;
typedef struct event_s event_t;

extern loop_t *MAIN_LOOP;

/**
 * \brief Creates a main loop
 * \return Pointer to the newly created loop, or NULL in case of error
 */
loop_t *loop_create();

/**
 * \brief Releases a loop instance and frees all associated memory
 * \param [in] loop - Pointer to the loop instance to free
 */
void loop_free(loop_t *loop);

/**
 * \brief Runs the loop instance to process events
 * \param [in] loop - Pointer to the loop instance
 * \return 0 if successful, -1 otherwise
 */
int loop_dispatch(loop_t *loop);

/**
 * \brief Terminates the dispatching of events
 * \param [in] loop - Pointer to the loop instance
 */
int loop_undispatch(loop_t *loop);

/**
 * \brief Breaks out of the loop
 * \param [in] loop - Pointer to the loop instance
 */
void loop_break(loop_t *loop);

/** Create new event associated with given fd.
 * \param [out] event - Struct representing new fd event
 * \param [in] loop - Loop running events
 * \param [in] fd - fd to register
 * \param [in] callback_owner - Pointer to the owner of the callack (first
 *      parameter of callback function)
 * \param [in] callback - Callback function
 * \param [in] callback_data - User data to pass alongside callback invocation
 * \return 0 in case of success, -1 otherwise
 */
int loop_fd_event_create(event_t **event, loop_t *loop, int fd,
                         void *callback_owner, fd_callback_t callback,
                         void *callback_data);

/**
 * Register event in corresponding event loop.
 * \param [in] event - Struct representing fd event
 * \return 0 in case of success, -1 otherwise
 */
int loop_fd_event_register(event_t *event);

/**
 * Unregister event from corresponding event loop.
 * \param [in] event - Struct representing fd event
 * \return 0 in case of success, -1 otherwise
 */
int loop_event_unregister(event_t *event);

/**
 * Free event object.
 * \param [in] event - Struct representing the event
 * \return 0 in case of success, -1 otherwise
 */
int loop_event_free(event_t *event);

/** Create new timer event.
 * \param [out] event - Struct representing new timer event
 * \param [in] loop - Loop running events
 * \param [in] callback_owner - Pointer to the owner of the callack (first
 *      parameter of callback function)
 * \param [in] callback - Callback function
 * \param [in] callback_data - User data to pass alongside callback invocation
 * \return 0 in case of success, -1 otherwise
 */
int loop_timer_create(event_t **timer, loop_t *loop, void *callback_owner,
                      fd_callback_t callback, void *callback_data);

/**
 * Register event in corresponding event loop.
 * \param [in] timer - Struct representing timer event
 * \return 0 in case of success, -1 otherwise
 */
int loop_timer_register(event_t *timer, unsigned delay_ms);

/**
 * Check if timer is enabled.
 * \param [in] timer - Struct representing timer event
 * \return 1 if enabled, 0 otherwise
 */
int loop_timer_is_enabled(event_t *timer);

#endif /* UTIL_LOOP_H */
