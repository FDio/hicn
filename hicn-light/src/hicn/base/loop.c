/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * @file loop.c
 * @brief Implementation of event loop based on libevent
 */

#include <apr_pools.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/thread.h>
#include <fcntl.h>  // fcntl
#ifdef WITH_THREAD
#include <pthread.h>
#endif /* WITH_THREAD */
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <stdlib.h>
#include <unistd.h>  // fcntl

#include "loop.h"

/**
 * Lifetime of loops should be as long as the lifetime of the process, hence the
 * static pool of memory to allocate them.
 */
static apr_pool_t *global_loop_pool = NULL;

loop_t *MAIN_LOOP = NULL;

/**
 * \brief Holds all callback parameters
 */
typedef struct {
    void *owner;
    fd_callback_t callback;
    void *data;
} cb_wrapper_args_t;

typedef enum {
    EVTYPE_TIMER,
    EVTYPE_FD,
} event_type_t;

struct loop_s {
    /* Libevent-based implementation */
    struct event_base *event_base;

    /* Pool to allocate events */
    apr_pool_t *pool;
};

struct event_s {
    /* Reference to loop */
    loop_t *loop;

    /* Event type*/
    event_type_t event_type;

    /* Raw event */
    struct event raw_event;

    /* Callback on event */
    cb_wrapper_args_t callback;
};

loop_t *loop_create()
{
    apr_status_t rc;

    if (!global_loop_pool) {
        rc = apr_pool_create(&global_loop_pool, NULL);
        if (rc) {
            ERROR("[loop_create] Failed to allocate global memory pool");
        }
    }

    loop_t *loop = apr_palloc(global_loop_pool, sizeof(loop_t));
    if (!loop) {
        ERROR("[loop_create] Failed to allocate memory");
        goto ERR_MALLOC;
    }

#ifdef WITH_THREAD
    evthread_use_pthreads();
#endif /* WITH_THREAD */

    loop->event_base = event_base_new();
    if (!loop) goto ERR_EVENT;

    rc = apr_pool_create(&loop->pool, global_loop_pool);
    if (rc) {
        ERROR("[loop_create] Failed to allocate global memory pool");
    }

    event_set_log_callback(NULL);

    return loop;

ERR_EVENT:
ERR_MALLOC:
    return NULL;
}

void loop_free(loop_t *loop) { event_base_free(loop->event_base); }

int loop_dispatch(loop_t *loop)
{
    event_base_loop(loop->event_base, 0);
    return 0;
}

void loop_break(loop_t *loop) { event_base_loopbreak(loop->event_base); }

void cb_wrapper(evutil_socket_t fd, short what, void *arg)
{
    cb_wrapper_args_t *cb_wrapper_args = arg;
    cb_wrapper_args->callback(cb_wrapper_args->owner, fd,
                              cb_wrapper_args->data);
}

static inline void _event_create(event_t *event, loop_t *loop,
                                 event_type_t type, void *callback_owner,
                                 fd_callback_t callback, void *callback_data)
{
    event = apr_palloc(loop->pool, sizeof(event_t));
    event->callback = (cb_wrapper_args_t){
        .owner = callback_owner,
        .callback = callback,
        .data = callback_data,
    };
    event->event_type = type;
    event->loop = loop;
}

int loop_fd_event_create(event_t *event, loop_t *loop, int fd,
                         void *callback_owner, fd_callback_t callback,
                         void *callback_data)
{
    _event_create(event, loop, EVTYPE_FD, callback_owner, callback,
                  callback_data);

    evutil_make_socket_nonblocking(fd);
    event_assign(&event->raw_event, loop->event_base, fd, EV_READ | EV_PERSIST,
                 cb_wrapper, &event->callback);

    return 0;
}

int loop_fd_event_register(event_t *event)
{
    assert(event->event_type == EVTYPE_FD);

    if (event_add(&event->raw_event, NULL) < 0) {
        ERROR("[loop_register_fd] event_add");
        goto ERR_EVENT_ADD;
    }

    return 0;

ERR_EVENT_ADD:
    return -1;
}

int loop_fd_event_unregister(event_t *event)
{
    assert(event->event_type == EVTYPE_FD);
    event_del(&event->raw_event);
    return 0;
}

int loop_timer_create(event_t *timer, loop_t *loop, void *callback_owner,
                      fd_callback_t callback, void *callback_data)
{
    _event_create(timer, loop, EVTYPE_TIMER, callback_owner, callback,
                  callback_data);

    evtimer_assign(&timer->raw_event, loop->event_base, cb_wrapper,
                   &timer->callback);

    return 0;
}

static inline void _ms_to_timeval(unsigned delay_ms, struct timeval *tv)
{
    tv->tv_sec = delay_ms / 1000;
    tv->tv_usec = (delay_ms % 1000) * 1000;
}

int loop_timer_register(event_t *timer, unsigned delay_ms)
{
    struct timeval tv;
    _ms_to_timeval(delay_ms, &tv);

    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
        event_active(&timer->raw_event, EV_TIMEOUT, 0);
    } else {
        event_add(&timer->raw_event, &tv);
    }

    return 0;
}

int loop_timer_is_enabled(event_t *timer)
{
    return evtimer_pending(&timer->raw_event, NULL) != 0;
}

int loop_timer_unregister(event_t *timer)
{
    event_del(&timer->raw_event);
    return 0;
}
