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

#include <assert.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <fcntl.h> // fcntl
#ifdef WITH_THREAD
#include <pthread.h>
#endif /* WITH_THREAD */
#include <stdlib.h>
#include <sys/timerfd.h>
#include <unistd.h> // fcntl

#include <hicn/util/log.h>
#include <hicn/util/map.h>

#include "loop.h"

/**
 * \brief Holds all callback parameters
 */
typedef struct {
    void * owner;
    fd_callback_t callback;
    void * data;
} cb_wrapper_args_t;

TYPEDEF_MAP_H(event_map, int, struct event *);
TYPEDEF_MAP(event_map, int, struct event *, int_cmp, int_snprintf, generic_snprintf);

/* Map that associates timer fds with their associated cb_wrapper_args_t */
TYPEDEF_MAP_H(timer_fd_map, int, cb_wrapper_args_t *);
TYPEDEF_MAP(timer_fd_map, int, cb_wrapper_args_t *, int_cmp, int_snprintf, generic_snprintf);

struct loop_s {
    struct event_base * event_base;
    event_map_t * event_map;
    timer_fd_map_t * timer_fd_map;
#ifdef WITH_THREAD
    pthread_t thread;
#endif /* WITH_THREAD */
};

loop_t *
loop_create()
{
    loop_t * loop = malloc(sizeof(loop_t));
    if (!loop) {
        ERROR("[loop_create] Failed to allocate memory");
        goto ERR_MALLOC;
    }

#ifdef WITH_THREAD
    evthread_use_pthreads();
#endif /* WITH_THREAD */

    loop->event_base = event_base_new();
    if (!loop)
        goto ERR_EVENT;

    loop->event_map = event_map_create();
    if (!loop->event_map) {
        ERROR("[loop_create] Failed to create event_map");
        goto ERR_EVENT_MAP;
    }

    loop->timer_fd_map = timer_fd_map_create();
    if (!loop->timer_fd_map) {
        ERROR("[loop_create] Failed to create timer_fd_map");
        goto ERR_TIMER_FD_MAP;
    }

    event_set_log_callback(NULL);

    return loop;

    timer_fd_map_free(loop->timer_fd_map);
ERR_TIMER_FD_MAP:
    event_map_free(loop->event_map);
ERR_EVENT_MAP:
    event_base_free(loop->event_base);
ERR_EVENT:
    free(loop);
ERR_MALLOC:
    return NULL;
}

void
loop_free(loop_t * loop)
{
    /*
     * Release all timer cb_wrapper_args_t
     *
     * We need to stop all timers, this should release associated fd events at
     * the same time... for that reason, this code has to be called before
     * releasing events
     */

    int * timer_fd_map_array;
    int n = timer_fd_map_get_key_array(loop->timer_fd_map, &timer_fd_map_array);
    if (n < 0) {
        ERROR("[loop_free] Could not get event map array");
    } else {
        for (unsigned i = 0; i < n; i++) {
            int fd = timer_fd_map_array[i];
            if (loop_unregister_timer(loop, fd) < 0) {
                ERROR("[loop_free] Could not unregister timer");
            }
        }
        free(timer_fd_map_array);
    }
    timer_fd_map_free(loop->timer_fd_map);

    /* Release all events */

    int * event_map_array;
    n = event_map_get_key_array(loop->event_map, &event_map_array);
    if (n < 0) {
        ERROR("[loop_free] Could not get event map array");
    } else {
        for (unsigned i = 0; i < n; i++) {
            int fd = event_map_array[i];
            if (loop_unregister_fd(loop, fd) < 0) {
                ERROR("[loop_free] Could not unregister fd");
            }
        }
        free(event_map_array);
    }
    event_map_free(loop->event_map);

    event_base_free(loop->event_base);

    free(loop);
}

int
loop_dispatch(loop_t * loop)
{
#ifdef WITH_THREAD
    if (pthread_create(&loop->thread, NULL, (void * (*)(void *))event_base_dispatch, loop->event_base)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }
#else
    event_base_dispatch(loop->event_base);
#endif /* WITH_THREAD */
    return 0;
}

int
loop_undispatch(loop_t * loop)
{
#ifdef WITH_THREAD
    DEBUG("Waiting for loop to terminate...");
    if(pthread_join(loop->thread, NULL)) {
        fprintf(stderr, "Error joining thread\n");
        return -1;
    }
    DEBUG("Loop terminated !");
#endif /* WITH_THREAD */
    return 0;
}

void
loop_break(loop_t * loop)
{
    event_base_loopbreak(loop->event_base);
}

void cb_wrapper(evutil_socket_t fd, short what, void * arg) {
    cb_wrapper_args_t * cb_wrapper_args = arg;
    cb_wrapper_args->callback(cb_wrapper_args->owner, fd, cb_wrapper_args->data);
}

int
loop_register_fd(loop_t * loop, int fd, void * callback_owner,
        fd_callback_t callback, void * callback_data)
{
    /* This will be freed with the event */
    cb_wrapper_args_t * cb_wrapper_args = malloc(sizeof(cb_wrapper_args_t));
    *cb_wrapper_args = (cb_wrapper_args_t) {
        .owner = callback_owner,
        .callback = callback,
        .data = callback_data,
    };

    evutil_make_socket_nonblocking(fd);
    struct event * event = event_new(loop->event_base, fd, EV_READ | EV_PERSIST, cb_wrapper, cb_wrapper_args);
    if (!event) {
        ERROR("[loop_register_fd] event_new");
        goto ERR_EVENT_NEW;
    }

    if (event_add(event, NULL) < 0) {
        ERROR("[loop_register_fd] event_add");
        goto ERR_EVENT_ADD;
    }

    if (event_map_add(loop->event_map, fd, event) < 0) {
        ERROR("[loop_register_fd] event_map_add");
        goto ERR_EVENT_MAP;
    }

    return 0;

ERR_EVENT_MAP:
ERR_EVENT_ADD:
    event_free(event);
ERR_EVENT_NEW:
    return -1;
}

int
loop_unregister_fd(loop_t * loop, int fd)
{
    struct event * event = NULL;

    if (event_map_remove(loop->event_map, fd, &event) < 0) {
        ERROR("[loop_unregister_fd] Error removing event associated to fd");
        return -1;
    }

    assert(event);

    cb_wrapper_args_t * cb_wrapper_args = event_get_callback_arg(event);
    free(cb_wrapper_args);

    event_del(event);
    event_free(event);

    return 0;
}

int
loop_timer_callback(loop_t * loop, int fd, void * data)
{
    char buf[1024]; /* size is not important */
    cb_wrapper_args_t * cb_wrapper_args = data;
    while (read(fd, &buf, sizeof(buf)) > 0)
        ;

    int rc = cb_wrapper_args->callback(cb_wrapper_args->owner, fd,
            cb_wrapper_args->data);

    return rc;
}

int
_loop_register_timer(loop_t * loop, unsigned delay_ms, void * owner,
        fd_callback_t callback, void * data)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fd == -1) {
        perror("timerfd_create");
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl");
        return -1;
    }

    struct itimerspec ts = {
        .it_interval = {
            .tv_sec = delay_ms / 1000,
            .tv_nsec = (delay_ms % 1000) * 1000000,
        },
        .it_value = {
            .tv_sec = delay_ms / 1000,
            .tv_nsec = (delay_ms % 1000) * 1000000,
        }
    };

    if (timerfd_settime(fd, 0, &ts, NULL) == -1) {
        perror("timerfd_settime");
        return -1;
    }

    /* This should be freed together with the timer release */
    cb_wrapper_args_t * cb_wrapper_args = malloc(sizeof(cb_wrapper_args_t));
    *cb_wrapper_args = (cb_wrapper_args_t) {
        .owner = owner,
            .callback = callback,
            .data = data,
    };

    if (timer_fd_map_add(loop->timer_fd_map, fd, cb_wrapper_args) < 0) {
        ERROR("[loop_register_timer] Could not add cb_wrapper to timer map");
        return -1;
    }

    if (loop_register_fd(loop, fd, loop,
                (fd_callback_t) loop_timer_callback, cb_wrapper_args) < 0) {
        ERROR("[loop_register_timer] Error registering fd to event loop");
        return -1;
    }

    return fd;
}

int
loop_unregister_timer(loop_t * loop, int fd)
{
    struct itimerspec ts = {
        .it_interval = {
            .tv_sec = 0,
            .tv_nsec = 0,
        },
        .it_value = { /* This value disables the timer */
            .tv_sec = 0,
            .tv_nsec = 0,
        }
    };
    ts.it_value.tv_sec = 0;

    if (timerfd_settime(fd, 0, &ts, NULL) == -1) {
        perror("timerfd_settime");
        return -1;
    }

    cb_wrapper_args_t * cb_wrapper_args;
    if (timer_fd_map_remove(loop->timer_fd_map, fd, &cb_wrapper_args) < 0) {
        ERROR("[loop_unregister_timer] Could not remove cb_wrapper from timer map");
        return -1;
    }
    assert(cb_wrapper_args);
    free(cb_wrapper_args);

    if (loop_unregister_fd(loop, fd) < 0) {
        ERROR("[loop_unregister_timer] Error unregistering fd from event loop");
        return -1;
    }

    return 0;
}
