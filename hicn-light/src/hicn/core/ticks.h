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
 * @brief The router periodically measures time in units of Ticks
 *
 * See forwarder.c HZ which specifies the tick rate.  forwarder.h has functions
 * to convert between ticks and milliseconds.
 *
 */
#ifndef ticks_h
#define ticks_h

#define __STDC_FORMAT_MACROS
#include <stdint.h>
#include <time.h>

#include <sys/param.h> // HZ


typedef uint64_t Ticks;

// these will all be a little off because its all integer division
#define NSEC_PER_TICK ((1000000000ULL) / HZ)
#define NSEC_TO_TICKS(nsec) ((nsec < NSEC_PER_TICK) ? 1 : nsec / NSEC_PER_TICK)

#define TICKS_TO_NSEC(ticks) ((1000000000ULL) * ticks / HZ)

static inline
Ticks
ticks_now()
{
#if __linux__
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1e6;
#elif _WIN32
    struct timespec ts;
    _clock_gettime(TIME_UTC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1e6;
#else
    clock_serv_t clockService;
    mach_timespec_t ts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &clockService);
    clock_get_time(clockService, &mts);
    mach_port_deallocate(mach_task_self(), clockService);
#endif

    return ts.tv_sec * 1000 + ts.tv_nsec / 1e6;
}

#endif  // ticks_h
