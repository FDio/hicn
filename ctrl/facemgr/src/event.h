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
 * \file event.h
 * \brief Face event
 */
#ifndef FACEMGR_EVENT_H
#define FACEMGR_EVENT_H

#include "face.h"
#include "interface.h"

#define foreach_event_type      \
    _(UNDEFINED)                \
    _(CREATE)                   \
    _(UPDATE)                   \
    _(DELETE)                   \
    _(SET_PARAMS)               \
    _(SET_UP)                   \
    _(SET_DOWN)                 \
    _(SET_TAGS)                 \
    _(CLEAR_TAGS)               \
    _(ADD_TAG)                  \
    _(REMOVE_TAG)               \
    _(N)

#define MAXSZ_EVENT_TYPE_ 10
#define MAXSZ_EVENT_TYPE MAXSZ_EVENT_TYPE_ + 1

typedef enum {
#define _(x) EVENT_TYPE_ ## x,
foreach_event_type
#undef _
} event_type_t;

extern const char * event_type_str[];

typedef struct event_s {
    event_type_t type;
    const face_t * face; /* + bitfield for face fields ? */
} event_t;

int
event_raise(event_type_t type, const face_t * face, const interface_t * interface);

#endif /* FACEMGR_EVENT_H */
