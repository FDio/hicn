/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file request.h
 * \brief Pending requests.
 */

#ifndef HC_REQUEST_H
#define HC_REQUEST_H

#include <stdbool.h>

#include <hicn/ctrl/action.h>
#include <hicn/ctrl/callback.h>
#include <hicn/ctrl/data.h>
#include <hicn/ctrl/object.h>

#if 0
typedef int (*HC_PARSE)(const uint8_t *, uint8_t *);
#endif

#define foreach_request_state           \
  _(UNDEFINED)                          \
  _(INIT)                               \
  _(CONNECTION_CREATE_LISTENER_LIST)    \
  _(CONNECTION_CREATE_LISTENER_ITERATE) \
  _(CONNECTION_CREATE_LISTENER_GET)     \
  _(CONNECTION_CREATE_LISTENER_VERIFY)  \
  _(CONNECTION_CREATE_LISTENER_CREATE)  \
  _(CONNECTION_CREATE_LISTENER_CHECK)   \
  _(CONNECTION_CREATE)                  \
  _(CONNECTION_CREATE_N)                \
  _(FACE_CREATE_CONNECTION_CREATE)      \
  _(FACE_CREATE_CONNECTION_CHECK)       \
  _(FACE_CREATE_CONNECTION_GET)         \
  _(FACE_CREATE_CONNECTION_VERIFY)      \
  _(FACE_CREATE_LISTENER_CREATE)        \
  _(FACE_CREATE_LISTENER_CHECK)         \
  _(FACE_LIST_CONNECTION_LIST)          \
  _(ROUTE_CREATE_FACE_CREATE)           \
  _(ROUTE_CREATE_FACE_CHECK)            \
  _(ROUTE_CREATE)                       \
  _(GET_LIST)                           \
  _(COMPLETE)                           \
  _(N)

typedef enum {
#define _(x) REQUEST_STATE_##x,
  foreach_request_state
#undef _
} hc_request_state_t;

extern const char *hc_request_state_str[];

#define hc_request_state_str(x) hc_request_state_str[x]

/*
 * Internal state associated to a pending request
 */
typedef struct hc_request_s hc_request_t;

hc_request_t *hc_request_create(int seq, hc_action_t action,
                                hc_object_type_t object_type,
                                hc_object_t *object,
                                hc_result_callback_t callback,
                                void *callback_data);

void hc_request_free(hc_request_t *request);

void hc_request_set(hc_request_t *request, hc_action_t action,
                    hc_object_type_t object_type, hc_object_t *object);

int hc_request_get_seq(const hc_request_t *request);
hc_request_t *hc_request_get_current(hc_request_t *request);
hc_request_t *hc_request_pop(hc_request_t *request);

hc_request_state_t hc_request_get_state(const hc_request_t *request);
void hc_request_set_state(hc_request_t *request, hc_request_state_t state);

int hc_request_get_state_count(const hc_request_t *request);
void hc_request_set_state_count(hc_request_t *request, unsigned count);

hc_action_t hc_request_get_action(const hc_request_t *request);
hc_object_type_t hc_request_get_object_type(const hc_request_t *request);
hc_object_t *hc_request_get_object(const hc_request_t *request);
hc_data_t *hc_request_get_data(const hc_request_t *request);
void hc_request_set_data(hc_request_t *request, hc_data_t *data);
void hc_request_reset_data(hc_request_t *request);

bool hc_request_is_subscription(const hc_request_t *request);
bool hc_request_requires_object(const hc_request_t *request);

// do not free data which might be invalid
// XXX to be removed if we replace "ensure_data_size_and_free" functions and the
// like, with equivalent functions acting on request
void hc_request_clear_data(hc_request_t *request);

void hc_request_set_complete(hc_request_t *request);
bool hc_request_is_complete(const hc_request_t *request);

void hc_request_on_complete(hc_request_t *request);
void hc_request_on_notification(hc_request_t *request);

/*
 * Same seq & callbacks
 */
hc_request_t *hc_request_make_subrequest(hc_request_t *request,
                                         hc_action_t action,
                                         hc_object_type_t object_type,
                                         hc_object_t *object);

#endif /* HC_REQUEST_H */
