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
 * \file request.c
 * \brief Implementation of pending requests.
 */

#include <assert.h>
#include <stdlib.h>

#include <hicn/util/log.h>

#include "request.h"

const char *hc_request_state_str[] = {
#define _(x) [REQUEST_STATE_##x] = #x,
    foreach_request_state
#undef _
};

struct hc_request_s {
  int seq;
  hc_action_t action;
  hc_object_type_t object_type;
  hc_object_t *object;

#if 0
  int (*parse)(const uint8_t *src, uint8_t *dst);
#endif

  /* Callbacks */
  hc_result_callback_t callback;
  void *callback_data;

  /* Temp data used for the execution of the request */
  hc_data_t *data;

  /* Nested requests support
   *
   * In order to answer complex requests, involving a combination of requests to
   * the forwarder, we will allow maintaining a Finite State Machine in the
   * requests (and a tree of requests)
   *
   * The entry point for the modules will always remain the initial request,
   * however, we will chain nested requests in their parent fields, and point to
   * the one currently under execution in current.
   * */
  hc_request_state_t state;
  unsigned state_count; /* Usefor for iterative requests */
  hc_request_t *parent;
  hc_request_t *current;
};

hc_request_t *hc_request_create(int seq, hc_action_t action,
                                hc_object_type_t object_type,
                                hc_object_t *object,
                                hc_result_callback_t callback,
                                void *callback_data) {
  hc_request_t *request = malloc(sizeof(hc_request_t));
  if (!request) return NULL;
  request->seq = seq;

  request->action = action;
  request->object_type = object_type;
  request->object = object;

  request->callback = callback;
  request->callback_data = callback_data;

  request->data = NULL;

  request->state = REQUEST_STATE_INIT;
  request->state_count = 0;
  request->parent = NULL;
  request->current = NULL;

  return request;
}

void hc_request_free(hc_request_t *request) { free(request); }

void hc_request_set(hc_request_t *request, hc_action_t action,
                    hc_object_type_t object_type, hc_object_t *object) {
  request->action = action;
  request->object_type = object_type;
  request->object = object;
}

int hc_request_get_seq(const hc_request_t *request) { return request->seq; }

hc_request_t *hc_request_get_current(hc_request_t *request) {
  return request->current ? request->current : request;
}

hc_request_t *hc_request_pop(hc_request_t *request) {
  hc_request_t *current_request = hc_request_get_current(request);
  hc_request_t *parent = current_request->parent;
  request->current = parent;
  if (parent) {
    parent->data = current_request->data;
    /* We only free the current_request if it was not the root */
    hc_request_free(current_request);
  }
  return parent;
}

hc_request_state_t hc_request_get_state(const hc_request_t *request) {
  return request->state;
}

void hc_request_set_state(hc_request_t *request, hc_request_state_t state) {
  request->state = state;
}

int hc_request_get_state_count(const hc_request_t *request) {
  return request->state_count;
}

void hc_request_set_state_count(hc_request_t *request, unsigned count) {
  request->state_count = count;
}

hc_action_t hc_request_get_action(const hc_request_t *request) {
  return request->action;
}

hc_object_type_t hc_request_get_object_type(const hc_request_t *request) {
  return request->object_type;
}

hc_object_t *hc_request_get_object(const hc_request_t *request) {
  return request->object;
}

hc_data_t *hc_request_get_data(const hc_request_t *request) {
  return request->data;
}

void hc_request_set_data(hc_request_t *request, hc_data_t *data) {
  assert(!request->data);
  request->data = data;
}

void hc_request_reset_data(hc_request_t *request) {
  if (!request->data) return;
  hc_data_free(request->data);
  request->data = NULL;
}

bool hc_request_is_subscription(const hc_request_t *request) {
  hc_action_t action = hc_request_get_action(request);
  hc_object_type_t object_type = hc_request_get_object_type(request);
  return (action == ACTION_SUBSCRIBE) ||
         (action == ACTION_CREATE && object_type == OBJECT_TYPE_SUBSCRIPTION);
}

bool hc_request_requires_object(const hc_request_t *request) {
  hc_action_t action = hc_request_get_action(request);
  return (action != ACTION_LIST) && (action != ACTION_SUBSCRIBE);
}

void hc_request_clear_data(hc_request_t *request) { request->data = NULL; }

void hc_request_set_complete(hc_request_t *request) {
  request->state = REQUEST_STATE_COMPLETE;
}

bool hc_request_is_complete(const hc_request_t *request) {
  return request->state == REQUEST_STATE_COMPLETE;
}

void hc_request_on_complete(hc_request_t *request) {
  // request->state = REQUEST_STATE_COMPLETE;
  if (!request->callback) return;
  request->callback(request->data, request->callback_data);
}

void hc_request_on_notification(hc_request_t *request) {
  if (!request->callback) return;
  request->callback(request->data, request->callback_data);
}

hc_request_t *hc_request_make_subrequest(hc_request_t *request,
                                         hc_action_t action,
                                         hc_object_type_t object_type,
                                         hc_object_t *object) {
  hc_request_t *sr =
      hc_request_create(request->seq, action, object_type, object,
                        request->callback, request->callback_data);

  /* The parent is either the current one, or the request itself if NULL */
  hc_request_t *current_request = hc_request_get_current(request);
  hc_request_reset_data(current_request);
  sr->parent = current_request;
  request->current = sr;
  return sr;
}
