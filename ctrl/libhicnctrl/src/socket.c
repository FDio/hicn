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
 * \file socket.c
 * \brief Implementation of control socket.
 */

#include <dlfcn.h>
#include <stdio.h>

#include <hicn/ctrl/socket.h>
#include <hicn/util/log.h>

#ifdef ANDROID
/*
 * In android we do not load a module at runtime but we link the hicnlight
 * implementation directly to the main library.
 */
#include "modules/hicn_light.h"
#endif /* ANDROID */

#include "socket_private.h"

TYPEDEF_MAP(hc_sock_map, int, hc_request_t *, int_cmp, int_snprintf,
            generic_snprintf);

const char *forwarder_type_str[] = {
#define _(x) [FORWARDER_TYPE_##x] = #x,
    foreach_forwarder_type
#undef _
};

forwarder_type_t forwarder_type_from_str(const char *str) {
  for (forwarder_type_t i = FORWARDER_TYPE_UNDEFINED + 1; i < FORWARDER_TYPE_N;
       i++) {
    if (strcasecmp(str, forwarder_type_str[i]) == 0) return i;
  }
  return FORWARDER_TYPE_UNDEFINED;
}

#ifndef ANDROID
static int hc_sock_set_ops(hc_sock_t *s, const char *name, const char *url) {
  char complete_name[128];
#ifdef __APPLE__
  sprintf(complete_name, "%s.dylib", name);
#elif defined(__linux__)
  snprintf(complete_name, 128, "%s.so", name);
#else
#error "System not supported for dynamic lynking"
#endif

  void *handle = 0;
  const char *error = 0;
  int (*initialize_module)(hc_sock_t *) = 0;
  int rc = 0;

  // open module
  handle = dlopen(complete_name, RTLD_LAZY);
  if (!handle) {
    if ((error = dlerror()) != 0) {
      ERROR("%s", error);
    }
    goto ERR_DL;
    return -1;
  }
  s->handle = handle;

  // get factory method
  initialize_module =
      (int (*)(hc_sock_t *))dlsym(handle, "hc_sock_initialize_module");
  if (!initialize_module) {
    if ((error = dlerror()) != 0) {
      ERROR("%s", error);
    }
    goto ERR_INIT;
  }
  initialize_module(s);

  return rc;
ERR_INIT:
  dlclose(s->handle);
  s->handle = NULL;
ERR_DL:
  return -1;
}
#endif /* ! ANDROID */

int hc_sock_is_async(hc_sock_t *s) { return s->async; }

int hc_sock_set_async(hc_sock_t *s) {
  s->async = true;
  return 0;
}

hc_sock_t *hc_sock_create(forwarder_type_t forwarder, const char *url) {
#ifndef ANDROID
  int rc;
#endif

  hc_sock_t *s = malloc(sizeof(hc_sock_t));
  if (!s) goto ERR_MALLOC;

#ifdef ANDROID
  assert(forwarder == HICNLIGHT);
  s->data = hc_sock_light_data_create(url);
  s->handle = NULL;
#else
  switch (forwarder) {
    case FORWARDER_TYPE_HICNLIGHT:
      rc = hc_sock_set_ops(s, "hicnlightctrl_module", url);
      break;
    case FORWARDER_TYPE_VPP:
      rc = hc_sock_set_ops(s, "vppctrl_module", url);
      break;
    default:
      goto ERR_INIT;
  }

  if (rc < 0) goto ERR_INIT;

  s->data = s->ops.create_data(url);
#endif

  if (!s->data) goto ERR_DATA;

  s->map = hc_sock_map_create();
  if (!s->map) goto ERR_MAP;

  s->async = false;

  s->seq_request = 0;
  s->current_request = NULL;

  return s;

ERR_MAP:
#ifdef ANDROID
  hc_sock_light_data_free(s->data);
#else
    ;  // XXX VFT() free
#endif
ERR_DATA:
#ifndef ANDROID
ERR_INIT:
#endif
  free(s);
ERR_MALLOC:
  return NULL;
}

void hc_sock_free(hc_sock_t *s) {
  if (s->ops.disconnect) s->ops.disconnect(s);
#ifdef ANDROID
  hc_sock_light_data_free(s->data);
#else
  if (s->ops.free_data) s->ops.free_data(s->data);
  if (s->handle) {
    dlclose(s->handle);
  }
#endif /* ANDROID */

  hc_request_t **request_array = NULL;
  int n = hc_sock_map_get_value_array(s->map, &request_array);
  if (n < 0) {
    ERROR("Could not retrieve pending request array for freeing up resources");
  } else {
    for (unsigned i = 0; i < n; i++) {
      hc_request_t *request = request_array[i];
      if (hc_sock_map_remove(s->map, hc_request_get_seq(request), NULL) < 0)
        ERROR("[hc_sock_light_process] Error removing request from map");
      hc_request_free(request);
    }
    free(request_array);
  }

  hc_sock_map_free(s->map);

  free(s);
}

#if 0
int hc_sock_get_next_seq(hc_sock_t *s) { return s->hc_sock_get_next_seq(s); }

int hc_sock_set_nonblocking(hc_sock_t *s) { return s->hc_sock_get_next_seq(s); }

#endif

int hc_sock_get_fd(hc_sock_t *s) { return s->ops.get_fd(s); }

int hc_sock_connect(hc_sock_t *s) { return s->ops.connect(s); }

int hc_sock_get_recv_buffer(hc_sock_t *s, u8 **buffer, size_t *size) {
  return s->ops.get_recv_buffer(s, buffer, size);
}
#if 0

int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, uint32_t seq) {
  return s->hc_sock_send(s, msg, msglen, seq);
}

int hc_sock_recv(hc_sock_t *s) { return s->ops.recv(s); }
#endif

#if 0
int hc_sock_process(hc_sock_t *s, hc_data_t **data) {
  return s->hc_sock_process(s, data);
}

int hc_sock_callback(hc_sock_t *s, hc_data_t **data) {
  return s->hc_sock_callback(s, data);
}

int hc_sock_reset(hc_sock_t *s) { return s->hc_sock_reset(s); }

void hc_sock_increment_woff(hc_sock_t *s, size_t bytes) {
  s->hc_sock_increment_woff(s, bytes);
}

int hc_sock_prepare_send(hc_sock_t *s, hc_result_t *result,
                         data_callback_t complete_cb, void *complete_cb_data) {
  return s->hc_sock_prepare_send(s, result, complete_cb, complete_cb_data);
}

int hc_sock_set_recv_timeout_ms(hc_sock_t *s, long timeout_ms) {
  return s->hc_sock_set_recv_timeout_ms(s, timeout_ms);
}
#endif

hc_request_t *hc_sock_create_request(hc_sock_t *s, hc_action_t action,
                                     hc_object_type_t object_type,
                                     hc_object_t *object,
                                     hc_result_callback_t callback,
                                     void *callback_data) {
  /* Create request state */
  int seq = s->seq_request++;
  hc_request_t *request = hc_request_create(seq, action, object_type, object,
                                            callback, callback_data);
  if (!request) goto ERR_MALLOC;

  hc_request_set_state(request, REQUEST_STATE_INIT);

  // Add state to map
  if (hc_sock_map_add(s->map, seq, request) < 0) {
    ERROR("[hc_sock_create_request] Error adding request state to map");
    goto ERR_MAP;
  }

  return request;

ERR_MAP:
  free(request);
ERR_MALLOC:
  return NULL;
}

hc_request_t *hc_sock_get_request(hc_sock_t *s) { return s->current_request; }

void hc_sock_free_request(hc_sock_t *s, hc_request_t *request, bool recursive) {
  if (hc_sock_map_remove(s->map, hc_request_get_seq(request), NULL) < 0) {
    ERROR("[hc_sock_free_request] Error removing request from map");
  }
  if (recursive) {
    hc_request_t *r = NULL;
    do {
      r = hc_request_pop(request);
    } while (r);
  }
  hc_request_free(request);
  s->current_request = NULL;
}

/**
 * TODO: return code:
 * -1 object not found
 * -2 action not found
 * -3 error during serialization
 *
 * @return the size of the created message
 */
ssize_t hc_sock_serialize_object(hc_sock_t *s, hc_action_t action,
                                 hc_object_type_t object_type,
                                 hc_object_t *object, uint8_t *msg) {
  hc_serialize_t fn = (s->ops.object_vft[object_type]).serialize[action];
  if (!fn) return -1;
  return fn(object, msg);
}

int hc_sock_parse_object(hc_sock_t *s, hc_object_type_t object_type,
                         uint8_t *buffer, size_t size, hc_object_t *object) {
  return s->ops.object_vft[object_type].parse(buffer, size, object);
}
