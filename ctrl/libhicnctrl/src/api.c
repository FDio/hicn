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
 * \file api.c
 * \brief Implementation of hICN control library API
 */

#include <assert.h>
#include <dlfcn.h>  // dlopen
#include <hicn/strategy.h>
#include <hicn/util/log.h>
#include <hicn/ctrl/route.h>
#include <math.h>  // log2

#include "api_private.h"
#include "object_vft.h"
#include "request.h"

#include <hicn/ctrl/socket.h>
#include "socket_private.h"

#define ENOIMPL 42

int hc_sock_on_init(hc_sock_t *s, hc_request_t *request) {
  int rc;
  ssize_t size;

  uint8_t *buffer;

  size = s->ops.prepare(s, request, &buffer);
  if (size < 0) goto ERR_PREPARE;

  if (size == 0) return 1; /* Done */

  assert(hc_request_get_data(hc_request_get_current(request)));

  rc = s->ops.send(s, buffer, size);
  if (rc < 0) goto ERR_SEND;

  return 0;

ERR_PREPARE:
ERR_SEND:
  return -1;
}

int hc_sock_on_receive(hc_sock_t *s, size_t count) {
  int rc;

  DEBUG("hc_sock_on_receive: calling process with count=%ld", count);
  rc = s->ops.process(s, count);
  if (rc < 0) goto ERR_PROCESS;

  hc_request_t *request = hc_sock_get_request(s);
  hc_request_t *current_request = hc_request_get_current(request);
  hc_data_t *data = hc_request_get_data(current_request);
  if (hc_data_is_complete(data)) {
    /*
     * We only notice a request is complete when trying to send the second
     * time... either the state machine reaches the end, or in case of generic
     * requests, we mark it as such.
     */
  ON_INIT:
    rc = hc_sock_on_init(s, request);
    if (rc < 0) goto ERR_INIT;
    if (rc == 1) {
      if (!hc_request_pop(request)) {
        /* Free request context */
        /* In case of error, data is NULL */
        // hc_sock_free_request(s, request);
        if (!hc_request_is_subscription(request))
          hc_request_set_complete(request);
        return 1; /* Done */
      }
      goto ON_INIT;
    }
#if 0
    }
#endif
  }
  return 0; /* Continue processing */

ERR_INIT:
ERR_PROCESS:
  return -1;
}

// -1 error
// 0 = request is not yet complete
// 1 request is complete
int hc_sock_receive(hc_sock_t *s, hc_data_t **pdata) {
  int rc;
  DEBUG("Waiting for data...");
  rc = s->ops.recv(s);
  if (rc < 0) return -1;

  rc = hc_sock_on_receive(s, 0);
  if (rc < 0) return -1;

  hc_request_t *request = hc_sock_get_request(s);
  /*
   * If notification, display it, ideally callback. What to do with
   * allocated data ?
   */
  // XXX problem we display object on ACK... but not subsequent
  // notifications
  // XXX we should rely on callback here in addition, even for a synchronous
  // request
  if (hc_request_is_subscription(request)) {
    hc_data_t *data = hc_request_get_data(request);
    assert(data);
    hc_object_t *obj = (hc_object_t *)hc_data_get_buffer(data);
    char buf[MAXSZ_HC_OBJECT];
    hc_object_type_t object_type = hc_data_get_object_type(data);
    if (hc_object_snprintf(buf, sizeof(buf), object_type, obj) > 0) {
      ;
      INFO("%s %s", object_type_str(object_type), buf);
    }
  }

  // XXX need same for async
  if (rc != 1) return 0;

  hc_request_t *current_request = hc_request_get_current(request);
  if (hc_request_is_complete(current_request)) {
    /* We either return the (last) allocated data, or free it */
    if (pdata) {
      *pdata = hc_request_get_data(request);
    } else {
      hc_request_reset_data(request);
    }
    hc_request_on_complete(request);
    // hc_sock_free_request(s, request);
  }
  return 1;
}

int hc_sock_receive_all(hc_sock_t *s, hc_data_t **pdata) {
  for (;;) {
    int rc = hc_sock_receive(s, pdata);
    if (rc < 0) return -1;

    /* If request is complete, stop */
    if (rc == 1) break;
  }
  return 0;
}

/**
 * @return <0 in case of error
 *   -1 : validation error
 *   -2 : error during send
 *   -3 : error receiving or parsing
 *
 * If the caller provider a non-NULL hc_data_t pointer to receive results
 * back, it is responsible for freeing it.
 */
int _hc_execute(hc_sock_t *s, hc_action_t action, hc_object_type_t object_type,
                hc_object_t *object, hc_result_callback_t callback,
                void *callback_data, hc_data_t **pdata) {
  assert(!(hc_sock_is_async(s) && pdata));

  if (hc_sock_is_async(s) && !s->ops.get_fd) {
    return -1; /* No async support */
  }

  // XXX no need to pass pdata to the request
  // XXX sync socket, no multiplexed requests, no notifications
  /*
   * The request will contain all state needed to identify and demultiplex
   * replies and notifications arriving on the socket. We assume there is at
   * most a single request/reply in progress for a given request, and that
   * requests involving multiple queries will run them sequentially. The use
   * of a sequence number that is transported by the requests and reply is
   * thus sufficient to disambiguate them.
   */
  hc_request_t *request = hc_sock_create_request(s, action, object_type, object,
                                                 callback, callback_data);
  if (!request) {
    goto ERR_REQUEST;
  }

  if (hc_request_requires_object(request)) {
    if (hc_object_is_empty(object) ||
        hc_object_validate(object_type, object, true) < 0) {
      goto ERR_VALIDATE;
    }
  } else {
    if (object && !hc_object_is_empty(object)) {
      goto ERR_CHECK;
    }
  }

  /* Workaround for non-fd based modules */
  if (s->ops.prepare && s->ops.send && s->ops.recv && s->ops.process) {
    if (hc_sock_on_init(s, request) < 0) goto ERR_INIT;

    if (hc_sock_is_async(s)) return 0;

    if (hc_sock_receive_all(s, pdata) < 0) goto ERR_RECV;
  } else if (s->ops.prepare) {
    // hc_data_t *data = hc_data_create(OBJECT_TYPE_LISTENER);
    // hc_data_push(data, NULL);
    // No nested requests for now...
    ssize_t size = s->ops.prepare(s, request, NULL);
    _ASSERT(size == 0); /* Done */
    if (hc_request_is_complete(request)) {
      if (pdata) {
        *pdata = hc_request_get_data(request);
      } else {
        hc_request_reset_data(request);
      }
      hc_request_on_complete(request);
    }
  }

  return 0;

ERR_RECV:
  hc_request_reset_data(request);
ERR_INIT:
  hc_sock_free_request(s, request, true);
ERR_CHECK:
ERR_REQUEST:
ERR_VALIDATE:
  if (pdata) *pdata = NULL;
  return -1;
}

int hc_execute(hc_sock_t *s, hc_action_t action, hc_object_type_t object_type,
               hc_object_t *object, hc_data_t **pdata) {
  return _hc_execute(s, action, object_type, object, NULL, NULL, pdata);
}

int hc_execute_async(hc_sock_t *s, hc_action_t action,
                     hc_object_type_t object_type, hc_object_t *object,
                     hc_result_callback_t callback, void *callback_data) {
  return _hc_execute(s, action, object_type, object, callback, callback_data,
                     NULL);
}

/*----------------------------------------------------------------------------*
 * VFT
 *----------------------------------------------------------------------------*/

int hc_object_create(hc_sock_t *s, hc_object_type_t object_type,
                     hc_object_t *object) {
  return hc_execute(s, ACTION_CREATE, object_type, object, NULL);
}

int hc_object_get(hc_sock_t *s, hc_object_type_t object_type,
                  hc_object_t *object, hc_object_t **found) {
  return hc_execute(s, ACTION_GET, object_type, object, NULL);
}

int hc_object_find(hc_sock_t *s, hc_object_type_t object_type, hc_data_t *data,
                   const hc_object_t *element, hc_object_t **found) {
// XXX NOT IMPLEMENTED
#if 0
  foreach_type(hc_object_t, x, data) {
    if (hc_object_cmp(x, element) == 0) {
      *found = x;
      return 0;
    }
  };
#endif
  *found = NULL; /* this is optional */
  return 0;
}

int hc_object_delete(hc_sock_t *s, hc_object_type_t object_type,
                     hc_object_t *object) {
  return hc_execute(s, ACTION_DELETE, object_type, object, NULL);
}

int hc_object_list(hc_sock_t *s, hc_object_type_t object_type,
                   hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, object_type, NULL, pdata);
}
