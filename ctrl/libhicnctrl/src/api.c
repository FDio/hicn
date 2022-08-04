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

#if 0
/* /!\ Please update constants in public header file upon changes */
const char * connection_state_str[] = {
#define _(x) [HC_CONNECTION_STATE_##x] = STRINGIZE(x),
foreach_connection_state
#undef _
};

/* /!\ Please update constants in public header file upon changes */
const char * connection_type_str[] = {
#define _(x) [CONNECTION_TYPE_##x] = STRINGIZE(x),
foreach_connection_type
#undef _
};

hc_connection_type_t
connection_type_from_str(const char * str)
{
    if (strcasecmp(str, "TCP") == 0)
        return CONNECTION_TYPE_TCP;
    else if (strcasecmp(str, "UDP") == 0)
        return CONNECTION_TYPE_UDP;
    else if (strcasecmp(str, "HICN") == 0)
        return CONNECTION_TYPE_HICN;
    else
        return CONNECTION_TYPE_UNDEFINED;
}
#endif

/******************************************************************************
 * Control Data
 ******************************************************************************/

/*----------------------------------------------------------------------------*
 * Object model
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * Entry point
 *----------------------------------------------------------------------------*/

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
#if 0
    if (hc_request_is_complete(current_request)) {
      if (!hc_request_pop(request)) {
        /* Free request context */
        /* In case of error, data is NULL */
        // XXX bug if we free request XXX
        // hc_sock_free_request(s, request);
        if (!hc_request_is_subscription(request))
          hc_request_set_complete(request);
        return 1; /* Done */
      }
    } else {
#endif
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

    /* Case in which no reply is expected */
    if (!pdata) return 0;

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

/* This function has to be called after the first execute until data and
 * request are complete */
// execute is just setting things up so that we can keep on calling this
// function repeatedly until completion.
//
// in the caller, we don't know how much we will receive in advance... so in
// asio for instance, we will use async_receive rather than async_read.
// XXX the question remains about the buffers...

/*
 * request -> write command
 *
 * SYNC : hc_data_t
 * ASYNC : provide socket-level callback
 *
 * socket available -> read -> parse -> populate data
 * data complete ->
 */

/******************************************************************************
 * OBJECT-SPECIFIC FUNCTIONS (backwards compatibility)
 ******************************************************************************/

/*----------------------------------------------------------------------------*
 * FACE
 *
 * This is an abstraction provided for when the module does not implement
 *it. Alternative is to move it to hicn light
 *----------------------------------------------------------------------------*/

#if 0

/* FACE -> LISTENER */


/* LISTENER -> FACE */

int hc_listener_to_face(const hc_listener_t *listener, hc_face_t *face) {
  return -1; /* XXX Not implemented */
}

/* FACE -> CONNECTION */


/* CONNECTION -> FACE */
/* CONNECTION -> LISTENER */


/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

int hc_punting_create(hc_sock_t *s, hc_punting_t *punting) {
  return s->hc_punting_create(s, punting);
}

int hc_punting_get(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found) {
  return s->hc_punting_get(s, punting, punting_found);
}

int hc_punting_delete(hc_sock_t *s, hc_punting_t *punting) {
  return s->hc_punting_delete(s, punting);
}

int hc_punting_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_punting_list(s, pdata);
}

int hc_punting_validate(const hc_punting_t *punting) {
  if (!IS_VALID_FAMILY(punting->family)) return -1;

  /*
   * We might use the zero value to add punting on all faces but this is not
   * (yet) implemented
   */
  if (punting->face_id == 0) {
    ERROR("Punting on all faces is not (yet) implemented.");
    return -1;
  }

  return 0;
}

int hc_punting_cmp(const hc_punting_t *p1, const hc_punting_t *p2) {
  int rc;

  rc = INT_CMP(p1->face_id, p2->face_id);
  if (rc != 0) return rc;

  rc = INT_CMP(p1->family, p2->family);
  if (rc != 0) return rc;

  rc = ip_address_cmp(&p1->prefix, &p2->prefix);
  if (rc != 0) return rc;

  rc = INT_CMP(p1->prefix_len, p2->prefix_len);
  if (rc != 0) return rc;

  return rc;
}

#if 0
int hc_punting_parse(void *in, hc_punting_t *punting) {
  ERROR("hc_punting_parse not (yet) implemented.");
  return -1;
}
#endif

int hc_punting_snprintf(char *s, size_t size, hc_punting_t *punting) {
  ERROR("hc_punting_snprintf not (yet) implemented.");
  return -1;
}

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int hc_cache_set_store(hc_sock_t *s, hc_cache_t *cache) {
  return s->hc_cache_set_store(s, cache);
}

int hc_cache_set_serve(hc_sock_t *s, hc_cache_t *cache) {
  return s->hc_cache_set_serve(s, cache);
}

int hc_cache_clear(hc_sock_t *s, hc_cache_t *cache) {
  return s->hc_cache_clear(s, cache);
}

int hc_cache_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_cache_list(s, pdata);
}

int hc_cache_snprintf(char *s, size_t size, const hc_cache_info_t *cache_info) {
  return snprintf(
      s, size, "Cache set_store=%s set_serve=%s size=%lu stale_entries=%lu",
      cache_info->store ? "true" : "false",
      cache_info->serve ? "true" : "false", (unsigned long)cache_info->cs_size,
      (unsigned long)cache_info->num_stale_entries);
}

int hc_stats_snprintf(char *s, size_t size, const hicn_light_stats_t *stats) {
  return snprintf(
      s, size,
      "pkts processed: %u\n\tinterests: %u\n\t"
      "data: %u\npkts from cache count: %u\npkts no pit count: "
      "%u\nexpired:\n\t interests: "
      "%u\n\t data: %u\ninterests aggregated: "
      "%u\nlru evictions: "
      "%u\ndropped: "
      "%u\ninterests retx: "
      "%u\npit entries: %u\ncs entries: %u",
      stats->forwarder.countReceived, stats->forwarder.countInterestsReceived,
      stats->forwarder.countObjectsReceived,
      stats->forwarder.countInterestsSatisfiedFromStore,
      stats->forwarder.countDroppedNoReversePath,
      stats->forwarder.countInterestsExpired, stats->forwarder.countDataExpired,
      stats->pkt_cache.n_lru_evictions, stats->forwarder.countDropped,
      stats->forwarder.countInterestsAggregated,
      stats->forwarder.countInterestsRetransmitted,
      stats->pkt_cache.n_pit_entries, stats->pkt_cache.n_cs_entries);
}

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

int hc_wldr_set(hc_sock_t *s /* XXX */) { return s->hc_wldr_set(s); }

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

int hc_mapme_set(hc_sock_t *s, hc_mapme_t *mapme) {
  return s->hc_mapme_set(s, mapme->enabled);
}

int hc_mapme_set_discovery(hc_sock_t *s, hc_mapme_t *mapme) {
  return s->hc_mapme_set_discovery(s, mapme->enabled);
}

int hc_mapme_set_timescale(hc_sock_t *s, hc_mapme_t *mapme) {
  return s->hc_mapme_set_timescale(s, mapme->timescale);
}

int hc_mapme_set_retx(hc_sock_t *s, hc_mapme_t *mapme) {
  return s->hc_mapme_set_retx(s, mapme->timescale);
}

int hc_mapme_send_update(hc_sock_t *s, hc_mapme_t *mapme) {
  return s->hc_mapme_send_update(s, mapme);
}

/*----------------------------------------------------------------------------*
 * Policy
 *----------------------------------------------------------------------------*/


/* POLICY SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_policy_snprintf(char *s, size_t size, hc_policy_t *policy) { return 0; }

int hc_policy_validate(const hc_policy_t *policy, bool allow_partial) {
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  return 0;
}

#endif

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
