/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size,
                          data_callback_t complete_cb) {
  hc_data_t *data = malloc(sizeof(hc_data_t));
  if (!data) goto ERR_MALLOC;

  /* FIXME Could be NULL thanks to realloc provided size is 0 */
  data->max_size_log = DEFAULT_SIZE_LOG;
  data->in_element_size = in_element_size;
  data->out_element_size = out_element_size;
  data->size = 0;
  data->complete = false;
  data->command_id = 0;  // TODO this could also be a busy mark in the socket
  /* No callback needed in blocking code for instance */
  data->complete_cb = complete_cb;

  data->buffer = malloc((1 << data->max_size_log) * data->out_element_size);
  if (!data->buffer) goto ERR_BUFFER;
  data->ret = 0;
  data->current = 0;

  return data;

ERR_BUFFER:
  hc_data_free(data);
ERR_MALLOC:
  return NULL;
}

void hc_data_free(hc_data_t *data) {
  if (data) free(data->buffer);
  free(data);
}

int hc_data_ensure_available(hc_data_t *data, size_t count) {
  size_t new_size_log =
      (data->size + count - 1 > 0) ? log2(data->size + count - 1) + 1 : 0;
  if (new_size_log > data->max_size_log) {
    data->max_size_log = new_size_log;
    data->buffer =
        realloc(data->buffer, (1 << new_size_log) * data->out_element_size);
    if (!data->buffer) return -1;
  }

  return 0;
}

int hc_data_push_many(hc_data_t *data, const void *elements, size_t count) {
  if (hc_data_ensure_available(data, count) < 0) return -1;

  memcpy(data->buffer + data->size * data->out_element_size, elements,
         count * data->out_element_size);
  data->size += count;

  return 0;
}

int hc_data_push(hc_data_t *data, const void *element) {
  return hc_data_push_many(data, element, 1);
}

/**
 *
 * NOTE: This function make sure there is enough room available in the data
 * structure.
 */
u8 *hc_data_get_next(hc_data_t *data) {
  if (hc_data_ensure_available(data, 1) < 0) return NULL;

  return data->buffer + data->size * data->out_element_size;
}

int hc_data_set_callback(hc_data_t *data, data_callback_t cb, void *cb_data) {
  data->complete_cb = cb;
  data->complete_cb_data = cb_data;
  return 0;
}

int hc_data_set_complete(hc_data_t *data) {
  data->complete = true;
  data->ret = 0;
  if (data->complete_cb) return data->complete_cb(data, data->complete_cb_data);
  return 0;
}

int hc_data_set_error(hc_data_t *data) {
  data->ret = -1;
  return 0;
}

int hc_data_reset(hc_data_t *data) {
  data->size = 0;
  return 0;
}

static hc_sock_t *_open_module(const char *name, const char *url) {
  char complete_name[128];
#ifdef __APPLE__
  snprintf(complete_name, 128, "%s.dylib", name);
#elif defined(__linux__)
  snprintf(complete_name, 128, "%s.so", name);
#else
#error "System not supported for dynamic lynking"
#endif

  void *handle = 0;
  const char *error = 0;
  hc_sock_t *(*creator)(const char *) = 0;
  hc_sock_t *ret = 0;

  // open module
  handle = dlopen(complete_name, RTLD_LAZY);
  if (!handle) {
    if ((error = dlerror()) != 0) {
      ERROR("%s", error);
    }
    return 0;
  }

  // get factory method
  creator =
      (hc_sock_t * (*)(const char *)) dlsym(handle, "_hc_sock_create_url");
  if (!creator) {
    if ((error = dlerror()) != 0) {
      ERROR("%s", error);
    }
    return 0;
  }

  ret = (*creator)(NULL);
  ret->handle = handle;

  return ret;
}

hc_sock_t *hc_sock_create_forwarder_url(forwarder_type_t forwarder,
                                        const char *url) {
  switch (forwarder) {
    case HICNLIGHT:
      return _open_module("hicnlightctrl_module", url);
    case HICNLIGHT_NG:
      return _open_module("hicnlightngctrl_module", url);
    case VPP:
      return _open_module("vppctrl_module", url);
    default:
      return NULL;
  }
}

#ifdef ANDROID
// In android we do not load a module at runtime
// but we link the hicnlight implmentation directly
// to the main library
extern hc_sock_t *_hc_sock_create_url(const char *url);
#endif

hc_sock_t *hc_sock_create_forwarder(forwarder_type_t forwarder) {
#ifdef ANDROID
  assert(forwarder == HICNLIGHT_NG);
  hc_sock_t *ret = _hc_sock_create_url(NULL);
  ret->handle = NULL;
  return ret;
#else
  return hc_sock_create_forwarder_url(forwarder, NULL);
#endif
}

hc_sock_t *hc_sock_create(void) {
  return hc_sock_create_forwarder(HICNLIGHT_NG);
}

void hc_sock_free(hc_sock_t *s) {
  void *handle = s->handle;
  s->hc_sock_free(s);

  if (handle) {
    dlclose(handle);
  }
}

int hc_sock_get_next_seq(hc_sock_t *s) { return s->hc_sock_get_next_seq(s); }

int hc_sock_set_nonblocking(hc_sock_t *s) { return s->hc_sock_get_next_seq(s); }

int hc_sock_get_fd(hc_sock_t *s) { return s->hc_sock_get_fd(s); }

int hc_sock_connect(hc_sock_t *s) { return s->hc_sock_connect(s); }

int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size) {
  return s->hc_sock_get_available(s, buffer, size);
}

int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, uint32_t seq) {
  return s->hc_sock_send(s, msg, msglen, seq);
}

int hc_sock_recv(hc_sock_t *s) { return s->hc_sock_recv(s); }

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

/*----------------------------------------------------------------------------*
 * LISTENER
 *----------------------------------------------------------------------------*/

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener) {
  return s->hc_listener_create(s, listener);
}

hc_result_t *hc_listener_create_conf(hc_sock_t *s, hc_listener_t *listener) {
  return s->hc_listener_create_conf(s, listener);
}

int hc_listener_get(hc_sock_t *s, hc_listener_t *listener,
                    hc_listener_t **listener_found) {
  return s->hc_listener_get(s, listener, listener_found);
}

int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener) {
  return s->hc_listener_delete(s, listener);
}

int hc_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_listener_list(s, pdata);
}

GENERATE_FIND(listener);

/* LISTENER VALIDATE */

int hc_listener_validate(const hc_listener_t *listener) {
  if (!IS_VALID_NAME(listener->name)) {
    ERROR("[hc_listener_validate] Invalid name specified");
    return -1;
  }
  if (!IS_VALID_INTERFACE_NAME(listener->interface_name)) {
    ERROR("[hc_listener_validate] Invalid interface_name specified");
    return -1;
  }
  if (!IS_VALID_TYPE(listener->type)) {
    ERROR("[hc_listener_validate] Invalid type specified");
    return -1;
  }
  if (!IS_VALID_FAMILY(listener->family)) {
    ERROR("[hc_listener_validate] Invalid family specified");
    return -1;
  }
  if (!IS_VALID_ADDRESS(&listener->local_addr, listener->family)) {
    ERROR("[hc_listener_validate] Invalid local_addr specified");
    return -1;
  }
  if (!IS_VALID_PORT(listener->local_port)) {
    ERROR("[hc_listener_validate] Invalid local_port specified");
    return -1;
  }

  return 0;
}

/* LISTENER CMP */

int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2) {
  int rc;

  rc = INT_CMP(l1->type, l2->type);
  if (rc != 0) return rc;

  rc = INT_CMP(l1->family, l2->family);
  if (rc != 0) return rc;

  rc = strncmp(l1->interface_name, l2->interface_name, INTERFACE_LEN);
  if (rc != 0) return rc;

  rc = ip_address_cmp(&l1->local_addr, &l2->local_addr, l1->family);
  if (rc != 0) return rc;

  rc = INT_CMP(l1->local_port, l2->local_port);
  if (rc != 0) return rc;

  return rc;
}

/* LISTENER SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_listener_snprintf(char *s, size_t size, hc_listener_t *listener) {
  char local[MAXSZ_URL];
  int rc;
  rc = url_snprintf(local, MAXSZ_URL, listener->family, &listener->local_addr,
                    listener->local_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_listener_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s %s interface=%s", listener->name, local,
                  face_type_str(listener->type), listener->interface_name);
}

/*----------------------------------------------------------------------------*
 * CONNECTION
 *----------------------------------------------------------------------------*/

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection) {
  return s->hc_connection_create(s, connection);
}

hc_result_t *hc_connection_create_conf(hc_sock_t *s,
                                       hc_connection_t *connection) {
  return s->hc_connection_create_conf(s, connection);
}

int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_connection_t **connection_found) {
  return s->hc_connection_get(s, connection, connection_found);
}

int hc_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                               hc_connection_t *connection) {
  return s->hc_connection_update_by_id(s, hc_connection_id, connection);
}

int hc_connection_update(hc_sock_t *s, hc_connection_t *connection_current,
                         hc_connection_t *connection_updated) {
  return s->hc_connection_update(s, connection_current, connection_updated);
}

int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection) {
  return s->hc_connection_delete(s, connection);
}

hc_result_t *hc_connection_delete_conf(hc_sock_t *s,
                                       hc_connection_t *connection) {
  return s->hc_connection_delete_conf(s, connection);
}

int hc_connection_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_connection_list(s, pdata);
}

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state) {
  return s->hc_connection_set_admin_state(s, conn_id_or_name, state);
}

#ifdef WITH_POLICY
int hc_connection_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                               uint32_t priority) {
  return s->hc_connection_set_priority(s, conn_id_or_name, priority);
}

int hc_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                           policy_tags_t tags) {
  return s->hc_connection_set_tags(s, conn_id_or_name, tags);
}
#endif  // WITH_POLICY

GENERATE_FIND(connection);

/* CONNECTION VALIDATE */

int hc_connection_validate(const hc_connection_t *connection) {
  if (!IS_VALID_NAME(connection->name)) {
    ERROR("[hc_connection_validate] Invalid name specified");
    return -1;
  }
  if (!IS_VALID_INTERFACE_NAME(connection->interface_name)) {
    ERROR("[hc_connection_validate] Invalid interface_name specified");
    return -1;
  }
  if (!IS_VALID_TYPE(connection->type)) {
    ERROR("[hc_connection_validate] Invalid type specified");
    return -1;
  }
  if (!IS_VALID_FAMILY(connection->family)) {
    ERROR("[hc_connection_validate] Invalid family specified");
    return -1;
  }
  if (!IS_VALID_ADDRESS(&connection->local_addr, connection->family)) {
    ERROR("[hc_connection_validate] Invalid local_addr specified");
    return -1;
  }
  if (!IS_VALID_PORT(connection->local_port)) {
    ERROR("[hc_connection_validate] Invalid local_port specified");
    return -1;
  }
  if (!IS_VALID_ADDRESS(&connection->remote_addr, connection->family)) {
    ERROR("[hc_connection_validate] Invalid remote_addr specified");
    return -1;
  }
  if (!IS_VALID_PORT(connection->remote_port)) {
    ERROR("[hc_connection_validate] Invalid remote_port specified");
    return -1;
  }

  return 0;
}

/* CONNECTION CMP */

/*
 * hICN light uses ports even for hICN connections, but their value is ignored.
 * As connections are specific to hicn-light, we can safely use IP and ports for
 * comparison independently of the face type.
 */
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2) {
  int rc;

  rc = INT_CMP(c1->type, c2->type);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->family, c2->family);
  if (rc != 0) return rc;

  rc = strncmp(c1->interface_name, c2->interface_name, INTERFACE_LEN);
  if (rc != 0) return rc;

  rc = ip_address_cmp(&c1->local_addr, &c2->local_addr, c1->family);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->local_port, c2->local_port);
  if (rc != 0) return rc;

  rc = ip_address_cmp(&c1->remote_addr, &c2->remote_addr, c1->family);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->remote_port, c2->remote_port);
  if (rc != 0) return rc;

  return rc;
}

/* CONNECTION SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_connection_snprintf(char *s, size_t size,
                           const hc_connection_t *connection) {
  char local[MAXSZ_URL];
  char remote[MAXSZ_URL];
  int rc;

  // assert(connection->connection_state)
  if (strcmp(connection->name, "SELF") == 0) {
    return snprintf(s, size, "%s", connection->name);
  }

  rc = url_snprintf(local, MAXSZ_URL, connection->family,
                    &connection->local_addr, connection->local_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_connection_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;
  rc = url_snprintf(remote, MAXSZ_URL, connection->family,
                    &connection->remote_addr, connection->remote_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_connection_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s %s %s", connection->name, local, remote,
                  face_type_str(connection->type));
}

int hc_face_create(hc_sock_t *s, hc_face_t *face) {
  return s->hc_face_create(s, face);
}

int hc_face_get(hc_sock_t *s, hc_face_t *face, hc_face_t **face_found) {
  return s->hc_face_get(s, face, face_found);
}

int hc_face_delete(hc_sock_t *s, hc_face_t *face, uint8_t delete_listener) {
  return s->hc_face_delete(s, face, delete_listener);
}

int hc_face_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_face_list(s, pdata);
}

int hc_face_list_async(hc_sock_t *s) { return s->hc_face_list_async(s); }

int hc_face_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                            face_state_t state) {
  return s->hc_face_set_admin_state(s, conn_id_or_name, state);
}

#ifdef WITH_POLICY
int hc_face_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                         uint32_t priority) {
  return s->hc_face_set_priority(s, conn_id_or_name, priority);
}

int hc_face_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                     policy_tags_t tags) {
  return s->hc_face_set_tags(s, conn_id_or_name, tags);
}
#endif /* WITH_POLICY */

/* /!\ Please update constants in header file upon changes */
int hc_face_snprintf(char *s, size_t size, hc_face_t *face) {
  /* URLs are also big enough to contain IP addresses in the hICN case */
  char local[MAXSZ_URL];
  char remote[MAXSZ_URL];
#ifdef WITH_POLICY
  char tags[MAXSZ_POLICY_TAGS];
#endif /* WITH_POLICY */
  int rc;

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_HICN_LISTENER:
      rc = ip_address_snprintf(local, MAXSZ_URL, &face->face.local_addr,
                               face->face.family);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      rc = ip_address_snprintf(remote, MAXSZ_URL, &face->face.remote_addr,
                               face->face.family);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      break;
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      rc = url_snprintf(local, MAXSZ_URL, face->face.family,
                        &face->face.local_addr, face->face.local_port);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      rc = url_snprintf(remote, MAXSZ_URL, face->face.family,
                        &face->face.remote_addr, face->face.remote_port);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      break;
    default:
      return -1;
  }

    // [#ID NAME] TYPE LOCAL_URL REMOTE_URL STATE/ADMIN_STATE (TAGS)
#ifdef WITH_POLICY
  rc = policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->face.tags);
  if (rc >= MAXSZ_POLICY_TAGS)
    WARN("[hc_face_snprintf] Unexpected truncation of policy tags string");
  if (rc < 0) return rc;

  return snprintf(
      s, size, "[#%d %s] %s %s %s %s %s/%s [%d] (%s)", face->id, face->name,
      face->face.netdevice.index != NETDEVICE_UNDEFINED_INDEX
          ? face->face.netdevice.name
          : "*",
      face_type_str(face->face.type), local, remote,
      face_state_str(face->face.state), face_state_str(face->face.admin_state),
      face->face.priority, tags);
#else
  return snprintf(s, size, "[#%d %s] %s %s %s %s %s/%s", face->id, face->name,
                  face->face.netdevice.index != NETDEVICE_UNDEFINED_INDEX
                      ? face->face.netdevice.name
                      : "*",
                  face_type_str(face->face.type), local, remote,
                  face_state_str(face->face.state),
                  face_state_str(face->face.admin_state));
#endif /* WITH_POLICY */
}

/*----------------------------------------------------------------------------*
 * ROUTE
 *----------------------------------------------------------------------------*/

int hc_route_create(hc_sock_t *s, hc_route_t *route) {
  return s->hc_route_create(s, route);
}

hc_result_t *hc_route_create_conf(hc_sock_t *s, hc_route_t *route) {
  return s->hc_route_create_conf(s, route);
}

int hc_route_delete(hc_sock_t *s, hc_route_t *route) {
  return s->hc_route_delete(s, route);
}

int hc_route_list(hc_sock_t *s, hc_data_t **pdata) {
  return s->hc_route_list(s, pdata);
}

int hc_route_list_async(hc_sock_t *s) { return s->hc_route_list_async(s); }

/* ROUTE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_route_snprintf(char *s, size_t size, hc_route_t *route) {
  /* interface cost prefix length */

  char prefix[MAXSZ_IP_ADDRESS];
  int rc;

  rc = ip_address_snprintf(prefix, MAXSZ_IP_ADDRESS, &route->remote_addr,
                           route->family);
  if (rc >= MAXSZ_IP_ADDRESS)
    ;
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %*d %s %*d conn_id=%d", route->name, MAXSZ_COST,
                  route->cost, prefix, MAXSZ_LEN, route->len, route->face_id);
}

int hc_route_validate(const hc_route_t *route) {
  if (!IS_VALID_ID(route->connection_id)) {
    ERROR("[hc_route_validate] Invalid connection id");
    return -1;
  }
  if (!IS_VALID_NAME(route->name) && !IS_VALID_STR_ID(route->name)) {
    ERROR("[hc_route_validate] Invalid name specified");
    return -1;
  }
  if (!IS_VALID_FAMILY(route->family)) {
    ERROR("[hc_route_validate] Invalid family specified");
    return -1;
  }
  if (!IS_VALID_ADDRESS(&route->remote_addr, route->family)) {
    ERROR("[hc_route_validate] Invalid remote_addr specified");
    return -1;
  }
  if (!IS_VALID_ROUTE_COST(route->cost)) {
    ERROR("[hc_route_validate] Invalid cost");
    return -1;
  }
  if (!IS_VALID_PREFIX_LEN(route->len)) {
    ERROR("[hc_route_validate] Invalid len");
    return -1;
  }

  return 0;
}

/*----------------------------------------------------------------------------*
 * FACE
 *----------------------------------------------------------------------------*/

/* FACE -> LISTENER */

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener) {
  const face_t *f = &face->face;

  switch (f->type) {
    case FACE_TYPE_HICN_LISTENER:
      break;
    case FACE_TYPE_TCP_LISTENER:
      break;
    case FACE_TYPE_UDP_LISTENER:
      break;
    default:
      return -1;
  }
  return -1; /* XXX Not implemented */
}

/* LISTENER -> FACE */

int hc_listener_to_face(const hc_listener_t *listener, hc_face_t *face) {
  return -1; /* XXX Not implemented */
}

/* FACE -> CONNECTION */

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name) {
  int rc;

  const face_t *f = &face->face;
  switch (f->type) {
    case FACE_TYPE_HICN:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_HICN,
          .family = f->family,
          .local_addr = f->local_addr,
          .local_port = 0,
          .remote_addr = f->remote_addr,
          .remote_port = 0,
          .admin_state = f->admin_state,
          .state = f->state,
#ifdef WITH_POLICY
          .priority = f->priority,
          .tags = f->tags,
#endif /* WITH_POLICY */
      };
      rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s",
                    f->netdevice.name);
      if (rc >= SYMBOLIC_NAME_LEN)
        WARN(
            "[hc_face_to_connection] Unexpected truncation of symbolic "
            "name string");
      break;
    case FACE_TYPE_TCP:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_TCP,
          .family = f->family,
          .local_addr = f->local_addr,
          .local_port = f->local_port,
          .remote_addr = f->remote_addr,
          .remote_port = f->remote_port,
          .admin_state = f->admin_state,
          .state = f->state,
#ifdef WITH_POLICY
          .priority = f->priority,
          .tags = f->tags,
#endif /* WITH_POLICY */
      };
      if (generate_name) {
        rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "tcp%u", RANDBYTE());
        if (rc >= SYMBOLIC_NAME_LEN)
          WARN(
              "[hc_face_to_connection] Unexpected truncation of "
              "symbolic name string");
      } else {
        memset(connection->name, 0, SYMBOLIC_NAME_LEN);
      }
      break;
    case FACE_TYPE_UDP:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_UDP,
          .family = f->family,
          .local_addr = f->local_addr,
          .local_port = f->local_port,
          .remote_addr = f->remote_addr,
          .remote_port = f->remote_port,
          .admin_state = f->admin_state,
          .state = f->state,
#ifdef WITH_POLICY
          .priority = f->priority,
          .tags = f->tags,
#endif /* WITH_POLICY */
      };
      if (generate_name) {
        rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "udp%u", RANDBYTE());
        if (rc >= SYMBOLIC_NAME_LEN)
          WARN(
              "[hc_face_to_connection] Unexpected truncation of "
              "symbolic name string");
      } else {
        memset(connection->name, 0, SYMBOLIC_NAME_LEN);
      }
      snprintf(connection->interface_name, INTERFACE_LEN, "%s",
               f->netdevice.name);
      break;
    default:
      return -1;
  }

  connection->id = face->id;
  rc = snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                f->netdevice.name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "hc_face_to_connection] Unexpected truncation of interface name "
        "string");

  return 0;
}

/* CONNECTION -> FACE */

int hc_connection_to_face(const hc_connection_t *connection, hc_face_t *face) {
  int rc;
  switch (connection->type) {
    case FACE_TYPE_TCP:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_TCP,
                  .family = connection->family,
                  .local_addr = connection->local_addr,
                  .local_port = connection->local_port,
                  .remote_addr = connection->remote_addr,
                  .remote_port = connection->remote_port,
                  .admin_state = connection->admin_state,
                  .state = connection->state,
#ifdef WITH_POLICY
                  .priority = connection->priority,
                  .tags = connection->tags,
#endif /* WITH_POLICY */
              },
      };
      break;
    case FACE_TYPE_UDP:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_UDP,
                  .family = connection->family,
                  .local_addr = connection->local_addr,
                  .local_port = connection->local_port,
                  .remote_addr = connection->remote_addr,
                  .remote_port = connection->remote_port,
                  .admin_state = connection->admin_state,
                  .state = connection->state,
#ifdef WITH_POLICY
                  .priority = connection->priority,
                  .tags = connection->tags,
#endif /* WITH_POLICY */
              },
      };
      break;
    case FACE_TYPE_HICN:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_HICN,
                  .family = connection->family,
                  .netdevice.index = NETDEVICE_UNDEFINED_INDEX,  // XXX
                  .local_addr = connection->local_addr,
                  .remote_addr = connection->remote_addr,
                  .admin_state = connection->admin_state,
                  .state = connection->state,
#ifdef WITH_POLICY
                  .priority = connection->priority,
                  .tags = connection->tags,
#endif /* WITH_POLICY */
              },
      };
      break;
    default:
      return -1;
  }
  face->face.netdevice.name[0] = '\0';
  face->face.netdevice.index = 0;
  rc = snprintf(face->name, SYMBOLIC_NAME_LEN, "%s", connection->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[hc_connection_to_face] Unexpected truncation of symbolic name "
        "string");
  rc = snprintf(face->face.netdevice.name, INTERFACE_LEN, "%s",
                connection->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[hc_connection_to_face] Unexpected truncation of interface name "
        "string");
  netdevice_update_index(&face->face.netdevice);
  return 0;
}

/* CONNECTION -> LISTENER */

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener) {
  int rc;

  face_type_t listener_type;
  switch (connection->type) {
    case FACE_TYPE_UDP:
      listener_type = FACE_TYPE_UDP_LISTENER;
      break;
    case FACE_TYPE_TCP:
      listener_type = FACE_TYPE_TCP_LISTENER;
      break;
    default:
      return -1;
  }

  *listener = (hc_listener_t){
      .id = ~0,
      .type = listener_type,
      .family = connection->family,
      .local_addr = connection->local_addr,
      .local_port = connection->local_port,
  };
  rc = snprintf(listener->name, SYMBOLIC_NAME_LEN, "lst%u",
                RANDBYTE());  // generate name
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[hc_connection_to_local_listener] Unexpected truncation of "
        "symbolic name string");
  rc = snprintf(listener->interface_name, INTERFACE_LEN, "%s",
                connection->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[hc_connection_to_local_listener] Unexpected truncation of "
        "interface name string");

  return 0;
}

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

  rc = ip_address_cmp(&p1->prefix, &p2->prefix, p1->family);
  if (rc != 0) return rc;

  rc = INT_CMP(p1->prefix_len, p2->prefix_len);
  if (rc != 0) return rc;

  return rc;
}

int hc_punting_parse(void *in, hc_punting_t *punting) {
  ERROR("hc_punting_parse not (yet) implemented.");
  return -1;
}

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

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

int hc_strategy_list(hc_sock_t *s, hc_data_t **data) {
  return s->hc_strategy_list(s, data);
}

int hc_strategy_set(hc_sock_t *s, hc_strategy_t *strategy) {
  return s->hc_strategy_set(s, strategy);
}

int hc_strategy_add_local_prefix(hc_sock_t *s, hc_strategy_t *strategy) {
  return s->hc_strategy_add_local_prefix(s, strategy);
}

hc_result_t *hc_strategy_set_conf(hc_sock_t *s, hc_strategy_t *strategy) {
  return s->hc_strategy_set_conf(s, strategy);
}

hc_result_t *hc_strategy_add_local_prefix_conf(hc_sock_t *s,
                                               hc_strategy_t *strategy) {
  return s->hc_strategy_add_local_prefix_conf(s, strategy);
}

/* /!\ Please update constants in header file upon changes */
int hc_strategy_snprintf(char *s, size_t size, hc_strategy_t *strategy) {
  return snprintf(s, size, "%s", strategy->name);
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

#ifdef WITH_POLICY

/* POLICY SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_policy_snprintf(char *s, size_t size, hc_policy_t *policy) { return 0; }

int hc_policy_validate(const hc_policy_t *policy) {
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  return 0;
}

#endif /* WITH_POLICY */

/*----------------------------------------------------------------------------*
 * SUBSCRIPTION
 *----------------------------------------------------------------------------*/
int hc_subscription_create(hc_sock_t *s, hc_subscription_t *subscription) {
  return s->hc_subscription_create(s, subscription);
}

int hc_subscription_delete(hc_sock_t *s, hc_subscription_t *subscription) {
  return s->hc_subscription_delete(s, subscription);
}

hc_result_t *hc_subscription_create_conf(hc_sock_t *s,
                                         hc_subscription_t *subscription) {
  return s->hc_subscription_create_conf(s, subscription);
}

hc_result_t *hc_subscription_delete_conf(hc_sock_t *s,
                                         hc_subscription_t *subscription) {
  return s->hc_subscription_delete_conf(s, subscription);
}

/*----------------------------------------------------------------------------*
 * Result
 *----------------------------------------------------------------------------*/

hc_msg_t *hc_result_get_msg(hc_sock_t *s, hc_result_t *result) {
  return s->hc_result_get_msg(result);
}

int hc_result_get_cmd_id(hc_sock_t *s, hc_result_t *result) {
  return s->hc_result_get_cmd_id(result);
}

bool hc_result_get_success(hc_sock_t *s, hc_result_t *result) {
  return s->hc_result_get_success(result);
}

void hc_result_free(hc_result_t *result) { free(result); }
