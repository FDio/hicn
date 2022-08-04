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
 * \file modules/hicn_light.c
 * \brief Implementation of hicn-light module.
 */

#include <assert.h>  // assert
#include <fcntl.h>   // fcntl
#include <stdbool.h>
#include <stdio.h>       // snprintf
#include <string.h>      // memmove, strcasecmp
#include <sys/socket.h>  // socket
#include <sys/types.h>   // getpid
#include <unistd.h>      // close, fcntl, getpid

#ifdef __linux__
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif /* __linux__ */

#include <strings.h>

#include <hicn/ctrl/hicn-light.h>
#include <hicn/ctrl/socket.h>

#include "../api_private.h"
#include "../objects/connection.h"  // hc_connection_has_local
#include "../objects/listener.h"    // hc_listener_is_local
#include "../objects/route.h"       // hc_route_has_face
#include "../request.h"
#include "../socket_private.h"
#include "hicn_light.h"

#include "hicn_light/base.h"
#include "hicn_light/connection.h"
#include "hicn_light/listener.h"
#include "hicn_light/face.h"
#include "hicn_light/route.h"
#include "hicn_light/strategy.h"
#include "hicn_light/subscription.h"

#pragma GCC diagnostic ignored "-Warray-bounds"

#define DEFAULT_SOCK_RECV_TIMEOUT_MS 100

#define PORT 9695

#define BOOLSTR(x) ((x) ? "true" : "false")

hc_sock_light_data_t *hc_sock_light_data_create(const char *url) {
  hc_sock_light_data_t *s = malloc(sizeof(hc_sock_light_data_t));
  if (!s) goto ERR_MALLOC;

  s->roff = s->woff = 0;
  s->remaining = 0;
  s->got_header = false;

  s->url = url ? strdup(url) : NULL;

  s->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (s->fd < 0) goto ERR_SOCKET;

#if 0
  struct timeval tv = {.tv_sec = 0,
                       .tv_usec = DEFAULT_SOCK_RECV_TIMEOUT_MS * 1000};
  if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setsockopt");
    goto ERR_TIMEOUT;
  }
#endif

  return s;

#if 0
ERR_TIMEOUT:
#endif
  close(s->fd);
ERR_SOCKET:
  if (s->url) free(s->url);
  free(s);
ERR_MALLOC:
  return NULL;
}

void hc_sock_light_data_free(hc_sock_light_data_t *data) {
  if (data->url) free(data->url);
  free(data);
}

static const struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

/******************************************************************************
 * Control socket
 ******************************************************************************/

#define AVAILABLE(s) ((s)->woff - (s)->roff)

/**
 * \brief Parse a connection URL into a sockaddr
 * \param [in] url - URL
 * \param [out] sa - Resulting struct sockaddr, expected zero'ed.
 * \return 0 if parsing succeeded, a negative error value otherwise.
 */
static int hicnlight_parse_url(const char *url, struct sockaddr *sa) {
  /* FIXME URL parsing is currently not implemented */
  _ASSERT(!url);

#ifdef __linux__
  srand(time(NULL) ^ getpid() ^ gettid());
#else
  srand((unsigned int)(time(NULL) ^ getpid()));
#endif /* __linux__ */

  /*
   * A temporary solution is to inspect the sa_family fields of the passed in
   * sockaddr, which defaults to AF_UNSPEC (0) and thus creates an IPv4/TCP
   * connection to localhost.
   */
  switch (sa->sa_family) {
    case AF_UNSPEC:
    case AF_INET: {
      struct sockaddr_in *sai = (struct sockaddr_in *)sa;
      sai->sin_family = AF_INET;
      sai->sin_port = htons(PORT);
      sai->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)sa;
      sai6->sin6_family = AF_INET6;
      sai6->sin6_port = htons(PORT);
      sai6->sin6_addr = loopback_addr;
      break;
    }
    default:
      return -1;
  }

  return 0;
}

/*
 * Return codes:
 * < 0 : error; invalid buffer data -> flush
 * otherwise, seq_num of the identified request
 */
static int hicnlight_process_header(hc_sock_t *sock) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  hc_object_type_t object_type = OBJECT_TYPE_UNDEFINED;

  /* Check we have at least a header's worth of data, and consume it */
  if (AVAILABLE(s) < sizeof(hc_msg_header_t)) return 0;

  hc_msg_t *msg = (hc_msg_t *)(s->buf + s->roff);

  // INFO("Processing header header %s", command_type_str(msg->hdr.command_id));
  s->roff += sizeof(hc_msg_header_t);
  s->got_header = true;

  /* How many elements are we expecting in the reply ? */
  s->remaining = msg->header.length;

  /* Identify request being parsed */
  int seq = msg->header.seq_num;
  hc_request_t *request = NULL;
  if (hc_sock_map_get(sock->map, seq, &request) < 0) {
    ERROR("[hc_sock_light_process] Error searching for matching request");
    return -1;
  }
  if (!request) {
    ERROR("[hc_sock_light_process] No request matching sequence number");
    return -1;
  }
  sock->current_request = request;
  hc_request_t *current_request = hc_request_get_current(request);
  hc_data_t *data = hc_request_get_data(current_request);
  _ASSERT(data);

  switch (msg->header.message_type) {
    case ACK_LIGHT:
      _ASSERT(s->remaining == 0);

      s->got_header = false;
      if (!hc_request_is_subscription(request)) hc_data_set_complete(data);
      break;

    case NACK_LIGHT:
      _ASSERT(s->remaining == 0);

      s->got_header = false;
      hc_data_set_error(data);
      break;

    case RESPONSE_LIGHT:
      if (s->remaining == 0) {
        /* Empty response (i.e. containing 0 elements) */
        s->got_header = false;
        hc_data_set_complete(data);
        return 0;
      }

      /* Allocate buffer for response */
      if (hc_data_allocate(data, s->remaining) < 0) {
        ERROR("[hc_sock_light_process] Cannot allocate result buffer");
        return -99;
      }
      break;

    case NOTIFICATION_LIGHT: {
      _ASSERT(s->remaining == 1);
      /*
       * Assumption: the whole notification data is returned in a single read
       * and we immediately parse it.
       */
      // XXX assert enough buffer for object type + validate returned object
      object_type = (hc_object_type_t)msg->header.command_id;
      hc_data_clear(data);
      hc_data_set_object_type(data, object_type);
      if (hc_data_allocate(data, s->remaining) < 0) {
        ERROR("[hc_sock_light_process] Cannot allocate result buffer");
        return -1;
      }

      hc_data_push(data, s->buf + s->roff);

      s->roff += AVAILABLE(s);

      hc_request_on_notification(request);

      /*
       * The buffer is cleared just before the next notification, which means
       * it will have to be released upon exit. Otherwise we break the code
       * dumping the notification synchronously (eg. hicnctrl -s).
       */
      // hc_data_clear(data);

      s->got_header = false;
      break;
    }

    default:
      ERROR("[hc_sock_light_process] Invalid response received");
      return -99;
  }

  return 0;
}

size_t hc_light_object_size(hc_object_type_t object_type);

static int hicnlight_process_payload(hc_sock_t *sock) {
  int err = 0;
  int rc;

  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  hc_request_t *request = hc_sock_get_request(sock);
  hc_request_t *current_request = hc_request_get_current(request);
  hc_data_t *data = hc_request_get_data(current_request);

  hc_object_type_t object_type = hc_data_get_object_type(data);
  size_t object_size = hc_light_object_size(object_type);
  if (object_size == 0) return -1;

  /* We only process full elements (size is stored in data) */
  size_t num_chunks = AVAILABLE(s) / object_size;

  /* Check whether we have enough data to process */
  if (num_chunks == 0) return 0;

  /* Safeguard: _ASSERT(num_chunks < s->remaining); */
  if (num_chunks > s->remaining) {
    WARN(
        "[hicnlight_process_payload] Unexpected num_chunks > "
        "s->remaining");
    num_chunks = s->remaining;
  }

  for (size_t i = 0; i < num_chunks; i++) {
    /*
     * Get storage offset in hc_data_t, which we assume is correctly
     * provisioned.
     * XXX
     */
    u8 *src = s->buf + s->roff;
    hc_object_t *dst = (hc_object_t *)hc_data_get_free(data);
    if (!dst) {
      ERROR("[hc_sock_light_process] Error in hc_data_get_next");
      err = -2;
      break;
    }

    // XXX we might want to display even incomplete data when printing (eg.
    // string truncation), and be very strict when processing.
    rc = hc_sock_parse_object(sock, hc_data_get_object_type(data), src,
                              object_size, dst);
    s->roff += object_size;
    if (rc < 0) {
      ERROR("Error parsing received object");
      continue;
    }
    hc_data_inc_size(data);
  }

  /*
   * If we are not expecting any more data, mark the reply as complete
   */
  s->remaining -= num_chunks;
  if (s->remaining == 0) {
    s->got_header = false;
    hc_data_set_complete(data);
  }

  return err;
}

/*----------------------------------------------------------------------------
 * Socket operations
 *----------------------------------------------------------------------------*/

static int hicnlight_get_fd(hc_sock_t *sock) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  return s->fd;
}

static int hicnlight_get_recv_buffer(hc_sock_t *sock, uint8_t **buffer,
                                     size_t *size) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  *buffer = s->buf + s->woff;
  *size = RECV_BUFLEN - s->woff;

  return 0;
}

static int hicnlight_connect(hc_sock_t *sock) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  struct sockaddr_storage ss;
  memset(&ss, 0, sizeof(struct sockaddr_storage));

  if (hicnlight_parse_url(s->url, (struct sockaddr *)&ss) < 0) goto ERR_PARSE;

  size_t size = ss.ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6);
  if (connect(s->fd, (struct sockaddr *)&ss, (socklen_t)size) < 0) {
    perror("connect error");
    goto ERR_CONNECT;
  }
  return 0;

ERR_CONNECT:
ERR_PARSE:
  return -1;
}

static int hicnlight_disconnect(hc_sock_t *sock) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;

  /* Remove the connection created to send the command.
   *
   * Note this is done as a best effort and we don't expect to receive any
   * answer from the forwarder (hence the NULL pdata pointer in the request).
   */
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.connection.id = 0;
  int rc =
      strcpy_s(object.connection.name, sizeof(object.connection.name), "SELF");
  if (rc == EOK)
    hc_execute_async(sock, ACTION_DELETE, OBJECT_TYPE_CONNECTION, &object, NULL,
                     NULL);

  close(s->fd);

  return 0;
}

static ssize_t hicnlight_prepare_generic(hc_sock_t *sock, hc_request_t *request,
                                         uint8_t **buffer) {
  /* Dispatch to subrequest if any */
  hc_request_t *current_request = hc_request_get_current(request);

  _ASSERT(!hc_request_get_data(current_request));

  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);

  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;

  _ASSERT(hc_request_get_data(current_request) == NULL);
  hc_data_t *data = hc_data_create(object_type);
  if (!data) {
    ERROR("[hicnlight_prepare_generic] Could not create data storage");
    return -1;
  }
  hc_request_set_data(current_request, data);

  /* Serialize request into message */
  DEBUG("Calling serialize on %s %s", action_str(action),
        object_type_str(object_type));
  ssize_t msg_len = hc_sock_serialize_object(sock, action, object_type, object,
                                             (uint8_t *)&s->msg);
  if (msg_len < 0) {
    ERROR("[hicnlight_prepare_generic] Could not serialize command %s %s",
          action_str(action), object_type_str(object_type));
    return INPUT_ERROR;
  }

  s->msg.header.seq_num = hc_request_get_seq(current_request);

  *buffer = (uint8_t *)&s->msg;
  return msg_len;
}

static int hicnlight_send(hc_sock_t *sock, uint8_t *buffer, size_t size) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;

  int rc = (int)send(s->fd, buffer, size, 0);
  if (rc < 0) {
    perror("[hicnlight_send] Error sending message");
    return -1;
  }

  // XXX regular behaviour for others
  return 0;
}

// Example : face create udp
// 1) face to connection (immediate)
//    connection to local listener (immediate) : why not both at the same
//    time listener get
//       listener create / nothing
//    connection create
//    connection get (if needed for populating face_id for instance, aka
//    if we
//            need to return data)

static ssize_t hicnlight_prepare(hc_sock_t *sock, hc_request_t *request,
                                 uint8_t **buffer);

static ssize_t hicnlight_prepare_subrequest(
    hc_sock_t *sock, hc_request_t *request, hc_action_t action,
    hc_object_type_t object_type, hc_object_t *object, uint8_t **buffer) {
  WITH_DEBUG({
    if (object) {
      char buf[MAXSZ_HC_OBJECT];
      hc_object_snprintf(buf, sizeof(buf), object_type, object);
      DEBUG("Creating subrequest %s/%s %s", action_str(action),
            object_type_str(object_type), buf);
    }
  });
  hc_request_make_subrequest(request, action, object_type, object);
  return hicnlight_prepare(sock, request, buffer);
}

/*
 * XXX shall we update the object in the request for faces ? it is not done
 * for other objects, but for faces it is needed to further add a route !!!
 */
static ssize_t hicnlight_prepare_face_create(hc_sock_t *sock,
                                             hc_request_t *request,
                                             uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);
  hc_object_t *object = hc_request_get_object(current_request);
  hc_data_t *data = hc_request_get_data(current_request);
  hc_face_t *face = &object->face;

  // XXX those objects are created on stack and expected to be valid across
  // several calls. A quick fix is to make them static
  static hc_object_t connection;
  static hc_object_t listener;

  hc_request_state_t state;
  const hc_connection_t *conn;

NEXT:
  state = hc_request_get_state(current_request);
  DEBUG("hicnlight_prepare_face_create > %s", hc_request_state_str(state));

  switch (state) {
    case REQUEST_STATE_INIT:
      _ASSERT(!data);

      switch (face->type) {
        case FACE_TYPE_HICN:
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
          hc_request_set_state(current_request,
                               REQUEST_STATE_FACE_CREATE_CONNECTION_CREATE);
          goto NEXT;
        case FACE_TYPE_HICN_LISTENER:
        case FACE_TYPE_TCP_LISTENER:
        case FACE_TYPE_UDP_LISTENER:
          hc_request_set_state(current_request,
                               REQUEST_STATE_FACE_CREATE_LISTENER_CREATE);
          goto NEXT;
        case FACE_TYPE_UNDEFINED:
        case FACE_TYPE_N:
          return -99;  // Not implemented
      }

    case REQUEST_STATE_FACE_CREATE_CONNECTION_CREATE:
      if (hc_face_to_connection(face, &connection.connection, true) < 0) {
        ERROR("[hc_face_create] Could not convert face to connection.");
        return -1;
      }
      hc_request_set_state(current_request,
                           REQUEST_STATE_FACE_CREATE_CONNECTION_CHECK);

      return hicnlight_prepare_subrequest(sock, request, ACTION_CREATE,
                                          OBJECT_TYPE_CONNECTION, &connection,
                                          buffer);

    case REQUEST_STATE_FACE_CREATE_CONNECTION_CHECK:
      /*
       * If the newly created face_id was not need, we would only
       * need to return the same data result, which contains a ack/nack,
       * simply updating the object type.
       *
       * With the current API, once the connection is created, our only
       * solution is to list all connections and compare with the current one
       * to find the created connection ID, and thus face ID.
       */
      /* Has the connection been successfully created ? */
      if (!data || !hc_data_get_result(data)) return -1;

      hc_request_set_state(current_request,
                           REQUEST_STATE_FACE_CREATE_CONNECTION_GET);
      goto NEXT;

    case REQUEST_STATE_FACE_CREATE_CONNECTION_GET:
      hc_request_set_state(current_request,
                           REQUEST_STATE_FACE_CREATE_CONNECTION_VERIFY);
      return hicnlight_prepare_subrequest(sock, request, ACTION_GET,
                                          OBJECT_TYPE_CONNECTION, &connection,
                                          buffer);

    case REQUEST_STATE_FACE_CREATE_CONNECTION_VERIFY:
      if (!data || hc_data_get_size(data) != 1) return -1;

      /* Newly created connection was found */
      conn = (hc_connection_t *)hc_data_get_buffer(data);
      DEBUG("created connection id=%d", conn->id);
      object->face.id = conn->id;

      break;

    case REQUEST_STATE_FACE_CREATE_LISTENER_CREATE:
      if (hc_face_to_listener(face, &listener.listener) < 0) {
        ERROR("Could not convert face to listener.");
        return -1;
      }

      hc_request_set_state(current_request,
                           REQUEST_STATE_FACE_CREATE_LISTENER_CHECK);
      return hicnlight_prepare_subrequest(sock, request, ACTION_CREATE,
                                          OBJECT_TYPE_LISTENER, &listener,
                                          buffer);

      break;

    case REQUEST_STATE_FACE_CREATE_LISTENER_CHECK:
      /*
       * No need for face id here, simply return the hc_data_t structure
       * with the ack/nack, and the proper object type
       */
      if (!data) return -1;
      hc_data_set_object_type(data, OBJECT_TYPE_FACE);
      break;

#if 0
    case REQUEST_STATE_COMPLETE:
      hc_data_set_complete(data);
      break;
#endif

    default:
      return -1;
  }
  return 0;
}

static ssize_t hicnlight_prepare_face_list(hc_sock_t *sock,
                                           hc_request_t *request,
                                           uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);
  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);
  hc_data_t *data = hc_request_get_data(current_request);
  hc_face_t face;

  _ASSERT(action == ACTION_LIST);
  _ASSERT(object_type == OBJECT_TYPE_FACE);

  hc_request_state_t state = hc_request_get_state(current_request);
  DEBUG("hicnlight_prepare_face_list > %s", hc_request_state_str(state));

  switch (state) {
    case REQUEST_STATE_INIT:
      _ASSERT(!data);

      hc_request_set_state(current_request,
                           REQUEST_STATE_FACE_LIST_CONNECTION_LIST);
      return hicnlight_prepare_subrequest(
          sock, request, ACTION_LIST, OBJECT_TYPE_CONNECTION, object, buffer);

    case REQUEST_STATE_FACE_LIST_CONNECTION_LIST:
      _ASSERT(data);
      /*
       * 'list connection' succeeded, we just need to allocate hc_data_t,
       * create faces from connections, and return the data structure as if it
       * was created by the query
       */
      hc_data_t *face_data = hc_data_create(object_type);
      hc_data_allocate(face_data, hc_data_get_size(data));
      foreach_connection(c, data) {
        if (hc_face_from_connection(c, &face) < 0) {
          ERROR("[hc_face_list] Could not convert connection to face.");
          return -1;
        }
        hc_data_push(face_data, &face);
      }
      hc_data_set_complete(face_data);

      hc_request_reset_data(request);
      hc_request_set_data(request, face_data);

      /* FACE/LIST could be part of FACE/GET */
      break;

    default:
      return -1;
  }

  return 0;
}

static ssize_t hicnlight_prepare_get(hc_sock_t *sock, hc_request_t *request,
                                     uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);

  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);
  hc_data_t *data = hc_request_get_data(current_request);
  hc_object_t *found;

  hc_request_state_t state = hc_request_get_state(current_request);
  DEBUG("hicnlight_prepare_get > %s", hc_request_state_str(state));

  switch (state) {
    case REQUEST_STATE_INIT:
      _ASSERT(!data);
      hc_request_set_state(current_request, REQUEST_STATE_GET_LIST);
      return hicnlight_prepare_subrequest(sock, request, ACTION_LIST,
                                          object_type, NULL, buffer);
    case REQUEST_STATE_GET_LIST:
      _ASSERT(data);

      found = hc_data_find(data, object);
      hc_data_t *found_data = hc_data_create(object_type);
      if (found) {
        hc_data_allocate(found_data, 1);
        hc_data_push(found_data, found);
      }
      hc_data_set_complete(found_data);
      hc_request_reset_data(current_request);
      hc_request_set_data(current_request, found_data);
      return 0;
    default:
      return -1; /* Unexpected */
  }
}

// XXX This should process the content of pdata (unless at init), and
// terminate by sending something
static ssize_t hicnlight_prepare_face(hc_sock_t *sock, hc_request_t *request,
                                      uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);
  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(request);

  _ASSERT(object_type == OBJECT_TYPE_FACE);

  switch (action) {
    case ACTION_CREATE:
      return hicnlight_prepare_face_create(sock, request, buffer);
    case ACTION_LIST:
      return hicnlight_prepare_face_list(sock, request, buffer);
    default:
      return -99;  // Not implemented
  }
  return 0;
}

static ssize_t hicnlight_prepare_connection_create(hc_sock_t *sock,
                                                   hc_request_t *request,
                                                   uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);

  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);

  _ASSERT(action == ACTION_CREATE);
  _ASSERT(object_type == OBJECT_TYPE_CONNECTION);

  hc_data_t *data = hc_request_get_data(current_request);

  size_t size;
  unsigned pos;
  static hc_object_t listener;
  const hc_object_t *obj_listener;
  hc_data_t *listener_data = NULL;

  hc_request_state_t state;

NEXT:
  state = hc_request_get_state(current_request);
  DEBUG("hicnlight_prepare_connection_create > %s",
        hc_request_state_str(state));

  switch (state) {
    case REQUEST_STATE_INIT:
      /* Two behaviours depending on the content of local_addr and local_port:
       * - empty : create connection on all existing listeners, and raise an
       *   error if none
       * - otherwise, check whether a corresponding listener exists, and
       *   create it if necessary
       *
       * We assume connection has been already validated.
       */
      if (hc_connection_has_local(&object->connection)) {
        hc_request_set_state(current_request,
                             REQUEST_STATE_CONNECTION_CREATE_LISTENER_GET);
      } else {
        /*
         * At least part of the local socket specification is missing, match
         * against existing listeners
         */
        hc_request_set_state(current_request,
                             REQUEST_STATE_CONNECTION_CREATE_LISTENER_LIST);
      }
      goto NEXT;

    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_LIST:

      hc_request_set_state(current_request,
                           REQUEST_STATE_CONNECTION_CREATE_LISTENER_ITERATE);
      // XXX We are currently assuming an object is present for rewrite, fix
      // this
      return hicnlight_prepare_subrequest(sock, request, ACTION_LIST,
                                          OBJECT_TYPE_LISTENER, NULL, buffer);

    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_ITERATE:
      /*
       * NOTE: we could create all connections in parallel to speed up
       * processing
       */
      size = hc_data_get_size(data);
      if (size < 0) return -1;
      if (size == 0)
        /* We are done, we cannot create a connection, return a Nack */
        ;  // XXX TODO
           //
      /* Save the list of listeners for later iteration */
      listener_data = data;
      hc_request_clear_data(current_request);  // don't free data
      data = NULL;
      hc_request_set_state_count(current_request, 0);
      hc_request_set_state(current_request, REQUEST_STATE_CONNECTION_CREATE_N);
      goto NEXT; /* Start iteration */

    case REQUEST_STATE_CONNECTION_CREATE_N:
      /*
       * IMPORTANT
       *
       * For now we only create a connection with the first non-local
       * listener.
       *
       * Creating N connections in a single commands requires other
       * changes to the code that we might done later:
       *  - ack/nack is not sufficient, all create function should return the
       *  list of created connections
       *  - this would allow us to avoid a GET at the end of face creation to
       *  retrieve the connection id.
       *  - face create should correspond to N connection create (should work
       *  out of the box provided we don't expect a single connection back).
       *  - route+face creation might then create N faces, and thus we would
       *  have to add N routes.
       */
      assert(listener_data);

      // We need to back it up as the subrequest will clear the results
      pos = hc_request_get_state_count(current_request);
      size = hc_data_get_size(listener_data);
      /* We have data if pos > 0, and we did not skipped previous ones */
      if (data && !hc_data_get_result(data)) {
        INFO("Failed to create connection for listener %d / %d", pos - 1, size);
        // XXX we might allow connections that already exist... how to manage
        // the names
        return -1;
      }

      /*
       * Previous connection was successfully created, let's continue but
       * first check whether we reached the last one, which would complete the
       * request.
       */
      if (pos >= size) {
        hc_data_free(listener_data);
        hc_request_set_state(request, REQUEST_STATE_COMPLETE);
        goto NEXT;
      }

      /* Sending count'th connection creation */
      obj_listener = hc_data_get_object(listener_data, pos);

      // Filter which listener we use
      // same protocol ? ip ? port ?
      // avoid local ?
      if (hc_listener_is_local(&obj_listener->listener)) {
        /* Skip listener */
        DEBUG("Skipped local listener");
        hc_request_set_state_count(current_request, pos + 1);
        goto NEXT;
      }

      DEBUG("Creating connection with listener # %d / %d", pos, size);
      /* We complement missing information from listener */
      // XXX is_family, etc.
      object->connection.family = obj_listener->listener.family;
      object->connection.local_addr = obj_listener->listener.local_addr;
      object->connection.local_port = obj_listener->listener.local_port;
      snprintf(object->connection.interface_name, INTERFACE_LEN, "%s",
               obj_listener->listener.interface_name);

      hc_request_set_state_count(current_request, pos + 1);
      return hicnlight_prepare_subrequest(
          sock, request, ACTION_CREATE, OBJECT_TYPE_CONNECTION, object, buffer);

    /* Request listener to further check existence */
    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_GET:
      /* Ensure we have a corresponding local listener */
      if (hc_connection_to_local_listener(&object->connection,
                                          &listener.listener) < 0) {
        ERROR(
            "[hicnlight_prepare_connection_create] Could not convert face "
            "to "
            "local listener.");
        return -1;
      }
      hc_request_set_state(current_request,
                           REQUEST_STATE_CONNECTION_CREATE_LISTENER_VERIFY);
      return hicnlight_prepare_subrequest(
          sock, request, ACTION_GET, OBJECT_TYPE_LISTENER, &listener, buffer);

      break;

    /* Check whether listener exists in GET results */
    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_VERIFY:
      if (!data) return -1;
      switch (hc_data_get_size(data)) {
        case 0:
          hc_request_set_state(current_request,
                               REQUEST_STATE_CONNECTION_CREATE_LISTENER_CREATE);
          break;
        case 1:
          hc_request_set_state(current_request,
                               REQUEST_STATE_CONNECTION_CREATE);
          break;
        default:
          return -1;
      }
      goto NEXT;

    /* Create associated listener */
    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_CREATE:
      hc_request_set_state(current_request,
                           REQUEST_STATE_CONNECTION_CREATE_LISTENER_CHECK);
      return hicnlight_prepare_subrequest(sock, request, ACTION_CREATE,
                                          OBJECT_TYPE_LISTENER, &listener,
                                          buffer);

    /* Check whether listener creation succeeded */
    case REQUEST_STATE_CONNECTION_CREATE_LISTENER_CHECK:
      if (!data || hc_data_get_result(data)) return -1;
      hc_request_set_state(current_request, REQUEST_STATE_CONNECTION_CREATE);
      goto NEXT;

    /* Create connection */
    case REQUEST_STATE_CONNECTION_CREATE:
      /*
       * Break recursion by directly calling hicnlight_prepare_generic on
       * the initial request, that can now be executed since all
       * prerequisites are validated.
       */
      // return hicnlight_prepare_subrequest(
      //    sock, request, ACTION_CREATE, OBJECT_TYPE_CONNECTION, object,
      //    buffer);
      hc_request_reset_data(current_request);
      hc_request_set_state(current_request, REQUEST_STATE_COMPLETE);
      return hicnlight_prepare_generic(sock, request, buffer);

    case REQUEST_STATE_COMPLETE:
      if (data) {
        hc_data_set_complete(data);
      } else {
        /*
         * No connection has been created, and we freed the data due to
         * subrequest
         */
        data = hc_data_create(OBJECT_TYPE_CONNECTION);
        hc_data_set_error(data);
      }
      break;

    default:
      return -1;
  }
  return 0;
}

static ssize_t hicnlight_prepare_route_create(hc_sock_t *sock,
                                              hc_request_t *request,
                                              uint8_t **buffer) {
  hc_request_t *current_request = hc_request_get_current(request);

  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);

  _ASSERT(action == ACTION_CREATE);
  _ASSERT(object_type == OBJECT_TYPE_ROUTE);

  hc_data_t *data = hc_request_get_data(current_request);
  const hc_object_t *face_obj;

  hc_request_state_t state;

NEXT:
  state = hc_request_get_state(current_request);
  DEBUG("hicnlight_prepare_route_create > %s", hc_request_state_str(state));

  switch (state) {
    case REQUEST_STATE_INIT:
      if (hc_route_has_face(&object->route))
        hc_request_set_state(current_request,
                             REQUEST_STATE_ROUTE_CREATE_FACE_CREATE);
      else
        hc_request_set_state(current_request, REQUEST_STATE_ROUTE_CREATE);
      goto NEXT;

    case REQUEST_STATE_ROUTE_CREATE_FACE_CREATE:
      hc_request_set_state(current_request,
                           REQUEST_STATE_ROUTE_CREATE_FACE_CHECK);
      INFO(">>>>>>subrequest create face");
      return hicnlight_prepare_subrequest(
          sock, request, ACTION_CREATE, OBJECT_TYPE_FACE,
          (hc_object_t *)&object->route.face, buffer);

    case REQUEST_STATE_ROUTE_CREATE_FACE_CHECK:
      if (!data) return -1;
      int rc = hc_data_get_result(data);
      if (rc < 0) return -1;

      if (hc_data_get_size(data) != 1) return -1;

      face_obj = hc_data_get_object(data, 0);
      DEBUG("Created face id=%d", face_obj->face.id);
      object->route.face_id = face_obj->face.id;

      hc_request_set_state(current_request, REQUEST_STATE_ROUTE_CREATE);
      goto NEXT;

    /* Create route */
    case REQUEST_STATE_ROUTE_CREATE:
      /*
       * Break recursion by directly calling hicnlight_prepare_generic on the
       * initial request, that can now be executed since all prerequisites are
       * validated.
       */
      hc_request_set_state(current_request, REQUEST_STATE_COMPLETE);
      return hicnlight_prepare_generic(sock, request, buffer);

    case REQUEST_STATE_COMPLETE:
      hc_data_set_complete(data);
      break;

    default:
      return -1;
  }
  return 0;
}

static int hicnlight_recv(hc_sock_t *sock) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  int rc;

  /*
   * This condition should be ensured to guarantee correct processing of
   * messages. With TCP, we need at least a header as we will receive part of
   * the stream. With UDP, we need the be able to receive the full datagram,
   * otherwise the rest will be lost.
   *
   * Let's be sure to always be able to receive at least 1 JUMBO_MTU, which
   * should be fine for al situations.
   */
  _ASSERT(RECV_BUFLEN - s->woff > JUMBO_MTU);

  rc = (int)recv(s->fd, s->buf + s->woff, RECV_BUFLEN - s->woff, 0);
  if (rc == 0) {
    /* Connection has been closed */
    return 0;
  }
  if (rc < 0) {
    /*
     * Let's not return 0 which currently means the socket has been closed
     */
    if (errno == EWOULDBLOCK) {
      // XXX TODO ?if (hc_request_get_action(request) == ACTION_SUBSCRIBE)
      // return 0;
      return -1;
    }
    if (errno == EINTR) {
      WARN("recv has been stopped by signal");
      return -1;
    }
    perror("hc_sock_light_recv");
    return -1;
  }
  DEBUG("Received rc=%ld bytes", rc);
  s->woff += rc;

  return rc;
}

/*
 *
 * @param [in] data - hc_data_t structure allocated for the request
 *
 * This function is the entry point for all requests, and from there we will
 * decide whether
 *
 */
static ssize_t hicnlight_prepare(hc_sock_t *sock, hc_request_t *request,
                                 uint8_t **buffer) {
  /* Dispatch to subrequest if any */
  hc_request_t *current_request = hc_request_get_current(request);

  // XXX when do we create data... once for every step
  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);

  static hc_object_t object_subscribe;

  DEBUG("[hicnlight_prepare] %s %s", action_str(action),
        object_type_str(object_type));

  /*
   * Here the request is in progress and we just need to iterate through the
   * FSM, or complete it.
   */
  /*
   * Specific treatment for
   *   CREATE/ROUTE with face
   *   SUBSCRIBE/(*)
   *   GET/(*)
   *   (*)/FACE
   */

  /*
   * Special treatment for faces.
   *
   * This function will be called multiple times in order to process the
   * complex request, involving several calls to the API. The process is
   * responsible for going through the related state machine, and complete the
   * request when appropriate.
   */
  if (object_type == OBJECT_TYPE_FACE)
    return hicnlight_prepare_face(sock, request, buffer);

  switch (action) {
    case ACTION_CREATE:
      switch (object_type) {
        case OBJECT_TYPE_ROUTE:
          /* Route might require face creation */
          return hicnlight_prepare_route_create(sock, request, buffer);
        case OBJECT_TYPE_CONNECTION:
          /* Connection could have no corresponging listener, or no local info
           * provided */
          return hicnlight_prepare_connection_create(sock, request, buffer);
        default:
          break;
      }
      break;

    case ACTION_GET:
      return hicnlight_prepare_get(sock, request, buffer);

    case ACTION_SUBSCRIBE:
      /* Transform subscription queries */
      memset(&object_subscribe, 0, sizeof(hc_object_t));
      object->subscription.topics = topic_from_object_type(object_type);

      hc_request_set(request, ACTION_CREATE, OBJECT_TYPE_SUBSCRIPTION, object);
      break;

    default:
      break;
  }

    /*
     * Generic requests should complete after a single call to hicnlight_send,
     * with *pdata = NULL. If *pdata is not NULL, that means the request has
     * completed and we can close it.
     * It is the responsability of each state machine to complete the request
     * otherwise.
     */
#if 1
  hc_data_t *data = hc_request_get_data(current_request);
  if (data) {
    hc_request_set_complete(current_request);
    return 0;
  }
#endif

  return hicnlight_prepare_generic(sock, request, buffer);
}

/*
 * This function processes incoming data in the ring buffer. Multiple requests
 * might be interleaves, including regular requests and notifications.
 * Responses might arrive fragment over several read events, but our
 * assumption is that fragments arrive consecutively and are not interleaves
 * with fragments from other requests... otherwise we would have to way to
 * reconstruct a message.
 *
 * count != 0 when an external process has added data to the ring buffer
 * without updating indices
 */
static int hicnlight_process(hc_sock_t *sock, size_t count) {
  hc_sock_light_data_t *s = (hc_sock_light_data_t *)sock->data;
  int rc;

  if (count > 0) s->woff += count;

  /*
   * We loop consuming messages until there is no more data in the ring
   * buffer, or that we can find an entire message. Messages are received
   * sequentially, and we keep track of incomplete requests in s->cur_request.
   */
  while (AVAILABLE(s) > 0) {
    if (!s->got_header) {
      rc = hicnlight_process_header(sock);
    } else {
      rc = hicnlight_process_payload(sock);
    }
    if (rc < 0) break;
  }

  if ((rc == -99) || (s->roff == s->woff)) {
    /* Flush buffer */
    s->woff = 0;
  } else {
    /* Clean up read data from buffer */
    memmove(s->buf, s->buf + s->roff, AVAILABLE(s));
    s->woff -= s->roff;
  }
  s->roff = 0;

  return rc;
}

hc_sock_ops_t hc_sock_light = (hc_sock_ops_t) {
  .create_data = (void *(*)(const char *))hc_sock_light_data_create,
  .free_data = (void (*)(void *))hc_sock_light_data_free,
  .get_fd = hicnlight_get_fd, .get_recv_buffer = hicnlight_get_recv_buffer,
  .connect = hicnlight_connect, .disconnect = hicnlight_disconnect,
  .prepare = hicnlight_prepare, .send = hicnlight_send, .recv = hicnlight_recv,
  .process = hicnlight_process,
#if 0
    .object_vft = {
        [OBJECT_TYPE_LISTENER] = HC_MODULE_OBJECT_OPS(hicnlight, listener),
        [OBJECT_TYPE_CONNECTION] = HC_MODULE_OBJECT_OPS(hicnlight, connection),
        [OBJECT_TYPE_FACE] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_PUNTING] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_CACHE] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_MAPME] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_WLDR] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_POLICY] = HC_MODULE_OBJECT_OPS_EMPTY,
        [OBJECT_TYPE_ROUTE] = HC_MODULE_OBJECT_OPS(hicnlight, route),
        [OBJECT_TYPE_STRATEGY] = HC_MODULE_OBJECT_OPS(hicnlight, strategy),
        [OBJECT_TYPE_SUBSCRIPTION] = HC_MODULE_OBJECT_OPS(hicnlight, subscription),
}
#endif
};

size_t hc_light_object_size(hc_object_type_t object_type) {
  hc_module_object_ops_t *vft = &hc_sock_light.object_vft[object_type];
  if (!vft) return 0;
  return vft->serialized_size;
}

ssize_t hc_light_command_serialize(hc_action_t action,
                                   hc_object_type_t object_type,
                                   hc_object_t *object, uint8_t *msg) {
  hc_module_object_ops_t *vft = &hc_sock_light.object_vft[object_type];
  if (!vft || !vft->serialize[action]) return 0;
  return vft->serialize[action](object, msg);
}

// Public constructor

int hc_sock_initialize_module(hc_sock_t *s) {
  //
  /*
   * We do this because initialization in the static struct fails with
   * 'initializer element is not constant'
   */
#if 1
  hc_sock_light.object_vft[OBJECT_TYPE_LISTENER] =
      hicnlight_listener_module_ops;
  hc_sock_light.object_vft[OBJECT_TYPE_CONNECTION] =
      hicnlight_connection_module_ops;
  hc_sock_light.object_vft[OBJECT_TYPE_FACE] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_PUNTING] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_CACHE] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_MAPME] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_WLDR] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_POLICY] = HC_MODULE_OBJECT_OPS_EMPTY;
  hc_sock_light.object_vft[OBJECT_TYPE_ROUTE] = hicnlight_route_module_ops;
  hc_sock_light.object_vft[OBJECT_TYPE_STRATEGY] =
      hicnlight_strategy_module_ops;
  hc_sock_light.object_vft[OBJECT_TYPE_SUBSCRIPTION] =
      hicnlight_subscription_module_ops;
#endif

  if (s) s->ops = hc_sock_light;
  return 0;
}
