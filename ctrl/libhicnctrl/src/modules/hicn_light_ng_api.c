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

#include <assert.h>  // assert
#include <fcntl.h>   // fcntl
#include <stdbool.h>
#include <stdio.h>       // snprintf
#include <string.h>      // memmove, strcasecmp
#include <sys/socket.h>  // socket
#include <sys/types.h>   // getpid
#include <unistd.h>      // close, fcntl
#include <unistd.h>      // getpid

#include "api_private.h"
#ifdef __linux__
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif /* __linux__ */
#include <hicn/ctrl/hicn-light-ng.h>
#include <strings.h>

#include "hicn_light_common.h"
#include <hicn/util/sstrncpy.h>

#pragma GCC diagnostic ignored "-Warray-bounds"

#if 0
#ifdef __APPLE__
#define RANDBYTE() (u8)(arc4random() & 0xFF)
#else
#define RANDBYTE() (u8)(random() & 0xFF)
#endif
#endif
#define RANDBYTE() (u8)(rand() & 0xFF)

/**
 * \brief Defines the default size for the allocated data arrays holding the
 * results of API calls.
 *
 * This size should not be too small to avoid wasting memoyy, but also not too
 * big to avoid unnecessary realloc's. Later on this size is doubled at each
 * reallocation.
 */
#define DEFAULT_SIZE_LOG 3

#define connection_state_to_face_state(x) ((face_state_t)(x))
#define face_state_to_connection_state(x) ((hc_connection_state_t)(x))

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_hc_command     \
  _(connection_add)            \
  _(connection_remove)         \
  _(connection_list)           \
  _(listener_add)              \
  _(listener_remove)           \
  _(listener_list)             \
  _(route_add)                 \
  _(route_remove)              \
  _(route_list)                \
  _(cache_set_store)           \
  _(cache_set_serve)           \
  _(cache_clear)               \
  _(cache_list)                \
  _(strategy_set)              \
  _(strategy_add_local_prefix) \
  _(wldr_set)                  \
  _(punting_add)               \
  _(mapme_activator)           \
  _(mapme_timing)              \
  _(subscription_add)          \
  _(subscription_remove)       \
  _(stats_get)                 \
  _(stats_list)

const char *command_type_str[] = {
#define _(l, u) [COMMAND_TYPE_##u] = STRINGIZE(u),
    foreach_command_type
#undef _
};

typedef cmd_header_t hc_msg_header_t;

typedef union {
#define _(x) cmd_##x##_t x;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

typedef struct hc_msg_s {
  hc_msg_header_t hdr;
  hc_msg_payload_t payload;
} hc_msg_t;

/******************************************************************************
 * Control socket
 ******************************************************************************/

#define AVAILABLE(s) ((s)->woff - (s)->roff)
#define DEFAULT_SOCK_RECV_TIMEOUT_MS 100

/**
 * \brief Parse a connection URL into a sockaddr
 * \param [in] url - URL
 * \param [out] sa - Resulting struct sockaddr, expected zero'ed.
 * \return 0 if parsing succeeded, a negative error value otherwise.
 */
static int _hcng_sock_light_parse_url(const char *url, struct sockaddr *sa) {
  /* FIXME URL parsing is currently not implemented */
  assert(!url);

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

static int _hcng_sock_light_reset(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  s->roff = s->woff = 0;
  s->remaining = 0;
  return 0;
}

void _hcng_sock_light_free(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);

  unsigned k_seq;
  hc_sock_request_t *v_request;
  kh_foreach(s->map, k_seq, v_request,
             { hc_sock_light_request_free(v_request); });

  kh_destroy_sock_map(s->map);
  if (s->url) free(s->url);
  close(s->fd);
  free(s);
}

static void _hcng_sock_increment_woff(hc_sock_t *socket, size_t bytes) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  s->woff += bytes;
}

static int _hcng_sock_light_get_next_seq(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  return s->seq++;
}

static int _hcng_sock_light_set_nonblocking(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  return (fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL) | O_NONBLOCK) < 0);
}

static int _hcng_sock_light_get_fd(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  return s->fd;
}

static int _hcng_sock_light_connect(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  struct sockaddr_storage ss;
  memset(&ss, 0, sizeof(struct sockaddr_storage));

  if (_hcng_sock_light_parse_url(s->url, (struct sockaddr *)&ss) < 0)
    goto ERR_PARSE;

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

static int _hcng_sock_light_send(hc_sock_t *socket, hc_msg_t *msg,
                                 size_t msglen, uint32_t seq) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  int rc;
  msg->hdr.seq_num = seq;
  rc = (int)send(s->fd, msg, msglen, 0);
  if (rc < 0) {
    perror("hc_sock_light_send");
    return -1;
  }
  return 0;
}

static int _hcng_sock_light_get_available(hc_sock_t *socket, u8 **buffer,
                                          size_t *size) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  *buffer = s->buf + s->woff;
  *size = RECV_BUFLEN - s->woff;

  return 0;
}

static int _hcng_sock_light_recv(hc_sock_t *socket) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
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
  assert(RECV_BUFLEN - s->woff > JUMBO_MTU);

  rc = (int)recv(s->fd, s->buf + s->woff, RECV_BUFLEN - s->woff, 0);
  if (rc == 0) {
    /* Connection has been closed */
    return 0;
  }
  if (rc < 0) {
    /*
     * Let's not return 0 which currently means the socket has been closed
     */
    if (errno == EWOULDBLOCK) return -1;
    if (errno == EINTR) {
      WARN("recv has been stopped by signal");
      return -1;
    }
    perror("hc_sock_light_recv");
    return -1;
  }
  s->woff += rc;
  return rc;
}

static void _hcng_sock_light_mark_complete(hc_sock_light_t *s,
                                           hc_data_t **pdata) {
  hc_data_t *data = s->cur_request->data;

  khiter_t k = kh_get_sock_map(s->map, s->cur_request->seq);
  if (k == kh_end(s->map)) {
    ERROR("[hc_sock_light_mark_complete] Error removing request from map");
  } else {
    kh_del_sock_map(s->map, k);
  }

  hc_data_set_complete(data);
  if (pdata) *pdata = data;

  /* Free current request */
  hc_sock_light_request_free(s->cur_request);
  s->cur_request = NULL;
}

static int _hcng_sock_light_process_notification(hc_sock_light_t *s,
                                                 hc_data_t **pdata) {
  /* For now, notifications are not associated to requests */
  assert(!s->cur_request);

  /*
   * Assumption: the whole notification data is returned in a single read and we
   * immediately parse it.
   *
   * XXX This is only valid for UDP sockets.
   */
  size_t notification_size = AVAILABLE(s);

  *pdata = hc_data_create(0, /* in_element_size, 0 = no parsing */
                          notification_size, /* out_element_size */
                          NULL);             /* complete_cb */

  /* Copy the packet payload as the single entry in hc_data_t */
  hc_data_push_many(*pdata, s->buf + s->roff, 1);

  return (int)notification_size;
}

/*
 * Notifications have no sequence number and are not linked to any request
 */
static hc_sock_request_t *_hcng_sock_light_get_request(hc_sock_light_t *s,
                                                       int seq) {
  hc_sock_request_t *request;
  /* Retrieve request from sock map */
  khiter_t k = kh_get_sock_map(s->map, seq);
  if (k == kh_end(s->map)) {
    ERROR(
        "[_hcng_sock_light_get_request] Error searching for matching request");
    return NULL;
  }
  request = kh_val(s->map, k);

  if (!request) {
    ERROR("[_hcng_sock_light_get_request] No request matching sequence number");
    return NULL;
  }
  return request;
}

/*
 * Return codes:
 * 0 success, or not enough data yet to do something
 * > 0 : notification type
 * -99 invalid buffer data -> flush
 */
static int _hcng_sock_light_process_header(hc_sock_light_t *s,
                                           hc_data_t **pdata) {
  int rc;

  /* Check we have at least a header's worth of data, and consume it */
  if (AVAILABLE(s) < sizeof(hc_msg_header_t)) return 0;

  hc_msg_t *msg = (hc_msg_t *)(s->buf + s->roff);

  // INFO("Processing header header %s", command_type_str(msg->hdr.command_id));
  s->roff += sizeof(hc_msg_header_t);

  if (msg->hdr.message_type != NOTIFICATION_LIGHT) {
    s->cur_request = _hcng_sock_light_get_request(s, msg->hdr.seq_num);
    if (!s->cur_request) return -99;
  }

  /* How many elements are we expecting in the reply ? */
  s->remaining = msg->hdr.length;
  hc_data_t *request_data;

  switch (msg->hdr.message_type) {
    case ACK_LIGHT:
      assert(s->remaining == 1);  // sic
      assert(!pdata);
      _hcng_sock_light_mark_complete(s, pdata);
      break;

    case NACK_LIGHT:
      assert(!pdata);
      assert(s->remaining == 1);  // sic
      request_data = s->cur_request->data;
      _hcng_sock_light_mark_complete(s, pdata);
      hc_data_set_error(request_data);
      break;

    case RESPONSE_LIGHT:
      assert(pdata);

      if (s->remaining == 0) {
        /* Empty response (i.e. containing 0 elements) */
        _hcng_sock_light_mark_complete(s, pdata);
        return 0;
      }

      /* Make room in hc_data_t... to avoid multiple calls */
      rc = hc_data_ensure_available(s->cur_request->data, s->remaining);
      if (rc < 0) {
        ERROR("[hc_sock_light_process] Error in hc_data_ensure_available");
        return -99;
      }
      break;

    case NOTIFICATION_LIGHT: {
      assert(pdata);
      assert(s->remaining == 0);

      /* This returns the notification size */
      size_t notification_size =
          _hcng_sock_light_process_notification(s, pdata);
      s->roff += notification_size;
      return msg->hdr.command_id;
    }

    default:
      ERROR("[hc_sock_light_process] Invalid response received");
      return -99;
  }

  return 0;
}

static int _hcng_sock_light_process_payload(hc_sock_light_t *s,
                                            hc_data_t **pdata) {
  int err = 0;
  int rc;

  hc_data_t *data = s->cur_request->data;

  /* We only process full elements (size is stored in data) */
  size_t num_chunks = AVAILABLE(s) / data->in_element_size;

  /* Check whether we have enough data to process */
  if (num_chunks == 0) return 0;

  /* Safeguard: assert(num_chunks < s->remaining); */
  if (num_chunks > s->remaining) {
    WARN(
        "[_hcng_sock_light_process_payload] Unexpected num_chunks > "
        "s->remaining");
    num_chunks = s->remaining;
  }

  if (!s->cur_request->parse) {
    /* If we don't need to parse results, then we can directly push
     * all of them into the result data structure */
    hc_data_push_many(data, s->buf + s->roff, num_chunks);
  } else {
    /* Iterate on chunks of data */
    for (int i = 0; i < num_chunks; i++) {
      /* Get storage offset in hc_data_t */
      u8 *dst = hc_data_get_next(data);
      if (!dst) {
        ERROR("[hc_sock_light_process] Error in hc_data_get_next");
        err = -2;
        break;
      }

      /* Parse element #i */
      rc = s->cur_request->parse(s->buf + s->roff + i * data->in_element_size,
                                 dst);
      if (rc < 0) {
        ERROR("[hc_sock_light_process] Error in parse");
        err = -1;
        /* In this case we let the loop complete to collect other results */
      }
      data->size++;
    }
  }

  s->roff += num_chunks * data->in_element_size;

  /*
   * If we are not expecting any more data, mark the reply as complete
   */
  s->remaining -= num_chunks;
  if (s->remaining == 0) _hcng_sock_light_mark_complete(s, pdata);

  return err;
}

/*
 * Process messages as they are received in the ring buffer. There can be
 * interleaved queries and replies (they are identified by sequence number),
 * and the assumption is that a reply can arrive over mutiple packets (in
 * other terms, it is possible that not all data from the reply is available
 * in the buffer at a given time). However, we assume that a full query is
 * received at once.
 */
static int _hcng_sock_light_process(hc_sock_t *socket, hc_data_t **data) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  int rc = 0;

  /*
   * We loop consuming messages until there is no more data in the buffer,
   * or that we can find an entire message. Messages are received
   * sequentially, and we keep track of incomplete requests in s->cur_request.
   */
  while (AVAILABLE(s) > 0) {
    if (!s->cur_request) {
      rc = _hcng_sock_light_process_header(s, data);
    } else {
      rc = _hcng_sock_light_process_payload(s, data);
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

static int _hcng_sock_light_callback(hc_sock_t *socket, hc_data_t **pdata) {
  hc_data_t *data = NULL;
  int rc = 0;

  for (;;) {
    int n = _hcng_sock_light_recv(socket);
    if (n == 0) goto ERR_EOF;
    if (n < 0) {
      switch (errno) {
        case ECONNRESET:
        case ENODEV:
          /* Forwarder restarted */
          WARN("Forwarder likely restarted: not (yet) implemented");
          goto ERR;
        case EWOULDBLOCK:
          // DEBUG("Would block... stop reading from socket");
          goto END;
        case EINTR:
          WARN("callback has been stopped by signal");
          goto ERR;
        default:
          perror("hc_sock_light_callback");
          goto ERR;
      }
    }
    rc = _hcng_sock_light_process(socket, &data);
    if (rc < 0) goto ERR;
    if (rc > 0)  // i.e. rc = notification type
      goto END;
  }
END:
  if (pdata)
    *pdata = data;
  else
    hc_data_free(data);
  return rc;

ERR:
  hc_data_free(data);
ERR_EOF:
  return -1;
}

/******************************************************************************
 * Command-specific structures and functions
 ******************************************************************************/

typedef int (*HC_PARSE)(const u8 *, u8 *);

typedef struct {
  hc_action_t cmd;
  command_type_t cmd_id;
  size_t size_in;
  size_t size_out;
  HC_PARSE parse;
} hc_command_params_t;

typedef struct hc_result_s {
  hc_msg_t msg;
  hc_command_params_t params;
  bool async;
  bool success;
} hc_result_t;

int _hcng_sock_prepare_send(hc_sock_t *socket, hc_result_t *result,
                            data_callback_t complete_cb,
                            void *complete_cb_data) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);

  // Prepare data
  hc_data_t *data =
      hc_data_create(result->params.size_in, result->params.size_out, NULL);
  if (!data) {
    ERROR("[_hcng_sock_prepare_send] Could not create data storage");
    goto ERR_DATA;
  }
  hc_data_set_callback(data, complete_cb, complete_cb_data);

  // Update the sequence number
  int seq = _hcng_sock_light_get_next_seq(socket);
  result->msg.hdr.seq_num = seq;  // Like in _hcng_sock_light_send

  // Create state used to process the request
  hc_sock_request_t *request = NULL;
  request = hc_sock_request_create(seq, data, result->params.parse);
  if (!request) {
    ERROR("[_hcng_sock_prepare_send] Could not create request state");
    goto ERR_REQUEST;
  }

  int rc;
  khiter_t k = kh_put_sock_map(s->map, seq, &rc);
  if (rc != KH_ADDED && rc != KH_RESET) {
    ERROR("[_hcng_sock_prepare_send] Error adding request state to map");
    goto ERR_MAP;
  }
  kh_value(s->map, k) = request;

  return sizeof(result->msg);

ERR_MAP:
  hc_sock_light_request_free(request);
ERR_REQUEST:
  hc_data_free(data);
ERR_DATA:
  return -99;
}

int _hcng_sock_set_recv_timeout_ms(hc_sock_t *socket, long timeout_ms) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = (int)(timeout_ms * 1000);  // Convert ms into us
  if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setsockopt");
    return -1;
  }

  return 0;
}

static int _hcng_execute_command(hc_sock_t *socket, hc_msg_t *msg,
                                 size_t msg_len, hc_command_params_t *params,
                                 hc_data_t **pdata, bool async) {
  hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
  int ret;
  if (async) assert(!pdata);

  /* Sanity check */
  switch (params->cmd) {
    case ACTION_CREATE:
      assert(params->size_in != 0); /* payload repeated */
      assert(params->size_out == 0);
      assert(params->parse == NULL);
      break;
    case ACTION_DELETE:
      assert(params->size_in != 0); /* payload repeated */
      assert(params->size_out == 0);
      assert(params->parse == NULL);
      break;
    case ACTION_GET:
    case ACTION_LIST:
      assert(params->size_in != 0);
      assert(params->size_out != 0);
      // TODO(eloparco): Parsing should not be necessary after
      // (pending) refatoring
      // assert(params->parse != NULL);
      break;
    case ACTION_SET:
    case ACTION_SERVE:
    case ACTION_STORE:
    case ACTION_UPDATE:
      assert(params->size_in != 0);
      assert(params->size_out == 0);
      assert(params->parse == NULL);
      break;
    case ACTION_CLEAR:
      assert(params->size_in == 0);
      assert(params->size_out == 0);
      assert(params->parse == NULL);
      break;
    default:
      return -1;
  }

  // hc_sock_light_reset(s);

  /* XXX data will at least store the result (complete) */
  hc_data_t *data = hc_data_create(params->size_in, params->size_out, NULL);
  if (!data) {
    ERROR("[_hcng_execute_command] Could not create data storage");
    goto ERR_DATA;
  }

  int seq = _hcng_sock_light_get_next_seq(socket);

  /* Create state used to process the request */
  hc_sock_request_t *request = NULL;
  request = hc_sock_request_create(seq, data, params->parse);
  if (!request) {
    ERROR("[_hcng_execute_command] Could not create request state");
    goto ERR_REQUEST;
  }

  /* Add state to map */
  int rc;
  khiter_t k = kh_put_sock_map(s->map, seq, &rc);
  if (rc != KH_ADDED && rc != KH_RESET) {
    ERROR("[_hcng_execute_command] Error adding request state to map");
    goto ERR_MAP;
  }
  kh_value(s->map, k) = request;

  if (_hcng_sock_light_send(socket, msg, msg_len, seq) < 0) {
    ERROR("[_hcng_execute_command] Error sending message");
    goto ERR_PROCESS;
  }

  if (async) return 0;

  /*
   * Dangerous zone, we might be doing blocking operations on a non-blocking
   * UDP socket
   */
  int retries = 0;
  while (!data->complete) {
    /*
     * As the socket is non blocking it might happen that we need to read
     * several times before success...
     */
    int n = _hcng_sock_light_recv(socket);
    if (n == 0) goto ERR_EOF;
    if (n < 0) {
      if ((errno == EWOULDBLOCK) && (retries < 10)) { /* Max 500ms */
        DEBUG("read = EWOULDBLOCK... sleeping for 50ms (max 500ms)");
        usleep(50000); /* 50ms */
        retries++;
        continue;
      }
      break;
    }
    int rc = _hcng_sock_light_process(socket, pdata);
    switch (rc) {
      case 0:
      case -1:
        break;
      case -99:
        ERROR("[_hcng_execute_command] Error processing socket results");
        goto ERR;
      default:
        ERROR("[_hcng_execute_command] Unexpected return value");
        goto ERR;
    }
  }

ERR_EOF:
  ret = data->ret;
  if (!data->complete) return -1;
  if (!pdata) hc_data_free(data);

  return ret;

ERR_PROCESS:
ERR_MAP:
  hc_sock_light_request_free(request);
ERR:
ERR_REQUEST:
  hc_data_free(data);
ERR_DATA:
  return -99;
}

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

/* LISTENER CREATE */

static hc_result_t *_listener_create_serialize(hc_sock_t *s,
                                               hc_listener_t *listener,
                                               bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  char listener_s[MAXSZ_HC_LISTENER];
  int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
  if (rc >= MAXSZ_HC_LISTENER)
    WARN("[_hcng_listener_create] Unexpected truncation of listener string");
  DEBUG("[_hcng_listener_create] listener=%s async=%s", listener_s,
        BOOLSTR(async));

  if (hc_listener_validate(listener) < 0) {
    res->success = false;
    return res;
  }

  msg_listener_add_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_LISTENER_ADD,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .address = listener->local_addr,
                                .port = htons(listener->local_port),
                                .family = listener->family,
                                .type = listener->type,
                            }};

  rc = snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", listener->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_listener_create] Unexpected truncation of symbolic name "
        "string");

  rc = snprintf(msg.payload.interface_name, INTERFACE_LEN, "%s",
                listener->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[_hc_listener_create] Unexpected truncation of interface name "
        "string");

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_LISTENER_ADD,
      .size_in = sizeof(cmd_listener_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.listener_add = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_listener_create_conf(hc_sock_t *s,
                                               hc_listener_t *listener) {
  return _listener_create_serialize(s, listener, false);
}

static int _hcng_listener_create_internal(hc_sock_t *socket,
                                          hc_listener_t *listener, bool async) {
  hc_result_t *result = _listener_create_serialize(socket, listener, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  free(result);
  DEBUG("[_hcng_listener_create] done or error");
  return ret;
}

static int _hcng_listener_create(hc_sock_t *s, hc_listener_t *listener) {
  DEBUG("[_hcng_listener_create]");
  return _hcng_listener_create_internal(s, listener, false);
}

static int _hcng_listener_create_async(hc_sock_t *s, hc_listener_t *listener) {
  DEBUG("[_hcng_listener_create_async]");
  return _hcng_listener_create_internal(s, listener, true);
}

/* LISTENER PARSE */

static int hc_listener_parse(void *in, hc_listener_t *listener) {
  int rc;
  cmd_listener_list_item_t *item = (cmd_listener_list_item_t *)in;

  if (!IS_VALID_ID(item->id)) {
    ERROR("[hc_listener_parse] Invalid id received");
    return -1;
  }

  *listener = (hc_listener_t){
      .id = item->id,
      .type = item->type,
      .family = item->family,
      .local_addr = UNION_CAST(item->address, ip_address_t),
      .local_port = ntohs(item->port),
  };
  rc = snprintf(listener->name, SYMBOLIC_NAME_LEN, "%s", item->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN("[hc_listener_parse] Unexpected truncation of symbolic name string");
  rc = snprintf(listener->interface_name, INTERFACE_LEN, "%s",
                item->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN("[hc_listener_parse] Unexpected truncation of interface name string");

  if (hc_listener_validate(listener) < 0) return -1;
  return 0;
}

/* LISTENER LIST */

static hc_result_t *_hcng_listener_list_serialize(hc_sock_t *socket,
                                                  hc_data_t **pdata,
                                                  bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  DEBUG("[hc_listener_list] async=%s", BOOLSTR(async));

  msg_listener_list_t msg = {.header = {
                                 .message_type = REQUEST_LIGHT,
                                 .command_id = COMMAND_TYPE_LISTENER_LIST,
                                 .length = 0,
                                 .seq_num = 0,
                             }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_LISTENER_LIST,
      .size_in = sizeof(cmd_listener_list_item_t),
      .size_out = sizeof(hc_listener_t),
      .parse = (HC_PARSE)hc_listener_parse,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.listener_list = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_listener_list_conf(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_listener_list_serialize(s, pdata, false);
}

static int _hcng_listener_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                        bool async) {
  hc_result_t *result = _hcng_listener_list_serialize(socket, pdata, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, pdata,
                                result->async);
  }

  hc_result_free(result);
  DEBUG("[_hcng_listener_list] done or error");
  return ret;
}

static int _hcng_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[_hcng_listener_list]");
  return _hcng_listener_list_internal(s, pdata, false);
}

static int _hcng_listener_list_async(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[_hcng_listener_list_as-nc]");
  return _hcng_listener_list_internal(s, pdata, true);
}

/* LISTENER GET */

static int _hcng_listener_get(hc_sock_t *socket, hc_listener_t *listener,
                              hc_listener_t **listener_found) {
  hc_data_t *listeners;
  hc_listener_t *found;

  char listener_s[MAXSZ_HC_LISTENER];
  int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
  if (rc >= MAXSZ_HC_LISTENER)
    WARN("[hc_listener_get] Unexpected truncation of listener string");
  DEBUG("[hc_listener_get] listener=%s", listener_s);

  if (_hcng_listener_list(socket, &listeners) < 0) return -1;

  /* Test */
  if (hc_listener_find(listeners, listener, &found) < 0) {
    hc_data_free(listeners);
    return -1;
  }

  if (found) {
    *listener_found = malloc(sizeof(hc_listener_t));
    if (!*listener_found) return -1;
    **listener_found = *found;
  } else {
    *listener_found = NULL;
  }

  hc_data_free(listeners);

  return 0;
}

/* LISTENER DELETE */

static int _hcng_listener_delete_internal(hc_sock_t *socket,
                                          hc_listener_t *listener, bool async) {
  char listener_s[MAXSZ_HC_LISTENER];
  int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
  if (rc >= MAXSZ_HC_LISTENER)
    WARN("[_hcng_listener_delete] Unexpected truncation of listener string");
  DEBUG("[_hcng_listener_delete] listener=%s async=%s", listener_s,
        BOOLSTR(async));

  msg_listener_remove_t msg = {.header = {
                                   .message_type = REQUEST_LIGHT,
                                   .command_id = COMMAND_TYPE_LISTENER_REMOVE,
                                   .length = 1,
                                   .seq_num = 0,
                               }};

  if (listener->id) {
    rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d",
                  listener->id);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_listener_delete] Unexpected truncation of symbolic name "
          "string");
  } else if (*listener->name) {
    rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%s",
                  listener->name);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_listener_delete] Unexpected truncation of symbolic name "
          "string");
  } else {
    hc_listener_t *listener_found;
    if (_hcng_listener_get(socket, listener, &listener_found) < 0) return -1;
    if (!listener_found) return -1;
    rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d",
                  listener_found->id);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_listener_delete] Unexpected truncation of symbolic name "
          "string");
    free(listener_found);
  }

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_LISTENER_REMOVE,
      .size_in = sizeof(cmd_listener_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_listener_delete(hc_sock_t *s, hc_listener_t *listener) {
  return _hcng_listener_delete_internal(s, listener, false);
}

static int _hcng_listener_delete_async(hc_sock_t *s, hc_listener_t *listener) {
  return _hcng_listener_delete_internal(s, listener, true);
}

/*----------------------------------------------------------------------------*
 * CONNECTION
 *----------------------------------------------------------------------------*/

/* CONNECTION CREATE */

static hc_result_t *_connection_create_serialize(hc_sock_t *socket,
                                                 hc_connection_t *connection,
                                                 bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  char connection_s[MAXSZ_HC_CONNECTION];
  int rc =
      hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
  if (rc >= MAXSZ_HC_CONNECTION)
    WARN(
        "[_hcng_connection_create] Unexpected truncation of connection "
        "string");
  DEBUG("[_hcng_connection_create] connection=%s async=%s", connection_s,
        BOOLSTR(async));

  if (hc_connection_validate(connection) < 0) {
    res->success = false;
    return res;
  }

  msg_connection_add_t msg = {.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_CONNECTION_ADD,
                                      .length = 1,
                                      .seq_num = 0,
                                  },
                              .payload = {
                                  .remote_ip = connection->remote_addr,
                                  .local_ip = connection->local_addr,
                                  .remote_port = htons(connection->remote_port),
                                  .local_port = htons(connection->local_port),
                                  .family = connection->family,
                                  .type = connection->type,
                                  .admin_state = connection->admin_state,
#ifdef WITH_POLICY
                                  .priority = connection->priority,
                                  .tags = connection->tags,
#endif /* WITH_POLICY */
                              }};
  rc =
      snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", connection->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_create] Unexpected truncation of symbolic name "
        "string");
  // snprintf(msg.payload.interface_name, INTERFACE_NAME_LEN, "%s",
  // connection->interface_name);

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_CONNECTION_ADD,
      .size_in = sizeof(cmd_connection_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.connection_add = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_connection_create_conf(hc_sock_t *s,
                                                 hc_connection_t *connection) {
  return _connection_create_serialize(s, connection, false);
}

static int _hcng_connection_create_internal(hc_sock_t *socket,
                                            hc_connection_t *connection,
                                            bool async) {
  hc_result_t *result = _connection_create_serialize(socket, connection, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  DEBUG("[_hcng_connection_create] done or error");
  return ret;
}

static int _hcng_connection_create(hc_sock_t *s, hc_connection_t *connection) {
  DEBUG("[_hcng_connection_create]");
  return _hcng_connection_create_internal(s, connection, false);
}

static int _hcng_connection_create_async(hc_sock_t *s,
                                         hc_connection_t *connection) {
  DEBUG("[_hcng_connection_create_async]");
  return _hcng_connection_create_internal(s, connection, true);
}

/* CONNECTION PARSE */

static int hc_connection_parse(void *in, hc_connection_t *connection) {
  int rc;
  cmd_connection_list_item_t *item = (cmd_connection_list_item_t *)in;

  if (!IS_VALID_ID(item->id)) {
    ERROR("[hc_connection_parse] Invalid id received");
    return -1;
  }

  *connection = (hc_connection_t){
      .id = item->id,
      .type = item->type,
      .family = item->family,
      .local_addr = item->local_addr,
      .local_port = ntohs(item->local_port),
      .remote_addr = item->remote_addr,
      .remote_port = ntohs(item->remote_port),
      .admin_state = item->admin_state,
#ifdef WITH_POLICY
      .priority = item->priority,
      .tags = item->tags,
#endif /* WITH_POLICY */
      .state = item->state,
  };
  rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s", item->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[hc_connection_parse] Unexpected truncation of symbolic name "
        "string");
  rc = snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                item->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[hc_connection_parse] Unexpected truncation of interface name "
        "string");

  if (hc_connection_validate(connection) < 0) return -1;
  return 0;
}

/* CONNECTION LIST */

static int _hcng_connection_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                          bool async) {
  DEBUG("[hc_connection_list] async=%s", BOOLSTR(async));

  msg_connection_list_t msg = {.header = {
                                   .message_type = REQUEST_LIGHT,
                                   .command_id = COMMAND_TYPE_CONNECTION_LIST,
                                   .length = 0,
                                   .seq_num = 0,
                               }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_CONNECTION_LIST,
      .size_in = sizeof(cmd_connection_list_item_t),
      .size_out = sizeof(hc_connection_t),
      .parse = (HC_PARSE)hc_connection_parse,
  };

  int ret = _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg),
                                  &params, pdata, async);

  DEBUG("[hc_connection_list] done or error");
  return ret;
}

static int _hcng_connection_list(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[hc_connection_list]");
  return _hcng_connection_list_internal(s, pdata, false);
}

static int _hcng_connection_list_async(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[hc_connection_list_async]");
  return _hcng_connection_list_internal(s, pdata, true);
}

/* CONNECTION GET */

static int _hcng_connection_get(hc_sock_t *socket, hc_connection_t *connection,
                                hc_connection_t **connection_found) {
  hc_data_t *connections;
  hc_connection_t *found;

  char connection_s[MAXSZ_HC_CONNECTION];
  int rc =
      hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
  if (rc >= MAXSZ_HC_CONNECTION)
    WARN("[hc_connection_get] Unexpected truncation of connection string");
  DEBUG("[hc_connection_get] connection=%s", connection_s);

  if (_hcng_connection_list(socket, &connections) < 0) return -1;

  /* Test */
  if (hc_connection_find(connections, connection, &found) < 0) {
    hc_data_free(connections);
    return -1;
  }

  if (found) {
    *connection_found = malloc(sizeof(hc_connection_t));
    if (!*connection_found) return -1;
    **connection_found = *found;
  } else {
    *connection_found = NULL;
  }

  hc_data_free(connections);

  return 0;
}

/* CONNECTION DELETE */

static hc_result_t *_hcng_connection_delete_serialize(
    hc_sock_t *socket, hc_connection_t *connection, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  res->success = false;

  char connection_s[MAXSZ_HC_CONNECTION];
  int rc =
      hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
  if (rc >= MAXSZ_HC_CONNECTION)
    WARN(
        "[_hcng_connection_delete] Unexpected truncation of connection "
        "string");
  DEBUG("[_hcng_connection_delete] connection=%s async=%s", connection_s,
        BOOLSTR(async));

  msg_connection_remove_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_REMOVE,
              .length = 1,
              .seq_num = 0,
          },
  };

  if (connection->id) {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  connection->id);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
  } else if (*connection->name) {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  connection->name);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
  } else {
    hc_connection_t *connection_found;
    if (hc_connection_get(socket, connection, &connection_found) < 0)
      return res;
    if (!connection_found) return res;
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  connection_found->id);
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
    free(connection_found);
  }

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_CONNECTION_REMOVE,
      .size_in = sizeof(cmd_connection_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.connection_remove = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_connection_delete_conf(hc_sock_t *s,
                                                 hc_connection_t *connection) {
  return _hcng_connection_delete_serialize(s, connection, false);
}

static int _hcng_connection_delete_internal(hc_sock_t *socket,
                                            hc_connection_t *connection,
                                            bool async) {
  hc_result_t *result =
      _hcng_connection_delete_serialize(socket, connection, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

static int _hcng_connection_delete(hc_sock_t *s, hc_connection_t *connection) {
  return _hcng_connection_delete_internal(s, connection, false);
}

static int _hcng_connection_delete_async(hc_sock_t *s,
                                         hc_connection_t *connection) {
  return _hcng_connection_delete_internal(s, connection, true);
}

/* CONNECTION UPDATE */

static int _hcng_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                                         hc_connection_t *connection) {
  // Not implemented
  return -1;
}

static int _hcng_connection_update(hc_sock_t *s,
                                   hc_connection_t *connection_current,
                                   hc_connection_t *connection_updated) {
  // Not implemented
  return -1;
}

/* CONNECTION SET ADMIN STATE */

static int _hcng_connection_set_admin_state_internal(
    hc_sock_t *socket, const char *conn_id_or_name, face_state_t state,
    bool async) {
  int rc;
  DEBUG(
      "[hc_connection_set_admin_state] connection_id/name=%s admin_state=%s "
      "async=%s",
      conn_id_or_name, face_state_str(state), BOOLSTR(async));

  struct {
    cmd_header_t hdr;
    cmd_connection_set_admin_state_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_ADMIN_STATE,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .admin_state = state,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_admin_state] Unexpected truncation of symbolic "
        "name string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_ADMIN_STATE,
      .size_in = sizeof(cmd_connection_set_admin_state_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_connection_set_admin_state(hc_sock_t *s,
                                            const char *conn_id_or_name,
                                            face_state_t state) {
  return _hcng_connection_set_admin_state_internal(s, conn_id_or_name, state,
                                                   false);
}

static int _hcng_connection_set_admin_state_async(hc_sock_t *s,
                                                  const char *conn_id_or_name,
                                                  face_state_t state) {
  return _hcng_connection_set_admin_state_internal(s, conn_id_or_name, state,
                                                   true);
}

#ifdef WITH_POLICY

static int _hcng_connection_set_priority_internal(hc_sock_t *socket,
                                                  const char *conn_id_or_name,
                                                  uint32_t priority,
                                                  bool async) {
  int rc;
  DEBUG(
      "[hc_connection_set_priority] connection_id/name=%s priority=%d "
      "async=%s",
      conn_id_or_name, priority, BOOLSTR(async));
  struct {
    cmd_header_t hdr;
    cmd_connection_set_priority_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_PRIORITY,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .priority = priority,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_priority] Unexpected truncation of symbolic "
        "name "
        "string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_PRIORITY,
      .size_in = sizeof(cmd_connection_set_priority_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_connection_set_priority(hc_sock_t *s,
                                         const char *conn_id_or_name,
                                         uint32_t priority) {
  return _hcng_connection_set_priority_internal(s, conn_id_or_name, priority,
                                                false);
}

static int _hcng_connection_set_priority_async(hc_sock_t *s,
                                               const char *conn_id_or_name,
                                               uint32_t priority) {
  return _hcng_connection_set_priority_internal(s, conn_id_or_name, priority,
                                                true);
}

#endif  // WITH_POLICY

static int _hcng_connection_set_tags_internal(hc_sock_t *s,
                                              const char *conn_id_or_name,
                                              policy_tags_t tags, bool async) {
  int rc;
  DEBUG("[hc_connection_set_tags] connection_id/name=%s tags=%d async=%s",
        conn_id_or_name, tags, BOOLSTR(async));
  struct {
    cmd_header_t hdr;
    cmd_connection_set_tags_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_TAGS,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .tags = tags,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_tags] Unexpected truncation of symbolic name "
        "string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_TAGS,
      .size_in = sizeof(cmd_connection_set_tags_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL,
                               async);
}

static int _hcng_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                                     policy_tags_t tags) {
  return _hcng_connection_set_tags_internal(s, conn_id_or_name, tags, false);
}

static int _hcng_connection_set_tags_async(hc_sock_t *s,
                                           const char *conn_id_or_name,
                                           policy_tags_t tags) {
  return _hcng_connection_set_tags_internal(s, conn_id_or_name, tags, true);
}

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

/* ROUTE CREATE */

static hc_result_t *_route_create_serialize(hc_sock_t *socket,
                                            hc_route_t *route, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  char route_s[MAXSZ_HC_ROUTE];
  int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, route);
  if (rc >= MAXSZ_HC_ROUTE)
    WARN("[_hc_route_create] Unexpected truncation of route string");
  if (rc < 0)
    WARN("[_hc_route_create] Error building route string");
  else
    DEBUG("[hc_route_create] route=%s async=%s", route_s, BOOLSTR(async));

  if (hc_route_validate(route) < 0) {
    res->success = false;
    return res;
  }

  msg_route_add_t msg = {.header =
                             {
                                 .message_type = REQUEST_LIGHT,
                                 .command_id = COMMAND_TYPE_ROUTE_ADD,
                                 .length = 1,
                                 .seq_num = 0,
                             },
                         .payload = {
                             .address = route->remote_addr,
                             .cost = route->cost,
                             .family = route->family,
                             .len = route->len,
                         }};

  /*
   * The route commands expects the ID or name as part of the
   * symbolic_or_connid attribute.
   */
  if (route->name[0] != '\0') {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  route->name);
  } else {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  route->face_id);
  }

  if (rc >= SYMBOLIC_NAME_LEN)
    WARN("[_hc_route_create] Unexpected truncation of symbolic name string");

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_ROUTE_ADD,
      .size_in = sizeof(cmd_route_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.route_add = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_route_create_conf(hc_sock_t *s, hc_route_t *route) {
  return _route_create_serialize(s, route, false);
}

static int _hcng_route_create_internal(hc_sock_t *socket, hc_route_t *route,
                                       bool async) {
  hc_result_t *result = _route_create_serialize(socket, route, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

static int _hcng_route_create(hc_sock_t *s, hc_route_t *route) {
  return _hcng_route_create_internal(s, route, false);
}

static int _hcng_route_create_async(hc_sock_t *s, hc_route_t *route) {
  return _hcng_route_create_internal(s, route, true);
}

/* ROUTE DELETE */

static int _hcng_route_delete_internal(hc_sock_t *socket, hc_route_t *route,
                                       bool async) {
  char route_s[MAXSZ_HC_ROUTE];
  int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, route);
  if (rc >= MAXSZ_HC_ROUTE)
    WARN("[_hc_route_delete] Unexpected truncation of route string");
  DEBUG("[hc_route_delete] route=%s async=%s", route_s, BOOLSTR(async));

  if (!IS_VALID_FAMILY(route->family)) return -1;

  struct {
    cmd_header_t hdr;
    cmd_route_remove_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   .command_id = COMMAND_TYPE_ROUTE_REMOVE,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = route->remote_addr,
               .family = route->family,
               .len = route->len,
           }};

  /*
   * The route commands expects the ID or name as part of the
   * symbolic_or_connid attribute.
   */
  if (route->name[0] != '\0') {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  route->name);
  } else {
    rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  route->face_id);
  }

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_ROUTE_REMOVE,
      .size_in = sizeof(cmd_route_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_route_delete(hc_sock_t *s, hc_route_t *route) {
  return _hcng_route_delete_internal(s, route, false);
}

static int _hcng_route_delete_async(hc_sock_t *s, hc_route_t *route) {
  return _hcng_route_delete_internal(s, route, true);
}

/* ROUTE PARSE */

static int hc_route_parse(void *in, hc_route_t *route) {
  cmd_route_list_item_t *item = (cmd_route_list_item_t *)in;

  *route = (hc_route_t){
      .name = "", /* This is not reported back */
      .face_id = item->connection_id,
      .family = item->family,
      .remote_addr = item->address,
      .len = item->len,
      .cost = item->cost,
  };

  if (hc_route_validate(route) < 0) return -1;
  return 0;
}

/* ROUTE LIST */

static int _hcng_route_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                     bool async) {
  // DEBUG("[hc_route_list] async=%s", BOOLSTR(async));
  msg_route_list_t msg = {.header = {
                              .message_type = REQUEST_LIGHT,
                              .command_id = COMMAND_TYPE_ROUTE_LIST,
                              .length = 0,
                              .seq_num = 0,
                          }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_ROUTE_LIST,
      .size_in = sizeof(cmd_route_list_item_t),
      .size_out = sizeof(hc_route_t),
      .parse = (HC_PARSE)hc_route_parse,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               pdata, async);
}

static int _hcng_route_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_route_list_internal(s, pdata, false);
}

static int _hcng_route_list_async(hc_sock_t *s) {
  return _hcng_route_list_internal(s, NULL, true);
}

/*----------------------------------------------------------------------------*
 * Face
 *
 * Face support is not directly available in hicn-light, but we can offer such
 * an interface through a combination of listeners and connections. The code
 * starts with some conversion functions between faces/listeners/connections.
 *
 * We also need to make sure that there always exist a (single) listener when
 *a connection is created, and in the hICN face case, that there is a single
 * connection attached to this listener.
 *
 *----------------------------------------------------------------------------*/

/* FACE CREATE */

static int _hcng_face_create(hc_sock_t *socket, hc_face_t *face) {
  hc_listener_t listener;
  hc_listener_t *listener_found;

  hc_connection_t connection;
  hc_connection_t *connection_found;

  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_create] Unexpected truncation of face string");
  DEBUG("[hc_face_create] face=%s", face_s);

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
      if (hc_face_to_connection(face, &connection, false) < 0) {
        ERROR("[hc_face_create] Could not convert face to connection.");
        return -1;
      }

      /* Ensure we have a corresponding local listener */
      if (hc_connection_to_local_listener(&connection, &listener) < 0) {
        ERROR("[hc_face_create] Could not convert face to local listener.");
        return -1;
      }

      if (_hcng_listener_get(socket, &listener, &listener_found) < 0) {
        ERROR("[hc_face_create] Could not retrieve listener");
        return -1;
      }

      if (!listener_found) {
        /* We need to create the listener if it does not exist */
        if (hc_listener_create(socket, &listener) < 0) {
          ERROR("[hc_face_create] Could not create listener.");
          free(listener_found);
          return -1;
        }
      } else {
        free(listener_found);
      }

      /* Create corresponding connection */
      if (_hcng_connection_create(socket, &connection) < 0) {
        ERROR("[hc_face_create] Could not create connection.");
        return -1;
      }

      /*
       * Once the connection is created, we need to list all connections
       * and compare with the current one to find the created face ID.
       */
      if (_hcng_connection_get(socket, &connection, &connection_found) < 0) {
        ERROR("[hc_face_create] Could not retrieve connection");
        return -1;
      }

      if (!connection_found) {
        ERROR("[hc_face_create] Could not find newly created connection.");
        return -1;
      }

      face->id = connection_found->id;
      free(connection_found);

      break;

    case FACE_TYPE_HICN_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      if (hc_face_to_listener(face, &listener) < 0) {
        ERROR("Could not convert face to listener.");
        return -1;
      }
      if (hc_listener_create(socket, &listener) < 0) {
        ERROR("[hc_face_create] Could not create listener.");
        return -1;
      }
      break;
    default:
      ERROR("[hc_face_create] Unknwon face type.");

      return -1;
  };

  return 0;
}

static int _hcng_face_get(hc_sock_t *socket, hc_face_t *face,
                          hc_face_t **face_found) {
  hc_listener_t listener;
  hc_listener_t *listener_found;

  hc_connection_t connection;
  hc_connection_t *connection_found;

  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_get] Unexpected truncation of face string");
  DEBUG("[hc_face_get] face=%s", face_s);

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
      if (hc_face_to_connection(face, &connection, false) < 0) return -1;
      if (_hcng_connection_get(socket, &connection, &connection_found) < 0)
        return -1;
      if (!connection_found) {
        *face_found = NULL;
        return 0;
      }
      *face_found = malloc(sizeof(hc_face_t));
      hc_connection_to_face(connection_found, *face_found);
      free(connection_found);
      break;

    case FACE_TYPE_HICN_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      if (hc_face_to_listener(face, &listener) < 0) return -1;
      if (_hcng_listener_get(socket, &listener, &listener_found) < 0) return -1;
      if (!listener_found) {
        *face_found = NULL;
        return 0;
      }
      *face_found = malloc(sizeof(hc_face_t));
      hc_listener_to_face(listener_found, *face_found);
      free(listener_found);
      break;

    default:
      return -1;
  }

  return 0;
}

/* FACE DELETE */

static int _hcng_face_delete(hc_sock_t *socket, hc_face_t *face,
                             uint8_t delete_listener) {
  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_delete] Unexpected truncation of face string");
  DEBUG("[hc_face_delete] face=%s", face_s);

  hc_connection_t connection;
  if (hc_face_to_connection(face, &connection, false) < 0) {
    ERROR("[hc_face_delete] Could not convert face to connection.");
    return -1;
  }

  if (_hcng_connection_delete(socket, &connection) < 0) {
    ERROR("[hc_face_delete] Error removing connection");
    return -1;
  }

  if (!delete_listener) {
    return 0;
  }

  /* If this is the last connection attached to the listener, remove it */

  hc_data_t *connections;
  hc_listener_t listener = {{0}};

  /*
   * Ensure we have a corresponding local listener
   * NOTE: hc_face_to_listener is not appropriate
   */
  if (hc_connection_to_local_listener(&connection, &listener) < 0) {
    ERROR("[hc_face_create] Could not convert face to local listener.");
    return -1;
  }
#if 1
  /*
   * The name is generated to prepare listener creation, we need it to be
   * empty for deletion. The id should not need to be reset though.
   */
  listener.id = 0;
  memset(listener.name, 0, sizeof(listener.name));
#endif
  if (_hcng_connection_list(socket, &connections) < 0) {
    ERROR("[hc_face_delete] Error getting the list of listeners");
    return -1;
  }

  bool delete = true;
  foreach_connection(c, connections) {
    if ((ip_address_cmp(&c->local_addr, &listener.local_addr, c->family) ==
         0) &&
        (c->local_port == listener.local_port) &&
        (strcmp(c->interface_name, listener.interface_name) == 0)) {
      delete = false;
    }
  }

  if (delete) {
    if (_hcng_listener_delete(socket, &listener) < 0) {
      ERROR("[hc_face_delete] Error removing listener");
      return -1;
    }
  }

  hc_data_free(connections);

  return 0;
}

/* FACE LIST */

static int _hcng_face_list(hc_sock_t *socket, hc_data_t **pdata) {
  hc_data_t *connection_data;
  hc_face_t face;

  DEBUG("[hc_face_list]");

  if (_hcng_connection_list(socket, &connection_data) < 0) {
    ERROR("[hc_face_list] Could not list connections.");
    return -1;
  }

  hc_data_t *face_data =
      hc_data_create(sizeof(hc_connection_t), sizeof(hc_face_t), NULL);
  foreach_connection(c, connection_data) {
    if (hc_connection_to_face(c, &face) < 0) {
      ERROR("[hc_face_list] Could not convert connection to face.");
      goto ERR;
    }
    hc_data_push(face_data, &face);
  }

  *pdata = face_data;
  hc_data_free(connection_data);
  DEBUG("[hc_face_list] done");
  return 0;

ERR:
  hc_data_free(connection_data);
  DEBUG("[hc_face_list] error");
  return -1;
}

static int hc_connection_parse_to_face(void *in, hc_face_t *face) {
  hc_connection_t connection;

  if (hc_connection_parse(in, &connection) < 0) {
    ERROR("[hc_connection_parse_to_face] Could not parse connection");
    return -1;
  }

  if (hc_connection_to_face(&connection, face) < 0) {
    ERROR(
        "[hc_connection_parse_to_face] Could not convert connection to "
        "face.");
    return -1;
  }

  return 0;
}

static int _hcng_face_list_async(hc_sock_t *socket) {
  struct {
    cmd_header_t hdr;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_LIST,
              .length = 0,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_CONNECTION_LIST,
      .size_in = sizeof(cmd_connection_list_item_t),
      .size_out = sizeof(hc_face_t),
      .parse = (HC_PARSE)hc_connection_parse_to_face,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, true);
}

static int _hcng_face_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                      face_state_t admin_state) {
  return hc_connection_set_admin_state(s, conn_id_or_name, admin_state);
}

#ifdef WITH_POLICY
static int _hcng_face_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                                   uint32_t priority) {
  return hc_connection_set_priority(s, conn_id_or_name, priority);
}

static int _hcng_face_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                               policy_tags_t tags) {
  return hc_connection_set_tags(s, conn_id_or_name, tags);
}
#endif  // WITH_POLICY

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

static int _hcng_punting_create_internal(hc_sock_t *socket,
                                         hc_punting_t *punting, bool async) {
  int rc;

  if (hc_punting_validate(punting) < 0) return -1;

  struct {
    cmd_header_t hdr;
    cmd_punting_add_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   .command_id = COMMAND_TYPE_PUNTING_ADD,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = punting->prefix,
               .family = punting->family,
               .len = punting->prefix_len,
           }};
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                punting->face_id);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN("[_hc_punting_create] Unexpected truncation of symbolic name string");

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_PUNTING_ADD,
      .size_in = sizeof(cmd_punting_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_punting_create(hc_sock_t *s, hc_punting_t *punting) {
  return _hcng_punting_create_internal(s, punting, false);
}

static int _hcng_punting_create_async(hc_sock_t *s, hc_punting_t *punting) {
  return _hcng_punting_create_internal(s, punting, true);
}

static int _hcng_punting_get(hc_sock_t *s, hc_punting_t *punting,
                             hc_punting_t **punting_found) {
  ERROR("hc_punting_get not (yet) implemented.");
  return -1;
}

static int _hcng_punting_delete(hc_sock_t *s, hc_punting_t *punting) {
  ERROR("hc_punting_delete not (yet) implemented.");
  return -1;
}

#if 0
static int hc_punting_parse(void * in, hc_punting_t * punting)
{
    ERROR("hc_punting_parse not (yet) implemented.");
    return -1;
}
#endif

static int _hcng_punting_list(hc_sock_t *s, hc_data_t **pdata) {
  ERROR("hc_punting_list not (yet) implemented.");
  return -1;
}

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

/* CACHE SET STORE */

static int _hcng_cache_set_store_internal(hc_sock_t *socket, hc_cache_t *cache,
                                          bool async) {
  msg_cache_set_store_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CACHE_SET_STORE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = cache->store,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_STORE,
      .cmd_id = COMMAND_TYPE_CACHE_SET_STORE,
      .size_in = sizeof(cmd_cache_set_store_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_cache_set_store(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_store_internal(s, cache, false);
}

static int _hcng_cache_set_store_async(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_store_internal(s, cache, true);
}

/* CACHE SET SERVE */

static int _hcng_cache_set_serve_internal(hc_sock_t *socket, hc_cache_t *cache,
                                          bool async) {
  msg_cache_set_serve_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CACHE_SET_SERVE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = cache->serve,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SERVE,
      .cmd_id = COMMAND_TYPE_CACHE_SET_SERVE,
      .size_in = sizeof(cmd_cache_set_serve_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_cache_set_serve(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_serve_internal(s, cache, false);
}

static int _hcng_cache_set_serve_async(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_set_serve_internal(s, cache, true);
}

/* CACHE CLEAR */

static int _hcng_cache_clear_internal(hc_sock_t *socket, hc_cache_t *cache,
                                      bool async) {
  msg_cache_clear_t msg = {.header = {
                               .message_type = REQUEST_LIGHT,
                               .command_id = COMMAND_TYPE_CACHE_CLEAR,
                               .length = 1,
                               .seq_num = 0,
                           }};

  hc_command_params_t params = {
      .cmd = ACTION_CLEAR,
      .cmd_id = COMMAND_TYPE_CACHE_CLEAR,
      .size_in = sizeof(cmd_cache_clear_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_cache_clear(hc_sock_t *s, hc_cache_t *cache) {
  return _hcng_cache_clear_internal(s, cache, false);
}

/* CACHE PARSE */

static int hc_cache_parse(void *in, hc_cache_info_t *cache_info) {
  cmd_cache_list_reply_t *item = (cmd_cache_list_reply_t *)in;
  *cache_info = (hc_cache_info_t){.store = item->store_in_cs,
                                  .serve = item->serve_from_cs,
                                  .cs_size = item->cs_size,
                                  .num_stale_entries = item->num_stale_entries};

  return 0;
}

/* CACHE LIST */

static hc_result_t *_hcng_cache_list_serialize(hc_sock_t *socket,
                                               hc_data_t **pdata, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  DEBUG("[hc_cache_list] async=%s", BOOLSTR(async));

  msg_cache_list_t msg = {.header = {
                              .message_type = REQUEST_LIGHT,
                              .command_id = COMMAND_TYPE_CACHE_LIST,
                              .length = 0,
                              .seq_num = 0,
                          }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_CACHE_LIST,
      .size_in = sizeof(cmd_cache_list_reply_t),
      .size_out = sizeof(hc_cache_info_t),
      .parse = (HC_PARSE)hc_cache_parse,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.cache_list = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static int _hcng_cache_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                     bool async) {
  hc_result_t *result = _hcng_cache_list_serialize(socket, pdata, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, pdata,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

static int _hcng_cache_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_cache_list_internal(s, pdata, false);
}

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
static hc_result_t *_strategy_set_serialize(hc_sock_t *socket,
                                            hc_strategy_t *strategy) {
  hc_result_t *res = malloc(sizeof(*res));

  char strategy_s[MAXSZ_HC_STRATEGY];
  int rc = strcpy_s(strategy->name, MAXSZ_STRATEGY_NAME,
                    strategy_str(strategy->type));
  if (rc != EOK) goto ERR;
  rc = hc_strategy_snprintf(strategy_s, MAXSZ_HC_STRATEGY, strategy);
  if (rc >= MAXSZ_HC_STRATEGY)
    WARN("[_hcng_strategy_create] Unexpected truncation of strategy string");
  DEBUG("[_hcng_strategy_create] strategy=%s", strategy_s);

  if (!IS_VALID_FAMILY(strategy->family) ||
      !IS_VALID_STRATEGY_TYPE(strategy->type)) {
    goto ERR;
  }

  msg_strategy_set_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_STRATEGY_SET,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .address = strategy->address,
                                .family = strategy->family,
                                .len = strategy->len,
                                .type = strategy->type,
                            }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_STRATEGY_SET,
      .size_in = sizeof(cmd_strategy_set_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.strategy_set = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;

ERR:
  res->success = false;
  return res;
}

static hc_result_t *_strategy_add_local_prefix_serialize(
    hc_sock_t *socket, hc_strategy_t *strategy) {
  hc_result_t *res = malloc(sizeof(*res));

  char strategy_s[MAXSZ_HC_STRATEGY];
  int rc = strcpy_s(strategy->name, MAXSZ_STRATEGY_NAME,
                    strategy_str(strategy->type));
  if (rc != EOK) goto ERR;
  rc = hc_strategy_snprintf(strategy_s, MAXSZ_HC_STRATEGY, strategy);
  if (rc >= MAXSZ_HC_STRATEGY)
    WARN("[_hcng_strategy_create] Unexpected truncation of strategy string");
  DEBUG("[_hcng_strategy_create] strategy=%s", strategy_s);

  if (!IS_VALID_FAMILY(strategy->family) ||
      !IS_VALID_STRATEGY_TYPE(strategy->type) ||
      !IS_VALID_FAMILY(strategy->local_family)) {
    goto ERR;
  }

  msg_strategy_add_local_prefix_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_STRATEGY_ADD_LOCAL_PREFIX,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .type = strategy->type,
          .address = strategy->address,
          .family = strategy->family,
          .len = strategy->len,
          .local_address = strategy->local_address,
          .local_family = strategy->local_family,
          .local_len = strategy->local_len,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_STRATEGY_ADD_LOCAL_PREFIX,
      .size_in = sizeof(cmd_strategy_add_local_prefix_t),
      .size_out = 0,
      .parse = NULL,
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.strategy_add_local_prefix = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;

ERR:
  res->success = false;
  return res;
}

static hc_result_t *_hcng_strategy_set_conf(hc_sock_t *s,
                                            hc_strategy_t *strategy) {
  return _strategy_set_serialize(s, strategy);
}

static int _hcng_strategy_set(hc_sock_t *socket, hc_strategy_t *strategy) {
  hc_result_t *result = _strategy_set_serialize(socket, strategy);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

static hc_result_t *_hcng_strategy_add_local_prefix_conf(
    hc_sock_t *s, hc_strategy_t *strategy) {
  return _strategy_add_local_prefix_serialize(s, strategy);
}

static int _hcng_strategy_add_local_prefix(hc_sock_t *socket,
                                           hc_strategy_t *strategy) {
  hc_result_t *result = _strategy_add_local_prefix_serialize(socket, strategy);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

/* How to retrieve that from the forwarder ? */
static const char *strategies[] = {
    "random",
    "load_balancer",
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

static int _hcng_strategy_list(hc_sock_t *s, hc_data_t **data) {
  int rc;

  *data = hc_data_create(0, sizeof(hc_strategy_t), NULL);

  for (unsigned i = 0; i < ARRAY_SIZE(strategies); i++) {
    hc_strategy_t *strategy = (hc_strategy_t *)hc_data_get_next(*data);
    if (!strategy) return -1;
    rc = snprintf(strategy->name, MAXSZ_STRATEGY_NAME, "%s", strategies[i]);
    if (rc >= MAXSZ_STRATEGY_NAME)
      WARN("[hc_strategy_list] Unexpected truncation of strategy name string");
    (*data)->size++;
  }

  return 0;
}

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
static int _hcng_wldr_set(hc_sock_t *s /* XXX */) { return 0; }

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

static int _hcng_mapme_set(hc_sock_t *socket, int enabled) {
  msg_mapme_enable_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_MAPME_ENABLE,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .activate = enabled,
                            }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_ENABLE,
      .size_in = sizeof(cmd_mapme_enable_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
}

static int _hcng_mapme_set_discovery(hc_sock_t *socket, int enabled) {
  msg_mapme_enable_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = enabled,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
      .size_in = sizeof(cmd_mapme_set_discovery_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
}

static int _hcng_mapme_set_timescale(hc_sock_t *socket, uint32_t timescale) {
  msg_mapme_set_timescale_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .timePeriod = timescale,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
      .size_in = sizeof(cmd_mapme_set_timescale_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
}

static int _hcng_mapme_set_retx(hc_sock_t *socket, uint32_t timescale) {
  msg_mapme_set_retx_t msg = {.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_MAPME_SET_RETX,
                                      .length = 1,
                                      .seq_num = 0,
                                  },
                              .payload = {
                                  .timePeriod = timescale,
                              }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_RETX,
      .size_in = sizeof(msg_mapme_set_retx_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
}

static int _hcng_mapme_send_update(hc_sock_t *socket, hc_mapme_t *mapme) {
  if (!IS_VALID_FAMILY(mapme->family)) return -1;

  msg_mapme_send_update_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
              .length = 1,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_UPDATE,
      .cmd_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
      .size_in = sizeof(msg_mapme_send_update_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
}

/*----------------------------------------------------------------------------*
 * Policy
 *----------------------------------------------------------------------------*/

#ifdef WITH_POLICY

/* POLICY CREATE */

static int _hcng_policy_create_internal(hc_sock_t *socket, hc_policy_t *policy,
                                        bool async) {
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  struct {
    cmd_header_t hdr;
    cmd_policy_add_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   COMMAND_TYPE_POLICY_ADD,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = policy->remote_addr,
               .family = policy->family,
               .len = policy->len,
               .policy = policy->policy,
           }};

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_POLICY_ADD,
      .size_in = sizeof(cmd_policy_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_policy_create(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_create_internal(s, policy, false);
}

static int _hcng_policy_create_async(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_create_internal(s, policy, true);
}

/* POLICY DELETE */

static int _hcng_policy_delete_internal(hc_sock_t *socket, hc_policy_t *policy,
                                        bool async) {
  if (!IS_VALID_FAMILY(policy->family)) return -1;

  struct {
    cmd_header_t hdr;
    cmd_policy_remove_t payload;
  } msg = {.hdr =
               {
                   .message_type = REQUEST_LIGHT,
                   .command_id = COMMAND_TYPE_POLICY_REMOVE,
                   .length = 1,
                   .seq_num = 0,
               },
           .payload = {
               .address = policy->remote_addr,
               .family = policy->family,
               .len = policy->len,
           }};

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_POLICY_REMOVE,
      .size_in = sizeof(cmd_policy_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hcng_policy_delete(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_delete_internal(s, policy, false);
}

static int _hcng_policy_delete_async(hc_sock_t *s, hc_policy_t *policy) {
  return _hcng_policy_delete_internal(s, policy, true);
}

/* POLICY PARSE */

static int hc_policy_parse(void *in, hc_policy_t *policy) {
  cmd_policy_list_item_t *item = (cmd_policy_list_item_t *)in;

  if (!IS_VALID_ADDRESS(&item->address, item->family)) {
    ERROR("[hc_policy_parse] Invalid address");
    return -1;
  }
  if (!IS_VALID_FAMILY(item->family)) {
    ERROR("[hc_policy_parse] Invalid family");
    return -1;
  }
  if (!IS_VALID_PREFIX_LEN(item->len)) {
    ERROR("[hc_policy_parse] Invalid len");
    return -1;
  }
  if (!IS_VALID_POLICY(item->policy)) {
    ERROR("[hc_policy_parse] Invalid policy");
    return -1;
  }

  *policy = (hc_policy_t){
      .family = item->family,
      .remote_addr = item->address,
      .len = item->len,
      .policy = item->policy,
  };
  return 0;
}

/* POLICY LIST */

static int _hcng_policy_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                      bool async) {
  struct {
    cmd_header_t hdr;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_POLICY_LIST,
              .length = 0,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_POLICY_LIST,
      .size_in = sizeof(cmd_policy_list_item_t),
      .size_out = sizeof(hc_policy_t),
      .parse = (HC_PARSE)hc_policy_parse,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               pdata, async);
}

static int _hcng_policy_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_policy_list_internal(s, pdata, false);
}

static int _hcng_policy_list_async(hc_sock_t *s, hc_data_t **pdata) {
  return _hcng_policy_list_internal(s, pdata, true);
}

#endif /* WITH_POLICY */

/*----------------------------------------------------------------------------*
 * Subscriptioins
 *----------------------------------------------------------------------------*/

/* SUBSCRIPTION CREATE */

static hc_result_t *_subscription_create_serialize(
    hc_sock_t *s, hc_subscription_t *subscription) {
  msg_subscription_add_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_SUBSCRIPTION_ADD,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {.topics = subscription->topics}};

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = COMMAND_TYPE_SUBSCRIPTION_ADD,
      .size_in = sizeof(cmd_subscription_add_t),
      .size_out = 0,
      .parse = NULL,
  };

  hc_result_t *res = malloc(sizeof(*res));
  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.subscription_add = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_subscription_create_conf(
    hc_sock_t *s, hc_subscription_t *subscription) {
  return _subscription_create_serialize(s, subscription);
}

static int _hcng_subscription_create(hc_sock_t *socket,
                                     hc_subscription_t *subscriiption) {
  hc_result_t *result = _subscription_create_serialize(socket, subscriiption);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

/* SUBSCRIPTION DELETE */

static hc_result_t *_subscription_delete_serialize(
    hc_sock_t *s, hc_subscription_t *subscription) {
  msg_subscription_remove_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_SUBSCRIPTION_REMOVE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {.topics = subscription->topics}};

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = COMMAND_TYPE_SUBSCRIPTION_REMOVE,
      .size_in = sizeof(cmd_subscription_remove_t),
      .size_out = 0,
      .parse = NULL,
  };

  hc_result_t *res = malloc(sizeof(*res));
  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.subscription_remove = msg.payload,
          },
      .params = params,
      .async = false,
      .success = true,
  };
  return res;
}

static hc_result_t *_hcng_subscription_delete_conf(
    hc_sock_t *s, hc_subscription_t *subscription) {
  return _subscription_delete_serialize(s, subscription);
}

static int _hcng_subscription_delete(hc_sock_t *socket,
                                     hc_subscription_t *subscriiption) {
  hc_result_t *result = _subscription_delete_serialize(socket, subscriiption);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, NULL,
                                result->async);
  }

  hc_result_free(result);
  return ret;
}

/*----------------------------------------------------------------------------*
 * Statistics
 *----------------------------------------------------------------------------*/

/* STATS GET */

static hc_result_t *_hcng_stats_get_serialize(hc_sock_t *socket,
                                              hc_data_t **pdata, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  DEBUG("[hc_stats_get] async=%s", BOOLSTR(async));

  msg_stats_get_t msg = {.header = {
                             .message_type = REQUEST_LIGHT,
                             .command_id = COMMAND_TYPE_STATS_GET,
                             .length = 0,
                             .seq_num = 0,
                         }};

  hc_command_params_t params = {
      .cmd = ACTION_GET,
      .cmd_id = COMMAND_TYPE_STATS_GET,
      .size_in = sizeof(hicn_light_stats_t),
      .size_out = sizeof(hicn_light_stats_t),
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.stats_get = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static int _hcng_stats_get_internal(hc_sock_t *socket, hc_data_t **pdata,
                                    bool async) {
  hc_result_t *result = _hcng_stats_get_serialize(socket, pdata, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, pdata,
                                result->async);
  }

  hc_result_free(result);
  DEBUG("[_hcng_stats_get] done or error");
  return ret;
}

static int _hcng_stats_get(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[_hcng_stats_get]");
  return _hcng_stats_get_internal(s, pdata, false);
}

/* STATS LIST */

static hc_result_t *_hcng_stats_list_serialize(hc_sock_t *socket,
                                               hc_data_t **pdata, bool async) {
  hc_result_t *res = malloc(sizeof(*res));
  DEBUG("[hc_stats_list] async=%s", BOOLSTR(async));

  msg_stats_list_t msg = {.header = {
                              .message_type = REQUEST_LIGHT,
                              .command_id = COMMAND_TYPE_STATS_LIST,
                              .length = 0,
                              .seq_num = 0,
                          }};

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = COMMAND_TYPE_STATS_LIST,
      .size_in = sizeof(cmd_stats_list_item_t),
      .size_out = sizeof(cmd_stats_list_item_t),
  };

  *res = (hc_result_t){
      .msg =
          (hc_msg_t){
              .hdr = msg.header,
              .payload.stats_list = msg.payload,
          },
      .params = params,
      .async = async,
      .success = true,
  };
  return res;
}

static int _hcng_stats_list_internal(hc_sock_t *socket, hc_data_t **pdata,
                                     bool async) {
  hc_result_t *result = _hcng_stats_list_serialize(socket, pdata, async);

  int ret = INPUT_ERROR;
  if (result->success) {
    ret = _hcng_execute_command(socket, (hc_msg_t *)&result->msg,
                                sizeof(result->msg), &result->params, pdata,
                                result->async);
  }

  hc_result_free(result);
  DEBUG("[_hcng_stats_list] done or error");
  return ret;
}

static int _hcng_stats_list(hc_sock_t *s, hc_data_t **pdata) {
  DEBUG("[_hcng_stats_list]");
  return _hcng_stats_list_internal(s, pdata, false);
}

/* RESULT */
hc_msg_t *_hcng_result_get_msg(hc_result_t *result) { return &result->msg; }
int _hcng_result_get_cmd_id(hc_result_t *result) {
  return result->params.cmd_id;
}
bool _hcng_result_get_success(hc_result_t *result) { return result->success; }

static hc_sock_t hc_sock_light_ng_interface = (hc_sock_t){
    .hc_sock_get_next_seq = _hcng_sock_light_get_next_seq,
    .hc_sock_set_nonblocking = _hcng_sock_light_set_nonblocking,
    .hc_sock_get_fd = _hcng_sock_light_get_fd,
    .hc_sock_connect = _hcng_sock_light_connect,
    .hc_sock_get_available = _hcng_sock_light_get_available,
    .hc_sock_send = _hcng_sock_light_send,
    .hc_sock_recv = _hcng_sock_light_recv,
    .hc_sock_process = _hcng_sock_light_process,
    .hc_sock_callback = _hcng_sock_light_callback,
    .hc_sock_reset = _hcng_sock_light_reset,
    .hc_sock_free = _hcng_sock_light_free,
    .hc_sock_increment_woff = _hcng_sock_increment_woff,
    .hc_sock_prepare_send = _hcng_sock_prepare_send,
    .hc_sock_set_recv_timeout_ms = _hcng_sock_set_recv_timeout_ms,
    .hc_listener_create = _hcng_listener_create,
    .hc_listener_create_async = _hcng_listener_create_async,
    .hc_listener_get = _hcng_listener_get,
    .hc_listener_delete = _hcng_listener_delete,
    .hc_listener_delete_async = _hcng_listener_delete_async,
    .hc_listener_list = _hcng_listener_list,
    .hc_listener_list_async = _hcng_listener_list_async,
    .hc_connection_create = _hcng_connection_create,
    .hc_connection_create_async = _hcng_connection_create_async,
    .hc_connection_get = _hcng_connection_get,
    .hc_connection_update_by_id = _hcng_connection_update_by_id,
    .hc_connection_update = _hcng_connection_update,
    .hc_connection_delete = _hcng_connection_delete,
    .hc_connection_delete_async = _hcng_connection_delete_async,
    .hc_connection_list = _hcng_connection_list,
    .hc_connection_list_async = _hcng_connection_list_async,
    .hc_connection_set_admin_state = _hcng_connection_set_admin_state,
    .hc_connection_set_admin_state_async =
        _hcng_connection_set_admin_state_async,

#ifdef WITH_POLICY
    .hc_connection_set_priority = _hcng_connection_set_priority,
    .hc_connection_set_priority_async = _hcng_connection_set_priority_async,
    .hc_connection_set_tags = _hcng_connection_set_tags,
    .hc_connection_set_tags_async = _hcng_connection_set_tags_async,
#endif  // WITH_POLICY

    .hc_face_create = _hcng_face_create,
    .hc_face_get = _hcng_face_get,
    .hc_face_delete = _hcng_face_delete,
    .hc_face_list = _hcng_face_list,
    .hc_face_list_async = _hcng_face_list_async,
    .hc_face_set_admin_state = _hcng_face_set_admin_state,

#ifdef WITH_POLICY
    .hc_face_set_priority = _hcng_face_set_priority,
    .hc_face_set_tags = _hcng_face_set_tags,
#endif  // WITH_POLICY
    .hc_subscription_create = _hcng_subscription_create,
    .hc_subscription_delete = _hcng_subscription_delete,

    .hc_stats_get = _hcng_stats_get,
    .hc_stats_list = _hcng_stats_list,

    .hc_route_create = _hcng_route_create,
    .hc_route_create_async = _hcng_route_create_async,
    .hc_route_delete = _hcng_route_delete,
    .hc_route_delete_async = _hcng_route_delete_async,
    .hc_route_list = _hcng_route_list,
    .hc_route_list_async = _hcng_route_list_async,

    .hc_punting_create = _hcng_punting_create,
    .hc_punting_create_async = _hcng_punting_create_async,
    .hc_punting_get = _hcng_punting_get,
    .hc_punting_delete = _hcng_punting_delete,
    .hc_punting_list = _hcng_punting_list,

    .hc_cache_set_store = _hcng_cache_set_store,
    .hc_cache_set_store_async = _hcng_cache_set_store_async,
    .hc_cache_set_serve = _hcng_cache_set_serve,
    .hc_cache_set_serve_async = _hcng_cache_set_serve_async,
    .hc_cache_clear = _hcng_cache_clear,
    .hc_cache_list = _hcng_cache_list,

    .hc_strategy_list = _hcng_strategy_list,
    .hc_strategy_set = _hcng_strategy_set,
    .hc_strategy_add_local_prefix = _hcng_strategy_add_local_prefix,
    .hc_wldr_set = _hcng_wldr_set,

    .hc_mapme_set = _hcng_mapme_set,
    .hc_mapme_set_discovery = _hcng_mapme_set_discovery,
    .hc_mapme_set_timescale = _hcng_mapme_set_timescale,
    .hc_mapme_set_retx = _hcng_mapme_set_retx,
    .hc_mapme_send_update = _hcng_mapme_send_update,

#ifdef WITH_POLICY
    .hc_policy_create = _hcng_policy_create,
    .hc_policy_create_async = _hcng_policy_create_async,
    .hc_policy_delete = _hcng_policy_delete,
    .hc_policy_delete_async = _hcng_policy_delete_async,
    .hc_policy_list = _hcng_policy_list,
    .hc_policy_list_async = _hcng_policy_list_async,
#endif  // WITH_POLICY

    .hc_listener_create_conf = _hcng_listener_create_conf,
    .hc_listener_list_conf = _hcng_listener_list_conf,
    .hc_connection_create_conf = _hcng_connection_create_conf,
    .hc_connection_delete_conf = _hcng_connection_delete_conf,
    .hc_route_create_conf = _hcng_route_create_conf,
    .hc_strategy_set_conf = _hcng_strategy_set_conf,
    .hc_strategy_add_local_prefix_conf = _hcng_strategy_add_local_prefix_conf,
    .hc_subscription_create_conf = _hcng_subscription_create_conf,
    .hc_subscription_delete_conf = _hcng_subscription_delete_conf,

    .hc_result_get_msg = _hcng_result_get_msg,
    .hc_result_get_cmd_id = _hcng_result_get_cmd_id,
    .hc_result_get_success = _hcng_result_get_success,
};

// Public contructors

hc_sock_t *_hc_sock_create_url(const char *url) {
  hc_sock_light_t *s = malloc(sizeof(hc_sock_light_t));
  if (!s) goto ERR_MALLOC;

  s->vft = hc_sock_light_ng_interface;
  s->url = url ? strdup(url) : NULL;

  s->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (s->fd < 0) goto ERR_SOCKET;

  if (_hcng_sock_set_recv_timeout_ms((hc_sock_t *)s,
                                     DEFAULT_SOCK_RECV_TIMEOUT_MS) < 0)
    goto ERR_SOCKET;

  if (_hcng_sock_light_reset((hc_sock_t *)s) < 0) goto ERR_RESET;

  s->seq = 0;
  s->cur_request = NULL;

  s->map = kh_init_sock_map();
  if (!s->map) goto ERR_MAP;

  return (hc_sock_t *)(s);

  // hc_sock_light_map_free(s->map);
ERR_MAP:
ERR_RESET:
  if (s->url) free(s->url);
  close(s->fd);
ERR_SOCKET:
  free(s);
ERR_MALLOC:
  return NULL;
}
