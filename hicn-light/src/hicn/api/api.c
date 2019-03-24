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
 * \file api.c
 * \brief Implementation of hICN control library API
 */

#include <assert.h>      // assert
#include <fcntl.h>       // fcntl
#include <math.h>        // log2
#include <string.h>      // memmove, strncpy, strcasecmp
#include <sys/socket.h>  // socket
#include <unistd.h>      // close, fcntl

#include <stdio.h>  // XXX debug

#include <hicn/api/api.h>
#include <hicn/api/commands.h>
#include <hicn/api/util/ip_address.h>
#include <hicn/api/util/token.h>

#define PORT 9695

#define LIBHICNCTRL_SUCCESS 1
#define LIBHICNCTRL_FAILURE -1
#define LIBHICNCTRL_IS_ERROR(x) (x < 0)

/*
 * list was working with all seq set to 0, but it seems hicnLightControl uses
 * 1, and replies with the same seqno
 */
#define HICN_CTRL_SEND_SEQ_INIT 1
#define HICN_CTRL_RECV_SEQ_INIT 1

#define MAX(x, y) ((x > y) ? x : y)

#if 0
static inline u32 log2(const u32 x) {
  u32 y;
  asm ( "\tbsr %1, %0\n"
      : "=r"(y)
      : "r" (x)
  );
  return y;
}
#endif

/**
 * \brief Defines the default size for the allocated data arrays holding the
 * results of API calls.
 *
 * This size should not be too small to avoid wasting memoyy, but also not too
 * big to avoid unnecessary realloc's. Later on this size is doubled at each
 * reallocation.
 */
#define DEFAULT_SIZE_LOG 3

/**
 * In practise, we want to preserve enough room to store a full packet of
 * average expected size (say a header + N payload elements).
 */
#define AVG_ELEMENTS (1 << DEFAULT_SIZE_LOG)
#define AVG_BUFLEN \
  sizeof(hc_msg_header_t) + AVG_ELEMENTS * sizeof(hc_msg_payload_t)

/*
 * We should at least have buffer space allowing to store one processable unit
 * of data, either the header of the maximum possible payload
 */
#define MIN_BUFLEN MAX(sizeof(hc_msg_header_t), sizeof(hc_msg_payload_t))

static const struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

/* /!\ Please update constants in header file upon changes */
const char *connection_type_str[] = {
#define _(x) [CONNECTION_TYPE_##x] = STRINGIZE(x),
    foreach_connection_type
#undef _
};

#define IS_VALID_CONNECTION_TYPE(x) IS_VALID_ENUM_TYPE(CONNECTION_TYPE, x)

hc_connection_type_t connection_type_from_str(const char *str) {
  if (strcasecmp(str, "TCP") == 0)
    return CONNECTION_TYPE_TCP;
  else if (strcasecmp(str, "UDP") == 0)
    return CONNECTION_TYPE_UDP;
  else if (strcasecmp(str, "HICN") == 0)
    return CONNECTION_TYPE_HICN;
  else
    return CONNECTION_TYPE_UNDEFINED;
}

/*
 * Mandatory conversions to shield lib user from heterogeneity
 */

#define IS_VALID_LIST_CONNECTIONS_TYPE(x) ((x >= CONN_GRE) && (x <= CONN_HICN))

static const hc_connection_type_t map_from_list_connections_type[] = {
    [CONN_GRE] = CONNECTION_TYPE_UNDEFINED,
    [CONN_TCP] = CONNECTION_TYPE_TCP,
    [CONN_UDP] = CONNECTION_TYPE_UDP,
    [CONN_MULTICAST] = CONNECTION_TYPE_UNDEFINED,
    [CONN_L2] = CONNECTION_TYPE_UNDEFINED,
    [CONN_HICN] = CONNECTION_TYPE_HICN,
};

typedef enum {
  ENCAP_TCP,
  ENCAP_UDP,
  ENCAP_ETHER,
  ENCAP_LOCAL,
  ENCAP_HICN
} EncapType;

#define IS_VALID_LIST_LISTENERS_TYPE(x) ((x >= ENCAP_TCP) && (x <= ENCAP_HICN))

static const hc_connection_type_t map_from_encap_type[] = {
    [ENCAP_TCP] = CONNECTION_TYPE_TCP,
    [ENCAP_UDP] = CONNECTION_TYPE_UDP,
    [ENCAP_ETHER] = CONNECTION_TYPE_UNDEFINED,
    [ENCAP_LOCAL] = CONNECTION_TYPE_UNDEFINED,
    [ENCAP_HICN] = CONNECTION_TYPE_HICN,
};

static const connection_type map_to_connection_type[] = {
    [CONNECTION_TYPE_TCP] = TCP_CONN,
    [CONNECTION_TYPE_UDP] = UDP_CONN,
    [CONNECTION_TYPE_HICN] = HICN_CONN,
};

static const listener_mode map_to_listener_mode[] = {
    [CONNECTION_TYPE_TCP] = IP_MODE,
    [CONNECTION_TYPE_UDP] = IP_MODE,
    [CONNECTION_TYPE_HICN] = HICN_MODE,
};

#define IS_VALID_LIST_CONNECTIONS_STATE(x) \
  ((x >= IFACE_UP) && (x <= IFACE_UNKNOWN))

/* /!\ Please update constants in header file upon changes */
const char *connection_state_str[] = {
#define _(x) [CONNECTION_STATE_##x] = STRINGIZE(x),
    foreach_connection_state
#undef _
};

/*
#define IS_VALID_CONNECTION_STATE(x) IS_VALID_ENUM_TYPE(CONNECTION_STATE, x)

static const connection_state map_to_connection_state[] = {
    [CONNECTION_STATE_UP]       = IFACE_UP,
    [CONNECTION_STATE_DOWN]     = IFACE_DOWN,
};

*/

static const hc_connection_state_t map_from_list_connections_state[] = {
    [IFACE_UP] = CONNECTION_STATE_UP,
    [IFACE_DOWN] = CONNECTION_STATE_DOWN,
    [IFACE_UNKNOWN] = CONNECTION_STATE_UNDEFINED,
};

#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

static const int map_from_addr_type[] = {
    [ADDR_INET] = AF_INET,    [ADDR_INET6] = AF_INET6, [ADDR_LINK] = AF_UNSPEC,
    [ADDR_IFACE] = AF_UNSPEC, [ADDR_UNIX] = AF_UNSPEC,
};

static const address_type map_to_addr_type[] = {
    [AF_INET] = ADDR_INET,
    [AF_INET6] = ADDR_INET6,
};

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_hc_command \
  _(add_listener)          \
  _(add_connection)        \
  _(list_connections)      \
  _(add_route)             \
  _(list_routes)           \
  _(remove_connection)     \
  _(remove_route)          \
  _(cache_store)           \
  _(cache_serve)           \
  /*_(cache_clear) */      \
  _(set_strategy)          \
  _(set_wldr)              \
  _(add_punting)           \
  _(list_listeners)        \
  _(mapme_activator)       \
  _(mapme_timing)

typedef header_control_message hc_msg_header_t;

typedef union {
#define _(x) x##_command x;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

typedef struct hc_msg_s {
  hc_msg_header_t hdr;
  hc_msg_payload_t payload;
} hc_msg_t;

/******************************************************************************
 * Control Data
 ******************************************************************************/

hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size) {
  hc_data_t *data = malloc(sizeof(hc_data_t));
  if (!data) goto ERR_MALLOC;

  /* FIXME Could be NULL thanks to realloc provided size is 0 */
  data->max_size_log = DEFAULT_SIZE_LOG;
  data->in_element_size = in_element_size;
  data->out_element_size = out_element_size;
  data->size = 0;
  data->complete = 0;
  data->command_id = 0;  // TODO this could also be a busy mark in the socket
  /* No callback needed in blocking code for instance */
  data->complete_cb = NULL;

  data->buffer = malloc((1 << data->max_size_log) * data->out_element_size);
  if (!data->buffer) goto ERR_BUFFER;

  return data;

ERR_BUFFER:
  free(data);
ERR_MALLOC:
  return NULL;
}

void hc_data_free(hc_data_t *data) {
  if (data->buffer) free(data->buffer);
  free(data);
}

int hc_data_ensure_available(hc_data_t *data, size_t count) {
  size_t new_size_log =
      (data->size + count - 1 > 0) ? log2(data->size + count - 1) + 1 : 0;
  if (new_size_log > data->max_size_log) {
    data->max_size_log = new_size_log;
    data->buffer =
        realloc(data->buffer, (1 << new_size_log) * data->out_element_size);
    if (!data->buffer) return LIBHICNCTRL_FAILURE;
  }
  return LIBHICNCTRL_SUCCESS;
}

int hc_data_push_many(hc_data_t *data, const void *elements, size_t count) {
  if (hc_data_ensure_available(data, count) < 0) return LIBHICNCTRL_FAILURE;

  memcpy(data->buffer + data->size * data->out_element_size, elements,
         count * data->out_element_size);
  data->size += count;
  return LIBHICNCTRL_SUCCESS;
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
  return LIBHICNCTRL_SUCCESS;
}

int hc_data_set_complete(hc_data_t *data) {
  data->complete = true;
  if (data->complete_cb) return data->complete_cb(data, data->complete_cb_data);
  return LIBHICNCTRL_SUCCESS;
}

int hc_data_reset(hc_data_t *data) {
  data->size = 0;
  return LIBHICNCTRL_SUCCESS;
}

int hc_data_find(hc_data_t *data, const void *element, cmp_t cmp,
                 void **found) {
  foreach_type(u8, x, data) {
    if (cmp(x, element) == 0) {
      *found = x;
      return LIBHICNCTRL_SUCCESS;
    }
  };
  *found = NULL; /* this is optional */
  return LIBHICNCTRL_SUCCESS;
}

/******************************************************************************
 * Control socket
 ******************************************************************************/

/**
 * \brief Parse a connection URL into a sockaddr
 * \param [in] url - URL
 * \param [out] sa - Resulting struct sockaddr, expected zero'ed.
 * \return 0 if parsing succeeded, a negative error value otherwise.
 */
int hc_sock_parse_url(const char *url, struct sockaddr *sa) {
  /* FIXME URL parsing is currently not implemented */
  assert(!url);

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
      return LIBHICNCTRL_FAILURE;
  }

  return LIBHICNCTRL_SUCCESS;
}

hc_sock_t *hc_sock_create_url(const char *url) {
  hc_sock_t *s = malloc(sizeof(hc_sock_t));
  if (!s) goto ERR_MALLOC;

  s->url = url ? strdup(url) : NULL;

  s->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (s->fd < 0) goto ERR_SOCKET;

  if (hc_sock_reset(s) < 0) goto ERR_RESET;

  return s;

ERR_RESET:
  close(s->fd);
ERR_SOCKET:
  free(s);
ERR_MALLOC:
  return NULL;
}

hc_sock_t *hc_sock_create(void) { return hc_sock_create_url(NULL); }

void hc_sock_free(hc_sock_t *s) {
  if (s->url) free(s->url);
  close(s->fd);
  free(s);
}

int hc_sock_set_nonblocking(hc_sock_t *s) {
  return (fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL) | O_NONBLOCK) < 0);
}

int hc_sock_connect(hc_sock_t *s) {
  struct sockaddr_storage ss = {0};

  if (hc_sock_parse_url(s->url, (struct sockaddr *)&ss) < 0) goto ERR_PARSE;

  size_t size = ss.ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6);
  if (connect(s->fd, (struct sockaddr *)&ss, size) <
      0)  // sizeof(struct sockaddr)) < 0)
    goto ERR_CONNECT;

  return LIBHICNCTRL_SUCCESS;

ERR_CONNECT:
ERR_PARSE:
  return LIBHICNCTRL_FAILURE;
}

int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen) {
  return send(s->fd, msg, msglen, 0);
}

int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size) {
  *buffer = s->buf + s->woff;
  *size = RECV_BUFLEN - s->woff;

  return LIBHICNCTRL_SUCCESS;
}

int hc_sock_recv(hc_sock_t *s, hc_data_t *data) {
  int rc;

  /*
   * This condition should be ensured to guarantee correct processing of
   * messages
   */
  assert(RECV_BUFLEN - s->woff > MIN_BUFLEN);

  rc = recv(s->fd, s->buf + s->woff, RECV_BUFLEN - s->woff, 0);
  if (rc == 0) {
    printf("connection closed\n");
    return LIBHICNCTRL_FAILURE;
    /* Connection has been closed */
    // XXX
  }
  if (rc < 0) {
    /* Error occurred */
    printf("error occurred\n");
    // XXX check for EWOULDBLOCK;
    // XXX
    return LIBHICNCTRL_FAILURE;
  }
  s->woff += rc;
  return LIBHICNCTRL_SUCCESS;
}

int hc_sock_process(hc_sock_t *s, hc_data_t *data,
                    int (*parse)(const u8 *src, u8 *dst)) {
  int err = 0;

  /* We must have received at least one byte */
  size_t available = s->woff - s->roff;

  while (available > 0) {
    if (s->remaining == 0) {
      hc_msg_t *msg = (hc_msg_t *)(s->buf + s->roff);

      /* We expect a message header */
      if (available < sizeof(hc_msg_header_t)) break;

      /* Sanity checks (might instead raise warnings) */
      // TODO: sync check ?
      assert((msg->hdr.messageType == RESPONSE_LIGHT) ||
             (msg->hdr.messageType == ACK_LIGHT) ||
             (msg->hdr.messageType == NACK_LIGHT));
      // assert(msg->hdr.commandID == data->command_id); // FIXME
      assert(msg->hdr.seqNum == s->recv_seq++);

      s->remaining = msg->hdr.length;
      if (s->remaining == 0) {
        /*
         * The protocol expects all sequence number to be reset after
         * each transaction. We reset before running the callback in
         * case it triggers new exchanges.
         */
        s->send_seq = HICN_CTRL_SEND_SEQ_INIT;
        s->recv_seq = HICN_CTRL_RECV_SEQ_INIT;

        // TODO : check before even sending ?
        /* Complete message without payload */
        // TODO : is this correct ? no error code ?
        hc_data_set_complete(data);
      }

      available -= sizeof(hc_msg_header_t);
      s->roff += sizeof(hc_msg_header_t);
    } else {
      /* We expect the complete payload, or at least a chunk of it */
      size_t num_chunks = available / data->in_element_size;
      if (num_chunks == 0) break;
      if (num_chunks > s->remaining) num_chunks = s->remaining;

      if (!parse) {
        hc_data_push_many(data, s->buf + s->roff, num_chunks);
      } else {
        int rc;
        rc = hc_data_ensure_available(data, num_chunks);
        if (rc < 0) return LIBHICNCTRL_FAILURE;
        for (int i = 0; i < num_chunks; i++) {
          u8 *dst = hc_data_get_next(data);
          if (!dst) return LIBHICNCTRL_FAILURE;

          rc = parse(s->buf + s->roff + i * data->in_element_size, dst);
          if (rc < 0) err = -1; /* FIXME we let the loop complete (?) */
          data->size++;
        }
      }

      s->remaining -= num_chunks;
      if (s->remaining == 0) {
        /*
         * The protocol expects all sequence number to be reset after
         * each transaction. We reset before running the callback in
         * case it triggers new exchanges.
         */
        s->send_seq = HICN_CTRL_SEND_SEQ_INIT;
        s->recv_seq = HICN_CTRL_RECV_SEQ_INIT;

        hc_data_set_complete(data);
      }

      available -= num_chunks * data->in_element_size;
      s->roff += num_chunks * data->in_element_size;
    }
  }

  /* Make sure there is enough remaining space in the buffer */
  if (RECV_BUFLEN - s->woff < AVG_BUFLEN) {
    /*
     * There should be no overlap provided a sufficiently large BUFLEN, but
     * who knows.
     */
    memmove(s->buf, s->buf + s->roff, s->woff - s->roff);
    s->woff -= s->roff;
    s->roff = 0;
  }

  return err;
}

int hc_sock_reset(hc_sock_t *s) {
  s->roff = s->woff = 0;
  s->send_seq = HICN_CTRL_SEND_SEQ_INIT;
  s->recv_seq = HICN_CTRL_RECV_SEQ_INIT;
  s->remaining = 0;
  return LIBHICNCTRL_SUCCESS;
}

/******************************************************************************
 * Command-specific structures and functions
 ******************************************************************************/

typedef int (*HC_PARSE)(const u8 *, u8 *);

typedef struct {
  hc_action_t cmd;
  command_id cmd_id;
  size_t size_in;
  size_t size_out;
  HC_PARSE parse;
} hc_command_params_t;

int hc_execute_command(hc_sock_t *s, hc_msg_t *msg, size_t msg_len,
                       hc_command_params_t *params, hc_data_t **pdata) {
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
    case ACTION_LIST:
      assert(params->size_in != 0);
      assert(params->size_out != 0);
      assert(params->parse != NULL);
      break;
    case ACTION_SET:
      assert(params->size_in != 0);
      assert(params->size_out == 0);
      assert(params->parse == NULL);
      break;
    default:
      return LIBHICNCTRL_FAILURE;
  }

  hc_sock_reset(s);

  /* XXX data will at least store the result (complete) */
  hc_data_t *data = hc_data_create(params->size_in, params->size_out);
  if (!data) goto ERR_DATA;

  hc_sock_send(s, msg, msg_len);
  while (!data->complete) {
    if (hc_sock_recv(s, data) < 0) break;
    // XXX XXX XXX Process data with no resut !!!! XXX XXX XXX
    // XXX just return code
    // we are receiving the exact same message we have sent with a ACK
    // or NACK instead of the command !
    if (hc_sock_process(s, data, params->parse) < 0) {
      // ERROR PROCESSING... RESET ? XXX
      goto ERR_PROCESS;
    }
  }

  if (pdata) *pdata = data;

  return LIBHICNCTRL_SUCCESS;

ERR_PROCESS:
  free(data);
ERR_DATA:
  return LIBHICNCTRL_FAILURE;
}

/* /!\ Please update constants in header file upon changes */
size_t hc_url_snprintf(char *s, size_t size, int family,
                       ip_address_t *ip_address, u16 port) {
  char *cur = s;
  int rc;

  /* Other address are currently not supported */
  assert(IS_VALID_FAMILY(family));

  rc = snprintf(cur, s + size - cur, "inet%c://",
                (family == AF_INET) ? '4' : '6');
  if (rc < 0) return rc;
  cur += rc;
  if (size != 0 && cur >= s + size) return cur - s;

  rc = ip_address_snprintf(cur, s + size - cur, ip_address, family);
  if (rc < 0) return rc;
  cur += rc;
  if (size != 0 && cur >= s + size) return cur - s;

  rc = snprintf(cur, s + size - cur, ":");
  if (rc < 0) return rc;
  cur += rc;
  if (size != 0 && cur >= s + size) return cur - s;

  rc = snprintf(cur, s + size - cur, "%d", port);
  if (rc < 0) return rc;
  cur += rc;
  if (size != 0 && cur >= s + size) return cur - s;

  return cur - s;
}

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

int hc_parse_listener(void *in, hc_listener_t *listener) {
  list_listeners_command *cmd = (list_listeners_command *)in;

  if (!IS_VALID_LIST_LISTENERS_TYPE(cmd->encapType)) return LIBHICNCTRL_FAILURE;

  hc_connection_type_t type = map_from_encap_type[cmd->encapType];
  if (type == CONNECTION_TYPE_UNDEFINED) return LIBHICNCTRL_FAILURE;

  if (!IS_VALID_ADDR_TYPE(cmd->addressType)) return LIBHICNCTRL_FAILURE;

  int family = map_from_addr_type[cmd->addressType];
  if (!IS_VALID_FAMILY(family)) return LIBHICNCTRL_FAILURE;

  *listener = (hc_listener_t){
      .conn_id = cmd->connid,
      .type = type,
      .family = family,
      .local_addr = UNION_CAST(cmd->address, ip_address_t),
      .local_port = ntohs(cmd->port),
  };
  bzero(listener->name, NAME_LEN);
  return LIBHICNCTRL_SUCCESS;
}

typedef struct {
  header_control_message hdr;
  add_listener_command payload;
} hc_msg_listener_add_t;

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener) {
  if (!IS_VALID_FAMILY(listener->family)) return LIBHICNCTRL_FAILURE;

  if (!IS_VALID_CONNECTION_TYPE(listener->type)) return LIBHICNCTRL_FAILURE;

  hc_msg_listener_add_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = ADD_LISTENER,
              .length = 1,
              .seqNum = s->send_seq,
          },
      .payload = {
          .address =
              {
                  .ipv6 = listener->local_addr.v6.as_in6addr,
              },
          .port = htons(listener->local_port),
          .addressType = (u8)map_to_addr_type[listener->family],
          .listenerMode = (u8)map_to_listener_mode[listener->type],
          .connectionType = (u8)map_to_connection_type[listener->type],
      }};
  strncpy(msg.payload.symbolic, listener->name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = ADD_LISTENER,
      .size_in = sizeof(add_listener_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}

typedef struct {
  header_control_message hdr;
} hc_msg_listener_list_t;

int hc_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_msg_listener_list_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = LIST_LISTENERS,
              .length = 0,
              .seqNum = s->send_seq,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_LISTENERS,
      .size_in = sizeof(list_listeners_command),
      .size_out = sizeof(hc_listener_t),
      .parse = (HC_PARSE)hc_parse_listener,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, pdata);
}

int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2) {
  return ((l1->type == l2->type) && (l1->family == l2->family) &&
          (memcmp(&l1->local_addr, &l2->local_addr, sizeof(ip_address_t))) &&
          (l1->local_port == l2->local_port))
             ? LIBHICNCTRL_SUCCESS
             : LIBHICNCTRL_FAILURE;
}

/* /!\ Please update constants in header file upon changes */
size_t hc_listener_snprintf(char *s, size_t size, hc_listener_t *listener) {
  char local[MAXSZ_HC_URL];
  int rc;

  rc = hc_url_snprintf(local, MAXSZ_HC_URL, listener->family,
                       &listener->local_addr, listener->local_port);
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s", local, connection_type_str[listener->type]);
}

/*----------------------------------------------------------------------------*
 * Connections
 *----------------------------------------------------------------------------*/

int hc_parse_connection(void *in, hc_connection_t *connection) {
  list_connections_command *cmd = (list_connections_command *)in;

  if (!IS_VALID_LIST_CONNECTIONS_TYPE(cmd->connectionData.connectionType))
    return LIBHICNCTRL_FAILURE;

  hc_connection_type_t type =
      map_from_list_connections_type[cmd->connectionData.connectionType];
  if (type == CONNECTION_TYPE_UNDEFINED) return LIBHICNCTRL_FAILURE;

  if (!IS_VALID_LIST_CONNECTIONS_STATE(cmd->state)) return LIBHICNCTRL_FAILURE;

  hc_connection_state_t state = map_from_list_connections_state[cmd->state];
  if (state == CONNECTION_STATE_UNDEFINED) return LIBHICNCTRL_FAILURE;

  if (!IS_VALID_ADDR_TYPE(cmd->connectionData.ipType))
    return LIBHICNCTRL_FAILURE;

  int family = map_from_addr_type[cmd->connectionData.ipType];
  if (!IS_VALID_FAMILY(family)) return LIBHICNCTRL_FAILURE;

  *connection = (hc_connection_t){
      .id = cmd->connid,
      .type = type,
      .family = family,
      .local_addr = UNION_CAST(cmd->connectionData.localIp, ip_address_t),
      .local_port = ntohs(cmd->connectionData.localPort),
      .remote_addr = UNION_CAST(cmd->connectionData.remoteIp, ip_address_t),
      .remote_port = ntohs(cmd->connectionData.remotePort),
#ifdef WITH_POLICY
      .desired_state = cmd->connectionData.desired_state,
      .tags = cmd->connectionData.tags,
#endif /* WITH_POLICY */
      .state = state,
  };
  strncpy(connection->name, cmd->connectionData.symbolic, NAME_LEN);
  return LIBHICNCTRL_SUCCESS;
}

typedef struct {
  header_control_message hdr;
  add_connection_command payload;
} hc_msg_connection_add_t;

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection) {
  if (!IS_VALID_FAMILY(connection->family)) return LIBHICNCTRL_FAILURE;

  if (!IS_VALID_CONNECTION_TYPE(connection->type)) return LIBHICNCTRL_FAILURE;

  /* TODO assert both local and remote have the right family */

  hc_msg_connection_add_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = ADD_CONNECTION,
              .length = 1,
              .seqNum = s->send_seq,
          },
      .payload = {
          /* we use IPv6 which is the longest address */
          .remoteIp.ipv6 = connection->remote_addr.v6.as_in6addr,
          .localIp.ipv6 = connection->local_addr.v6.as_in6addr,
          .remotePort = htons(connection->remote_port),
          .localPort = htons(connection->local_port),
          .ipType = (u8)map_to_addr_type[connection->family],
#ifdef WITH_POLICY
          .desired_state = connection->desired_state,
          .tags = connection->tags,
#endif /* WITH_POLICY */
          .connectionType = (u8)map_to_connection_type[connection->type],
      }};
  strncpy(msg.payload.symbolic, connection->name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = ADD_CONNECTION,
      .size_in = sizeof(add_connection_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}

typedef struct {
  header_control_message hdr;
  remove_connection_command payload;
} hc_msg_connection_remove_t;

int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection) {
  hc_msg_connection_remove_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = REMOVE_CONNECTION,
              .length = 1,
              .seqNum = s->send_seq,
          },
  };
  strncpy(msg.payload.symbolicOrConnid, connection->name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = REMOVE_CONNECTION,
      .size_in = sizeof(remove_connection_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}

#ifdef WITH_POLICY
typedef struct {
  header_control_message hdr;
  connection_set_state_command payload;
} hc_msg_connection_set_state_t;

int hc_connection_set_state(hc_sock_t *s, const char *conn_id_or_name,
                            face_state_t state) {
  hc_msg_connection_set_state_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = CONNECTION_SET_STATE,
              .length = 1,
              .seqNum = s->send_seq,
          },
      .payload =
          {
              .state = state,
          },
  };
  strncpy(msg.payload.symbolicOrConnid, conn_id_or_name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = CONNECTION_SET_STATE,
      .size_in = sizeof(connection_set_state_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}
#endif /* WITH_POLICY */

typedef struct {
  header_control_message hdr;
} hc_msg_connection_list_t;

int hc_connection_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_msg_connection_list_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = LIST_CONNECTIONS,
              .length = 0,
              .seqNum = s->send_seq,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_CONNECTIONS,
      .size_in = sizeof(list_connections_command),
      .size_out = sizeof(hc_connection_t),
      .parse = (HC_PARSE)hc_parse_connection,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, pdata);
}

/* /!\ Please update constants in header file upon changes */
size_t hc_connection_snprintf(char *s, size_t size,
                              hc_connection_t *connection) {
  char local[MAXSZ_HC_URL];
  char remote[MAXSZ_HC_URL];
  int rc;

  // assert(connection->connection_state)

  rc = hc_url_snprintf(local, MAXSZ_HC_URL, connection->family,
                       &connection->local_addr, connection->local_port);
  if (rc < 0) return rc;
  rc = hc_url_snprintf(remote, MAXSZ_HC_URL, connection->family,
                       &connection->remote_addr, connection->remote_port);
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s %s %s",
                  connection_state_str[connection->state], local, remote,
                  connection_type_str[connection->type]);
}

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

int hc_parse_route(void *in, hc_route_t *route) {
  list_routes_command *cmd = (list_routes_command *)in;

  if (!IS_VALID_ADDR_TYPE(cmd->addressType)) return LIBHICNCTRL_FAILURE;

  int family = map_from_addr_type[cmd->addressType];
  if (!IS_VALID_FAMILY(family)) return LIBHICNCTRL_FAILURE;

  *route = (hc_route_t){
      .conn_id = cmd->connid,
      .family = family,
      .remote_addr = UNION_CAST(cmd->address, ip_address_t),
      .len = cmd->len,
      .cost = cmd->cost,
  };
  bzero(route->conn_name, NAME_LEN);
  return LIBHICNCTRL_SUCCESS;
}

typedef struct {
  header_control_message hdr;
  add_route_command payload;
} hc_msg_route_add_t;

int hc_route_create(hc_sock_t *s, hc_route_t *route) {
  if (!IS_VALID_FAMILY(route->family)) return LIBHICNCTRL_FAILURE;

  hc_msg_route_add_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = ADD_ROUTE,
              .length = 1,
              .seqNum = s->send_seq,
          },
      .payload = {
          /* we use IPv6 which is the longest address */
          .address.ipv6 = route->remote_addr.v6.as_in6addr,
          .cost = route->cost,
          .addressType = (u8)map_to_addr_type[route->family],
          .len = route->len,
      }};
  strncpy(msg.payload.symbolicOrConnid, route->conn_name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = ADD_ROUTE,
      .size_in = sizeof(add_route_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}

typedef struct {
  header_control_message hdr;
  remove_route_command payload;
} hc_msg_route_remove_t;

int hc_route_delete(hc_sock_t *s, hc_route_t *route) {
  if (!IS_VALID_FAMILY(route->family)) return LIBHICNCTRL_FAILURE;

  hc_msg_route_remove_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = REMOVE_ROUTE,
              .length = 1,
              .seqNum = s->send_seq,
          },
      .payload = {
          /* we use IPv6 which is the longest address */
          .address.ipv6 = route->remote_addr.v6.as_in6addr,
          .addressType = (u8)map_to_addr_type[route->family],
          .len = route->len,
      }};
  strncpy(msg.payload.symbolicOrConnid, route->conn_name, NAME_LEN);

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = REMOVE_ROUTE,
      .size_in = sizeof(remove_route_command),
      .size_out = 0,
      .parse = NULL,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL);
}

typedef struct {
  header_control_message hdr;
} hc_msg_route_list_t;

int hc_route_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_msg_route_list_t msg = {
      .hdr =
          {
              .messageType = REQUEST_LIGHT,
              .commandID = LIST_ROUTES,
              .length = 0,
              .seqNum = s->send_seq,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_ROUTES,
      .size_in = sizeof(list_routes_command),
      .size_out = sizeof(hc_route_t),
      .parse = (HC_PARSE)hc_parse_route,
  };

  return hc_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, pdata);
}

/* /!\ Please update constants in header file upon changes */
size_t hc_route_snprintf(char *s, size_t size, hc_route_t *route) {
  return LIBHICNCTRL_SUCCESS;
}

/*----------------------------------------------------------------------------*
 * Face
 *----------------------------------------------------------------------------*/

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
      return LIBHICNCTRL_FAILURE;
  }
  return LIBHICNCTRL_FAILURE; /* Not implemented */
}

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection) {
  const face_t *f = &face->face;

  switch (f->type) {
    case FACE_TYPE_HICN:
      /* FIXME truncations, collisions, ... */
      *connection = (hc_connection_t){
          .type = CONNECTION_TYPE_HICN,
          .family = f->hicn.family,
          .local_addr = f->hicn.local_addr,
          .local_port = 0,
          .remote_addr = f->hicn.remote_addr,
          .remote_port = 0,
      };
      snprintf(connection->name, NAME_LEN, "%s", f->hicn.netdevice.name);
      break;
    case FACE_TYPE_TCP:
      *connection = (hc_connection_t){
          .type = CONNECTION_TYPE_TCP,
          .family = f->hicn.family,
          .local_addr = f->tunnel.local_addr,
          .local_port = f->tunnel.local_port,
          .remote_addr = f->tunnel.remote_addr,
          .remote_port = f->tunnel.remote_port,
      };
#ifdef __APPLE__
      snprintf(connection->name, NAME_LEN, "tcp%d", arc4random() & 0xFF);
#else
      snprintf(connection->name, NAME_LEN, "tcp%ld", random() & 0xFF);
#endif
      break;
    case FACE_TYPE_UDP:
      *connection = (hc_connection_t){
          .type = CONNECTION_TYPE_UDP,
          .family = AF_INET,
          .local_addr = f->tunnel.local_addr,
          .local_port = f->tunnel.local_port,
          .remote_addr = f->tunnel.remote_addr,
          .remote_port = f->tunnel.remote_port,
      };
#ifdef __APPLE__
      snprintf(connection->name, NAME_LEN, "udp%d", arc4random() & 0xFF);
#else
      snprintf(connection->name, NAME_LEN, "udp%ld", random() & 0xFF);
#endif
      printf("Created f %s !\n", connection->name);
      break;
    default:
      return LIBHICNCTRL_FAILURE;
  }

  return LIBHICNCTRL_SUCCESS;
}

int hc_connection_to_face(const hc_connection_t *connection, hc_face_t *face) {
  switch (connection->type) {
    case CONNECTION_TYPE_TCP:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_TCP,
                  .tunnel =
                      {
                          .family = connection->family,
                          .local_addr = connection->local_addr,
                          .local_port = connection->local_port,
                          .remote_addr = connection->remote_addr,
                          .remote_port = connection->remote_port,
                      },
              },
      };
      break;
    case CONNECTION_TYPE_UDP:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_UDP,
                  .tunnel =
                      {
                          .family = connection->family,
                          .local_addr = connection->local_addr,
                          .local_port = connection->local_port,
                          .remote_addr = connection->remote_addr,
                          .remote_port = connection->remote_port,
                      },
              },
      };
      break;
    case CONNECTION_TYPE_HICN:
      *face = (hc_face_t){
          .id = connection->id,
          .face =
              {
                  .type = FACE_TYPE_HICN,
                  .hicn =
                      {
                          .family = connection->family,
                          .netdevice.index = NETDEVICE_UNDEFINED_INDEX,  // XXX
                          .local_addr = connection->local_addr,
                          .remote_addr = connection->remote_addr,
                      },
              },
      };
      break;
    default:
      return LIBHICNCTRL_FAILURE;
  }
  strncpy(face->name, connection->name, NAME_LEN);
  return LIBHICNCTRL_SUCCESS;
}

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener) {
  *listener = (hc_listener_t){
      .conn_id = ~0,
      .type = connection->type,
      .family = connection->family,
      .local_addr = connection->local_addr,
      .local_port = connection->local_port,
  };
  return LIBHICNCTRL_SUCCESS;
}

int hc_face_create(hc_sock_t *s, hc_face_t *face) {
  hc_connection_t connection;
  hc_data_t *listeners;
  hc_listener_t listener;
  hc_listener_t *found;

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
      if (hc_face_to_connection(face, &connection) < 0)
        return LIBHICNCTRL_FAILURE;

      /* Ensure we have a corresponding local listener */
      if (hc_connection_to_local_listener(&connection, &listener) < 0)
        return LIBHICNCTRL_FAILURE;

      /* We might cache results for faster future lookups (at least to
       * test existence) */
      if (hc_listener_list(s, &listeners) < 0) return LIBHICNCTRL_FAILURE;

      /* Test */
      if (hc_data_find(listeners, &listener, (cmp_t)hc_listener_cmp,
                       (void **)&found) < 0)
        return LIBHICNCTRL_FAILURE;

      hc_data_free(listeners);

      if (!found) {
        /* We need to create the listener if it does not exists */
        if (hc_listener_create(s, &listener) < 0) return LIBHICNCTRL_FAILURE;
      }

      if (hc_connection_create(s, &connection) < 0) return LIBHICNCTRL_FAILURE;

      break;

    case FACE_TYPE_HICN_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      if (hc_face_to_listener(face, &listener) < 0) return LIBHICNCTRL_FAILURE;
      if (hc_listener_create(s, &listener) < 0) return LIBHICNCTRL_FAILURE;
      return LIBHICNCTRL_FAILURE;
      break;
    default:
      return LIBHICNCTRL_FAILURE;
  };
  return LIBHICNCTRL_SUCCESS;
}

int hc_face_delete(hc_sock_t *s, hc_face_t *face) {
  /* We currently do not delete the listener */
  hc_connection_t connection;
  if (hc_face_to_connection(face, &connection) < 0) return LIBHICNCTRL_FAILURE;
  return hc_connection_delete(s, &connection);
}

int hc_face_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_data_t *connection_data;
  hc_face_t face;

  if (hc_connection_list(s, &connection_data) < 0) return LIBHICNCTRL_FAILURE;

  hc_data_t *face_data =
      hc_data_create(sizeof(hc_connection_t), sizeof(hc_face_t));
  foreach_connection(c, connection_data) {
    if (hc_connection_to_face(c, &face) < 0) goto ERR;
    hc_data_push(face_data, &face);
  }

  *pdata = face_data;
  hc_data_free(connection_data);
  return LIBHICNCTRL_SUCCESS;

ERR:
  hc_data_free(connection_data);
  return LIBHICNCTRL_FAILURE;
}

#ifdef WITH_POLICY
int hc_face_set_state(hc_sock_t *s, const char *conn_id_or_name,
                      face_state_t state) {
  return hc_connection_set_state(s, conn_id_or_name, state);
}
#endif /* WITH_POLICY */
/* /!\ Please update constants in header file upon changes */
size_t hc_face_snprintf(char *s, size_t size, hc_face_t *face) {
  return LIBHICNCTRL_SUCCESS;
}

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int hc_cache_set_store(hc_sock_t *s, int enabled) {
  return LIBHICNCTRL_SUCCESS;
}

int hc_cache_set_serve(hc_sock_t *s, int enabled) {
  return LIBHICNCTRL_SUCCESS;
}

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

int hc_punting_create(hc_sock_t *s /* XXX */) { return LIBHICNCTRL_SUCCESS; }

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
int hc_strategy_set(hc_sock_t *s /* XXX */) { return LIBHICNCTRL_SUCCESS; }

/*----------------------------------------------------------------------------*
 * FIB
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * PIT
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
int hc_wldr_set(hc_sock_t *s /* XXX */) { return LIBHICNCTRL_SUCCESS; }

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

int hc_mapme_set(hc_sock_t *s, int enabled) { return LIBHICNCTRL_SUCCESS; }

int hc_mapme_set_discovery(hc_sock_t *s, int enabled) {
  return LIBHICNCTRL_SUCCESS;
}

int hc_mapme_set_timescale(hc_sock_t *s, double timescale) {
  return LIBHICNCTRL_SUCCESS;
}

int hc_mapme_set_retx(hc_sock_t *s, double timescale) {
  return LIBHICNCTRL_SUCCESS;
}
