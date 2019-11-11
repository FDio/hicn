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

#include <assert.h> // assert
#include <math.h> // log2
#include <stdbool.h>
#include <stdio.h> // snprintf
#include <string.h> // memmove, strcasecmp
#include <sys/socket.h> // socket
#include <unistd.h> // close, fcntl
#include <fcntl.h> // fcntl

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/commands.h>
#include <hicn/util/token.h>
#include "util/log.h"
#include "util/map.h"
#include <strings.h>

#define PORT 9695

/*
 * Internal state associated to a pending request
 */
typedef struct {
    int seq;
    hc_data_t * data;
    /* Information used to process results */
    int size_in;
    int (*parse)(const u8 * src, u8 * dst);
} hc_sock_request_t;

/**
 * Messages to the forwarder might be multiplexed thanks to the seqNum fields in
 * the header_control_message structure. The forwarder simply answers back the
 * original sequence number. We maintain a map of such sequence number to
 * outgoing queries so that replied can be demultiplexed and treated
 * appropriately.
 */
TYPEDEF_MAP_H(hc_sock_map, int, hc_sock_request_t *);
TYPEDEF_MAP(hc_sock_map, int, hc_sock_request_t *, int_cmp, int_snprintf, generic_snprintf);

struct hc_sock_s {
    char * url;
    int fd;

    /* Partial receive buffer */
    u8 buf[RECV_BUFLEN];
    size_t roff; /**< Read offset */
    size_t woff; /**< Write offset */

    /*
     * Because received messages are potentially unbounded in size, we might not
     * guarantee that we can store a full packet before processing it. We must
     * implement a very simple state machine remembering the current parsing
     * status in order to partially process the packet.
     */
    size_t remaining;
    u32 send_id;

    /* Next sequence number to be used for requests */
    int seq;

    /* Request being parsed (NULL if none) */
    hc_sock_request_t * cur_request;

    bool async;
    hc_sock_map_t * map;
};


hc_sock_request_t *
hc_sock_request_create(int seq, hc_data_t * data, HC_PARSE parse)
{
    assert(seq >= 0);
    assert(data);

    hc_sock_request_t * request = malloc(sizeof(hc_sock_request_t));
    if (!request)
        return NULL;
    request->seq = seq;
    request->data = data;
    request->parse = parse;
    return request;
}

void
hc_sock_request_free(hc_sock_request_t * request)
{
    free(request);
}


#if 0
#ifdef __APPLE__
#define RANDBYTE() (u8)(arc4random() & 0xFF)
#else
#define RANDBYTE() (u8)(random() & 0xFF)
#endif
#endif
#define RANDBYTE() (u8)(rand() & 0xFF)

/*
 * list was working with all seq set to 0, but it seems hicnLightControl uses
 * 1, and replies with the same seqno
 */
#define HICN_CTRL_SEND_SEQ_INIT 1
#define HICN_CTRL_RECV_SEQ_INIT 1

#define MAX(x, y) ((x > y) ? x : y)

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
#define AVG_BUFLEN sizeof(hc_msg_header_t) + AVG_ELEMENTS * sizeof(hc_msg_payload_t)

/*
 * We should at least have buffer space allowing to store one processable unit
 * of data, either the header of the maximum possible payload
 */
#define MIN_BUFLEN MAX(sizeof(hc_msg_header_t), sizeof(hc_msg_payload_t))

static const struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

/* /!\ Please update constants in header file upon changes */
const char * connection_type_str[] = {
#define _(x) [CONNECTION_TYPE_ ## x] = STRINGIZE(x),
foreach_connection_type
#undef _
};

#define IS_VALID_CONNECTION_TYPE(x) IS_VALID_ENUM_TYPE(CONNECTION_TYPE, x)

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

/* Conversions to shield lib user from heterogeneity */

#define IS_VALID_LIST_CONNECTIONS_TYPE(x) ((x >= CONN_GRE) && (x <= CONN_HICN))

static const hc_connection_type_t map_from_list_connections_type[] = {
    [CONN_GRE]       = CONNECTION_TYPE_UNDEFINED,
    [CONN_TCP]       = CONNECTION_TYPE_TCP,
    [CONN_UDP]       = CONNECTION_TYPE_UDP,
    [CONN_MULTICAST] = CONNECTION_TYPE_UNDEFINED,
    [CONN_L2]        = CONNECTION_TYPE_UNDEFINED,
    [CONN_HICN]      = CONNECTION_TYPE_HICN,
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
    [ENCAP_TCP]     = CONNECTION_TYPE_TCP,
    [ENCAP_UDP]     = CONNECTION_TYPE_UDP,
    [ENCAP_ETHER]   = CONNECTION_TYPE_UNDEFINED,
    [ENCAP_LOCAL]   = CONNECTION_TYPE_UNDEFINED,
    [ENCAP_HICN]    = CONNECTION_TYPE_HICN,
};

static const connection_type map_to_connection_type[] = {
    [CONNECTION_TYPE_TCP]   = TCP_CONN,
    [CONNECTION_TYPE_UDP]   = UDP_CONN,
    [CONNECTION_TYPE_HICN]  = HICN_CONN,
};

static const listener_mode map_to_listener_mode[] = {
    [CONNECTION_TYPE_TCP]       = IP_MODE,
    [CONNECTION_TYPE_UDP]       = IP_MODE,
    [CONNECTION_TYPE_HICN]      = HICN_MODE,
};

#define IS_VALID_LIST_CONNECTIONS_STATE(x) ((x >= IFACE_UP) && (x <= IFACE_UNKNOWN))

/* /!\ Please update constants in header file upon changes */
const char * connection_state_str[] = {
#define _(x) [HC_CONNECTION_STATE_ ## x] = STRINGIZE(x),
foreach_connection_state
#undef _
};

/*
#define IS_VALID_CONNECTION_STATE(x) IS_VALID_ENUM_TYPE(CONNECTION_STATE, x)

static const connection_state map_to_connection_state[] = {
    [HC_CONNECTION_STATE_UP]       = IFACE_UP,
    [HC_CONNECTION_STATE_DOWN]     = IFACE_DOWN,
};

*/

static const hc_connection_state_t map_from_list_connections_state[] = {
    [IFACE_UP]                  = HC_CONNECTION_STATE_UP,
    [IFACE_DOWN]                = HC_CONNECTION_STATE_DOWN,
    [IFACE_UNKNOWN]             = HC_CONNECTION_STATE_UNDEFINED,
};


#define connection_state_to_face_state(x) ((face_state_t)(x))
#define face_state_to_connection_state(x) ((hc_connection_state_t)(x))

#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

static const int map_from_addr_type[] = {
    [ADDR_INET]     = AF_INET,
    [ADDR_INET6]    = AF_INET6,
    [ADDR_LINK]     = AF_UNSPEC,
    [ADDR_IFACE]    = AF_UNSPEC,
    [ADDR_UNIX]     = AF_UNSPEC,
};

static const address_type map_to_addr_type[] = {
    [AF_INET]   = ADDR_INET,
    [AF_INET6]  = ADDR_INET6,
};

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_hc_command      \
    _(add_connection)           \
    _(remove_connection)        \
    _(list_connections)         \
    _(add_listener)             \
    _(remove_listener)          \
    _(list_listeners)           \
    _(add_route)                \
    _(remove_route)             \
    _(list_routes)              \
    _(cache_store)              \
    _(cache_serve)              \
    /*_(cache_clear) */         \
    _(set_strategy)             \
    _(set_wldr)                 \
    _(add_punting)              \
    _(mapme_activator)          \
    _(mapme_timing)

typedef header_control_message hc_msg_header_t;

typedef union {
#define _(x) x ## _command x;
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

hc_data_t *
hc_data_create(size_t in_element_size, size_t out_element_size)
{
    hc_data_t * data = malloc(sizeof(hc_data_t));
    if (!data)
        goto ERR_MALLOC;

    /* FIXME Could be NULL thanks to realloc provided size is 0 */
    data->max_size_log = DEFAULT_SIZE_LOG;
    data->in_element_size = in_element_size;
    data->out_element_size = out_element_size;
    data->size = 0;
    data->complete = false;
    data->command_id = 0; // TODO this could also be a busy mark in the socket
    /* No callback needed in blocking code for instance */
    data->complete_cb = NULL;

    data->buffer = malloc((1 << data->max_size_log) * data->out_element_size);
    if (!data->buffer)
        goto ERR_BUFFER;
    data->ret = 0;

    return data;

ERR_BUFFER:
    hc_data_free(data);
ERR_MALLOC:
    return NULL;
}

void
hc_data_free(hc_data_t * data)
{
    if (data->buffer)
        free(data->buffer);
    free(data);
}

int
hc_data_ensure_available(hc_data_t * data, size_t count)
{
    size_t new_size_log = (data->size + count - 1 > 0)
        ? log2(data->size + count - 1) + 1
        : 0;
    if (new_size_log > data->max_size_log) {
        data->max_size_log = new_size_log;
        data->buffer = realloc(data->buffer, (1 << new_size_log) * data->out_element_size);
        if (!data->buffer)
             return -1;
    }
     return 0;
}

int
hc_data_push_many(hc_data_t * data, const void * elements, size_t count)
{
    if (hc_data_ensure_available(data, count) < 0)
         return -1;

    memcpy(data->buffer + data->size * data->out_element_size, elements,
            count * data->out_element_size);
    data->size += count;
     return 0;
}

int
hc_data_push(hc_data_t * data, const void * element)
{
    return hc_data_push_many(data, element, 1);
}

/**
 *
 * NOTE: This function make sure there is enough room available in the data
 * structure.
 */
u8 *
hc_data_get_next(hc_data_t * data)
{
    if (hc_data_ensure_available(data, 1) < 0)
        return NULL;

    return data->buffer + data->size * data->out_element_size;
}

int
hc_data_set_callback(hc_data_t * data, data_callback_t cb, void * cb_data)
{
    data->complete_cb = cb;
    data->complete_cb_data = cb_data;
     return 0;
}

int
hc_data_set_complete(hc_data_t * data)
{
    data->complete = true;
    data->ret = 0;
    if (data->complete_cb)
        return data->complete_cb(data, data->complete_cb_data);
     return 0;
}

int
hc_data_set_error(hc_data_t * data)
{
    data->complete = true;
    data->ret = -1;
    if (data->complete_cb)
        return data->complete_cb(data, data->complete_cb_data);
     return 0;
}

int
hc_data_reset(hc_data_t * data)
{
    data->size = 0;
     return 0;
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
int
hc_sock_parse_url(const char * url, struct sockaddr * sa)
{
    /* FIXME URL parsing is currently not implemented */
    assert(!url);

    srand(time(NULL));

    /*
     * A temporary solution is to inspect the sa_family fields of the passed in
     * sockaddr, which defaults to AF_UNSPEC (0) and thus creates an IPv4/TCP
     * connection to localhost.
     */
    switch (sa->sa_family) {
        case AF_UNSPEC:
        case AF_INET:
        {
            struct sockaddr_in * sai = (struct sockaddr_in *)sa;
            sai->sin_family = AF_INET;
            sai->sin_port = htons(PORT);
            sai->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 * sai6 = (struct sockaddr_in6 *)sa;
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

hc_sock_t *
hc_sock_create_url(const char * url)
{
    hc_sock_t * s = malloc(sizeof(hc_sock_t));
    if (!s)
        goto ERR_MALLOC;

    s->url = url ? strdup(url) : NULL;

    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0)
        goto ERR_SOCKET;

    if (hc_sock_reset(s) < 0)
        goto ERR_RESET;

    s->seq = 0;
    s->cur_request = NULL;

    s->map = hc_sock_map_create();
    if (!s->map)
        goto ERR_MAP;

    return s;

    //hc_sock_map_free(s->map);
ERR_MAP:
ERR_RESET:
    if (s->url)
        free(s->url);
    close(s->fd);
ERR_SOCKET:
    free(s);
ERR_MALLOC:
    return NULL;
}

hc_sock_t *
hc_sock_create(void)
{
    return hc_sock_create_url(NULL);
}

void
hc_sock_free(hc_sock_t * s)
{
    hc_sock_request_t ** request_array = NULL;
    int n = hc_sock_map_get_value_array(s->map, &request_array);
    if (n < 0) {
       ERROR("Could not retrieve pending request array for freeing up resources"); 
    } else {
        for (unsigned i = 0; i < n; i++) {
            hc_sock_request_t * request = request_array[i];
            hc_sock_request_free(request);
        }
        free(request_array);
    }

    hc_sock_map_free(s->map);
    if (s->url)
        free(s->url);
    close(s->fd);
    free(s);
}

int
hc_sock_get_next_seq(hc_sock_t * s)
{
    return s->seq++;
}

int
hc_sock_set_nonblocking(hc_sock_t * s)
{
    return (fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL) | O_NONBLOCK) < 0);
}

int
hc_sock_get_fd(hc_sock_t * s)
{
    return s->fd;
}

int
hc_sock_connect(hc_sock_t * s)
{
    struct sockaddr_storage ss = { 0 };

    if (hc_sock_parse_url(s->url, (struct sockaddr *)&ss) < 0)
        goto ERR_PARSE;

    size_t size = ss.ss_family == AF_INET
        ? sizeof(struct sockaddr_in)
        : sizeof(struct sockaddr_in6);
    if (connect(s->fd, (struct sockaddr *)&ss, size) < 0) //sizeof(struct sockaddr)) < 0)
        goto ERR_CONNECT;

     return 0;

ERR_CONNECT:
ERR_PARSE:
     return -1;
}

int
hc_sock_send(hc_sock_t * s, hc_msg_t * msg, size_t msglen, int seq)
{
    int rc;
    msg->hdr.seqNum = seq;
    rc = send(s->fd, msg, msglen, 0);
    if (rc < 0) {
        perror("hc_sock_send");
        return -1;
    }
    return 0;
}

int
hc_sock_get_available(hc_sock_t * s, u8 ** buffer, size_t * size)
{
    *buffer = s->buf + s->woff;
    *size = RECV_BUFLEN - s->woff;

     return 0;
}

int
hc_sock_recv(hc_sock_t * s)
{
    int rc;

    /*
     * This condition should be ensured to guarantee correct processing of
     * messages
     */
    assert(RECV_BUFLEN - s->woff > MIN_BUFLEN);

    rc = recv(s->fd, s->buf + s->woff, RECV_BUFLEN - s->woff, 0);
    if (rc == 0) {
        /* Connection has been closed */
         return 0;
    }
    if (rc < 0) {
        /*
         * Let's not return 0 which currently means the socket has been closed
         */
        if (errno == EWOULDBLOCK)
            return -1;
        perror("hc_sock_recv");
        return -1;
    }
    s->woff += rc;
    return rc;
}

int
hc_sock_process(hc_sock_t * s, hc_data_t ** data)
{
    int err = 0;

    /* We must have received at least one byte */
    size_t available = s->woff - s->roff;

    while(available > 0) {

        if (!s->cur_request) { // No message being parsed, alternatively (remaining == 0)
            hc_msg_t * msg = (hc_msg_t*)(s->buf + s->roff);

            /* We expect a message header */
            if (available < sizeof(hc_msg_header_t))
                break;

            hc_sock_request_t * request = NULL;
            if (hc_sock_map_get(s->map, msg->hdr.seqNum, &request) < 0) {
                ERROR("[hc_sock_process] Error searching for matching request");
                return -1;
            }
            if (!request) {
                ERROR("[hc_sock_process] No request matching received sequence number");
                return -1;
            }

            s->remaining = msg->hdr.length;
            switch(msg->hdr.messageType) {
                case ACK_LIGHT:
                    assert(s->remaining == 0);
                    assert(!data);
                    hc_data_set_complete(request->data);
                    break;
                case NACK_LIGHT:
                    assert(s->remaining == 0);
                    assert(!data);
                    hc_data_set_error(request->data);
                    break;
                case RESPONSE_LIGHT:
                    assert(data);
                    if (s->remaining == 0) {
                        hc_data_set_complete(request->data);
                        *data = request->data;
                        hc_sock_request_free(request);
                    } else {
                        /* We only remember it if there is still data to parse */
                        s->cur_request = request;
                    }
                    break;
                default:
                    ERROR("[hc_sock_process] Invalid response received");
                    return -1;
            }

            available -= sizeof(hc_msg_header_t);
            s->roff += sizeof(hc_msg_header_t);
        } else {
            /* We expect the complete payload, or at least a chunk of it */
            size_t num_chunks = available / s->cur_request->data->in_element_size;
            if (num_chunks == 0)
                break;
            if (num_chunks > s->remaining)
                num_chunks = s->remaining;

            if (!s->cur_request->parse) {
                /* If we don't need to parse results, then we can directly push
                 * all of them into the result data structure */
                hc_data_push_many(s->cur_request->data, s->buf + s->roff, num_chunks);
            } else {
                int rc;
                rc = hc_data_ensure_available(s->cur_request->data, num_chunks);
                if (rc < 0)
                     return -1;
                for (int i = 0; i < num_chunks; i++) {
                    u8 * dst = hc_data_get_next(s->cur_request->data);
                    if (!dst)
                         return -1;

                    rc = s->cur_request->parse(s->buf + s->roff + i * s->cur_request->data->in_element_size, dst);
                    if (rc < 0)
                        err = -1; /* FIXME we let the loop complete (?) */
                    s->cur_request->data->size++;
                }
            }

            s->remaining -= num_chunks;
            available -= num_chunks * s->cur_request->data->in_element_size;
            s->roff += num_chunks * s->cur_request->data->in_element_size;
            if (s->remaining == 0) {
                if (hc_sock_map_remove(s->map, s->cur_request->seq, NULL) < 0) {
                    ERROR("[hc_sock_process] Error removing request from map");
                    return -1;
                }
                hc_data_set_complete(s->cur_request->data);
                if (data)
                    *data = s->cur_request->data;
                hc_sock_request_free(s->cur_request);
                s->cur_request = NULL;
            }

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

int
hc_sock_callback(hc_sock_t * s, hc_data_t ** pdata)
{
    hc_data_t * data;

    for (;;) {
        int n = hc_sock_recv(s);
        if (n == 0) {
            goto ERR_EOF;
        }
        if (n < 0) {
            switch(errno) {
                case ECONNRESET:
                case ENODEV:
                    /* Forwarder restarted */
                    WARN("Forwarder likely restarted: not (yet) implemented");
                    goto ERR;
                case EWOULDBLOCK:
                    //DEBUG("Would block... stop reading from socket");
                    goto END;
                default:
                    perror("hc_sock_recv");
                    goto ERR;
            }
        }
        if (hc_sock_process(s, &data) < 0) {
            goto ERR;
        }
    }
END:
    if (pdata)
        *pdata = data;
    else
        hc_data_free(data);
    return 0;

ERR:
    hc_data_free(data);
ERR_EOF:
    return -1;
}

int
hc_sock_reset(hc_sock_t * s)
{
    s->roff = s->woff = 0;
    s->remaining = 0;
     return 0;
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

int
hc_execute_command(hc_sock_t * s, hc_msg_t * msg, size_t msg_len,
        hc_command_params_t * params, hc_data_t ** pdata, bool async)
{
    if (async)
        assert(!pdata);

    /* Sanity check */
    switch(params->cmd) {
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
             return -1;
    }

    //hc_sock_reset(s);

    /* XXX data will at least store the result (complete) */
    hc_data_t * data = hc_data_create(params->size_in, params->size_out);
    if (!data) {
        ERROR("[hc_execute_command] Could not create data storage");
        goto ERR_DATA;
    }

    int seq = hc_sock_get_next_seq(s);
    if (seq < 0) {
        ERROR("[hc_execute_command] Could not get next sequence number");
        goto ERR_SEQ;
    }

    /* Create state used to process the request */
    hc_sock_request_t * request = NULL;
    request = hc_sock_request_create(seq, data, params->parse);
    if (!request) {
        ERROR("[hc_execute_command] Could not create request state");
        goto ERR_REQUEST;
    }

    /* Add state to map */
    if (hc_sock_map_add(s->map, seq, request) < 0) {
        ERROR("[hc_execute_command] Error adding request state to map");
        goto ERR_MAP;
    }

    if (hc_sock_send(s, msg, msg_len, seq) < 0) {
        ERROR("[hc_execute_command] Error sending message");
        goto ERR_PROCESS;
    }

    if (async)
        return 0;

    while(!data->complete) {
        /*
         * As the socket is non blocking it might happen that we need to read
         * several times before success... shall we alternate between blocking
         * and non-blocking mode ?
         */
        if (hc_sock_recv(s) < 0)
            continue; //break;
        if (hc_sock_process(s, pdata) < 0) {
            ERROR("[hc_execute_command] Error processing socket results");
            goto ERR_PROCESS;
        }
    }

    if (!pdata)
        hc_data_free(data);

    return data->ret;

ERR_PROCESS:
ERR_MAP:
    hc_sock_request_free(request);
ERR_REQUEST:
ERR_SEQ:
    hc_data_free(data);
ERR_DATA:
     return -1;
}

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

/* LISTENER CREATE */

int
_hc_listener_create(hc_sock_t * s, hc_listener_t * listener, bool async)
{
    if (!IS_VALID_FAMILY(listener->family))
         return -1;

    if (!IS_VALID_CONNECTION_TYPE(listener->type))
         return -1;

    struct {
        header_control_message hdr;
        add_listener_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = ADD_LISTENER,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = listener->local_addr,
            .port = htons(listener->local_port),
            .addressType = (u8)map_to_addr_type[listener->family],
            .listenerMode = (u8)map_to_listener_mode[listener->type],
            .connectionType = (u8)map_to_connection_type[listener->type],
        }
    };

    snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", listener->name);
    snprintf(msg.payload.interfaceName, INTERFACE_LEN, "%s", listener->interface_name);

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_LISTENER,
        .size_in = sizeof(add_listener_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_listener_create(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_create(s, listener, false);
}

int
hc_listener_create_async(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_create(s, listener, true);
}

/* LISTENER GET */

int
hc_listener_get(hc_sock_t * s, hc_listener_t * listener,
        hc_listener_t ** listener_found)
{
    hc_data_t * listeners;
    hc_listener_t * found;

    if (hc_listener_list(s, &listeners) < 0)
        return -1;

    /* Test */
    if (hc_listener_find(listeners, listener, &found) < 0) {
        hc_data_free(listeners);
        return -1;
    }

    if (found) {
        *listener_found = malloc(sizeof(hc_listener_t));
        if (!*listener_found)
            return -1;
        **listener_found = *found;
    } else {
        *listener_found = NULL;
    }

    hc_data_free(listeners);

    return 0;
}


/* LISTENER DELETE */

int
_hc_listener_delete(hc_sock_t * s, hc_listener_t * listener, bool async)
{
    struct {
        header_control_message hdr;
        remove_listener_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = REMOVE_LISTENER,
            .length = 1,
            .seqNum = 0,
        },
    };

    if (listener->id) {
        snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d", listener->id);
    } else if (*listener->name) {
        snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%s", listener->name);
    } else {
        hc_listener_t * listener_found;
        if (hc_listener_get(s, listener, &listener_found) < 0)
            return -1;
        if (!listener_found)
            return -1;
        snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d", listener_found->id);
        free(listener_found);
    }

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_LISTENER,
        .size_in = sizeof(remove_listener_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_listener_delete(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_delete(s, listener, false);
}

int
hc_listener_delete_async(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_delete(s, listener, true);
}


/* LISTENER LIST */

int
_hc_listener_list(hc_sock_t * s, hc_data_t ** pdata, bool async)
{
    struct {
        header_control_message hdr;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = LIST_LISTENERS,
            .length = 0,
            .seqNum = 0,
        },
    };

    hc_command_params_t params = {
        .cmd = ACTION_LIST,
        .cmd_id = LIST_LISTENERS,
        .size_in = sizeof(list_listeners_command),
        .size_out = sizeof(hc_listener_t),
        .parse = (HC_PARSE)hc_listener_parse,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

int
hc_listener_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_listener_list(s, pdata, false);
}

int
hc_listener_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_listener_list(s, pdata, true);
}

/* LISTENER VALIDATE */

int
hc_listener_validate(const hc_listener_t * listener)
{
    if (!IS_VALID_FAMILY(listener->family))
         return -1;

    if (!IS_VALID_CONNECTION_TYPE(listener->type))
         return -1;

    return 0;
}

/* LISTENER CMP */

int
hc_listener_cmp(const hc_listener_t * l1, const hc_listener_t * l2)
{
    return ((l1->type == l2->type) &&
            (l1->family == l2->family) &&
            (strncmp(l1->interface_name, l2->interface_name, INTERFACE_LEN) == 0) &&
            (ip_address_cmp(&l1->local_addr, &l2->local_addr, l1->family) == 0) &&
            (l1->local_port == l2->local_port))
        ? 0
        : -1;
}

/* LISTENER PARSE */

int
hc_listener_parse(void * in, hc_listener_t * listener)
{
    list_listeners_command * cmd = (list_listeners_command *)in;

    if (!IS_VALID_LIST_LISTENERS_TYPE(cmd->encapType))
         return -1;

    hc_connection_type_t type = map_from_encap_type[cmd->encapType];
    if (type == CONNECTION_TYPE_UNDEFINED)
         return -1;

    if (!IS_VALID_ADDR_TYPE(cmd->addressType))
         return -1;

    int family = map_from_addr_type[cmd->addressType];
    if (!IS_VALID_FAMILY(family))
         return -1;

    *listener = (hc_listener_t) {
        .id = cmd->connid,
        .type = type,
        .family = family,
        .local_addr = UNION_CAST(cmd->address, ip_address_t),
        .local_port = ntohs(cmd->port),
    };
    snprintf(listener->name, SYMBOLIC_NAME_LEN, "%s", cmd->listenerName);
    snprintf(listener->interface_name, INTERFACE_LEN, "%s", cmd->interfaceName);
    return 0;
}

GENERATE_FIND(listener)

/* LISTENER SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int
hc_listener_snprintf(char * s, size_t size, hc_listener_t * listener)
{
    char local[MAXSZ_URL];
    int rc;
    rc = url_snprintf(local, MAXSZ_URL,
         listener->family, &listener->local_addr, listener->local_port);
    if (rc < 0)
        return rc;

    return snprintf(s, size+17, "%s %s %s",
            listener->interface_name,
            local,
            connection_type_str[listener->type]);
}

/*----------------------------------------------------------------------------*
 * CONNECTION
 *----------------------------------------------------------------------------*/

/* CONNECTION CREATE */

int
_hc_connection_create(hc_sock_t * s, hc_connection_t * connection, bool async)
{
    if (hc_connection_validate(connection) < 0)
        return -1;

    struct {
        header_control_message hdr;
        add_connection_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = ADD_CONNECTION,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .remoteIp = connection->remote_addr,
            .localIp = connection->local_addr,
            .remotePort = htons(connection->remote_port),
            .localPort = htons(connection->local_port),
            .ipType = (u8)map_to_addr_type[connection->family],
            .connectionType = (u8)map_to_connection_type[connection->type],
            .admin_state = connection->admin_state,
#ifdef WITH_POLICY
            .tags = connection->tags,
#endif /* WITH_POLICY */
        }
    };
    snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", connection->name);

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_CONNECTION,
        .size_in = sizeof(add_connection_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_connection_create(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_create(s, connection, false);
}

int
hc_connection_create_async(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_create(s, connection, true);
}

/* CONNECTION GET */

int
hc_connection_get(hc_sock_t * s, hc_connection_t * connection,
        hc_connection_t ** connection_found)
{
    hc_data_t * connections;
    hc_connection_t * found;

    if (hc_connection_list(s, &connections) < 0)
        return -1;

    /* Test */
    if (hc_connection_find(connections, connection, &found) < 0) {
        hc_data_free(connections);
        return -1;
    }

    if (found) {
        *connection_found = malloc(sizeof(hc_connection_t));
        if (!*connection_found)
            return -1;
        **connection_found = *found;
    } else {
        *connection_found = NULL;
    }

    hc_data_free(connections);

    return 0;
}


/* CONNECTION DELETE */

int
_hc_connection_delete(hc_sock_t * s, hc_connection_t * connection, bool async)
{
    struct {
        header_control_message hdr;
        remove_connection_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = REMOVE_CONNECTION,
            .length = 1,
            .seqNum = 0,
        },
    };

    if (connection->id) {
        snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", connection->id);
    } else if (*connection->name) {
        snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", connection->name);
    } else {
        hc_connection_t * connection_found;
        if (hc_connection_get(s, connection, &connection_found) < 0)
            return -1;
        if (!connection_found)
            return -1;
        snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", connection_found->id);
        free(connection_found);
    }

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_CONNECTION,
        .size_in = sizeof(remove_connection_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_connection_delete(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_delete(s, connection, false);
}

int
hc_connection_delete_async(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_delete(s, connection, true);
}

/* CONNECTION LIST */

int
_hc_connection_list(hc_sock_t * s, hc_data_t ** pdata, bool async)
{
    struct {
        header_control_message hdr;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = LIST_CONNECTIONS,
            .length = 0,
            .seqNum = 0,
        },
    };

    hc_command_params_t params = {
        .cmd = ACTION_LIST,
        .cmd_id = LIST_CONNECTIONS,
        .size_in = sizeof(list_connections_command),
        .size_out = sizeof(hc_connection_t),
        .parse = (HC_PARSE)hc_connection_parse,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

int
hc_connection_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_connection_list(s, pdata, false);
}

int
hc_connection_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_connection_list(s, pdata, true);
}

/* CONNECTION VALIDATE */

int
hc_connection_validate(const hc_connection_t * connection)
{
    if (!IS_VALID_FAMILY(connection->family))
         return -1;

    if (!IS_VALID_CONNECTION_TYPE(connection->type))
         return -1;

    /* TODO assert both local and remote have the right family */

    return 0;
}

/* CONNECTION CMP */

/*
 * hICN light uses ports even for hICN connections, but their value is ignored.
 * As connections are specific to hicn-light, we can safely use IP and ports for
 * comparison independently of the face type.
 */
int hc_connection_cmp(const hc_connection_t * c1, const hc_connection_t * c2)
{
    return ((c1->type == c2->type) &&
            (c1->family == c2->family) &&
            (ip_address_cmp(&c1->local_addr, &c2->local_addr, c1->family) == 0) &&
            (c1->local_port == c2->local_port) &&
            (ip_address_cmp(&c1->remote_addr, &c2->remote_addr, c1->family) == 0) &&
            (c1->remote_port == c2->remote_port))
        ? 0
        : -1;
}

/* CONNECTION PARSE */

int
hc_connection_parse(void * in, hc_connection_t * connection)
{
    list_connections_command * cmd = (list_connections_command *)in;

    if (!IS_VALID_LIST_CONNECTIONS_TYPE(cmd->connectionData.connectionType))
         return -1;

    hc_connection_type_t type = map_from_list_connections_type[cmd->connectionData.connectionType];
    if (type == CONNECTION_TYPE_UNDEFINED)
         return -1;

    if (!IS_VALID_LIST_CONNECTIONS_STATE(cmd->state))
         return -1;

    hc_connection_state_t state = map_from_list_connections_state[cmd->state];
    if (state == HC_CONNECTION_STATE_UNDEFINED)
         return -1;

    if (!IS_VALID_ADDR_TYPE(cmd->connectionData.ipType))
         return -1;

    int family = map_from_addr_type[cmd->connectionData.ipType];
    if (!IS_VALID_FAMILY(family))
         return -1;

    *connection = (hc_connection_t) {
        .id = cmd->connid,
        .type = type,
        .family = family,
        .local_addr = cmd->connectionData.localIp,
        //.local_addr = UNION_CAST(cmd->connectionData.localIp, ip_address_t),
        .local_port = ntohs(cmd->connectionData.localPort),
        .remote_addr = cmd->connectionData.remoteIp,
        //.remote_addr = UNION_CAST(cmd->connectionData.remoteIp, ip_address_t),
        .remote_port = ntohs(cmd->connectionData.remotePort),
        .admin_state = cmd->connectionData.admin_state,
#ifdef WITH_POLICY
        .tags = cmd->connectionData.tags,
#endif /* WITH_POLICY */
        .state = state,
    };
    snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s", cmd->connectionData.symbolic);
    snprintf(connection->interface_name, INTERFACE_LEN, "%s", cmd->interfaceName);
    return 0;
}

GENERATE_FIND(connection)

/* CONNECTION SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int
hc_connection_snprintf(char * s, size_t size, const hc_connection_t * connection)
{
    char local[MAXSZ_URL];
    char remote[MAXSZ_URL];
    int rc;

    // assert(connection->connection_state)

    rc = url_snprintf(local, MAXSZ_URL, connection->family,
            &connection->local_addr, connection->local_port);
    if (rc < 0)
        return rc;
    rc = url_snprintf(remote, MAXSZ_URL, connection->family,
            &connection->remote_addr, connection->remote_port);
    if (rc < 0)
        return rc;

    return snprintf(s, size, "%s %s %s %s %s",
            connection_state_str[connection->state],
            connection->interface_name,
            local,
            remote,
            connection_type_str[connection->type]);
}

/* CONNECTION SET ADMIN STATE */

int
_hc_connection_set_admin_state(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t state, bool async)
{
    struct {
        header_control_message hdr;
        connection_set_admin_state_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = CONNECTION_SET_ADMIN_STATE,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .admin_state = state,
        },
    };
    snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", conn_id_or_name);

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CONNECTION_SET_ADMIN_STATE,
        .size_in = sizeof(connection_set_admin_state_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_connection_set_admin_state(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t state)
{
    return _hc_connection_set_admin_state(s, conn_id_or_name, state, false);
}

int
hc_connection_set_admin_state_async(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t state)
{
    return _hc_connection_set_admin_state(s, conn_id_or_name, state, true);
}

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

/* ROUTE CREATE */

int
_hc_route_create(hc_sock_t * s, hc_route_t * route, bool async)
{
    if (!IS_VALID_FAMILY(route->family))
         return -1;

    struct {
        header_control_message hdr;
        add_route_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = ADD_ROUTE,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = route->remote_addr,
            .cost = route->cost,
            .addressType = (u8)map_to_addr_type[route->family],
            .len = route->len,
        }
    };

    /*
     * The route commands expects the ID (or name that we don't use) as part of
     * the symbolicOrConnid attribute.
     */
    snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", route->face_id);

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_ROUTE,
        .size_in = sizeof(add_route_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_route_create(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_create(s, route, false);
}

int
hc_route_create_async(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_create(s, route, true);
}

/* ROUTE DELETE */

int
_hc_route_delete(hc_sock_t * s, hc_route_t * route, bool async)
{
    if (!IS_VALID_FAMILY(route->family))
         return -1;

    struct {
        header_control_message hdr;
        remove_route_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = REMOVE_ROUTE,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = route->remote_addr,
            .addressType = (u8)map_to_addr_type[route->family],
            .len = route->len,
        }
    };

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_ROUTE,
        .size_in = sizeof(remove_route_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_route_delete(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_delete(s, route, false);
}

int
hc_route_delete_async(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_delete(s, route, true);
}

/* ROUTE LIST */

int
_hc_route_list(hc_sock_t * s, hc_data_t ** pdata, bool async)
{
    struct {
        header_control_message hdr;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = LIST_ROUTES,
            .length = 0,
            .seqNum = 0,
        },
    };

    hc_command_params_t params = {
        .cmd = ACTION_LIST,
        .cmd_id = LIST_ROUTES,
        .size_in = sizeof(list_routes_command),
        .size_out = sizeof(hc_route_t),
        .parse = (HC_PARSE)hc_route_parse,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

int
hc_route_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_route_list(s, pdata, false);
}

int
hc_route_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_route_list(s, pdata, true);
}

/* ROUTE PARSE */

int
hc_route_parse(void * in, hc_route_t * route)
{
    list_routes_command * cmd = (list_routes_command *) in;

    if (!IS_VALID_ADDR_TYPE(cmd->addressType))
         return -1;

    int family = map_from_addr_type[cmd->addressType];
    if (!IS_VALID_FAMILY(family))
         return -1;

    *route = (hc_route_t) {
        .face_id = cmd->connid,
        .family = family,
        .remote_addr = UNION_CAST(cmd->address, ip_address_t),
        .len = cmd->len,
        .cost = cmd->cost,
    };
    return 0;
}

/* ROUTE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int
hc_route_snprintf(char * s, size_t size, hc_route_t * route)
{
    /* interface cost prefix length */

    char prefix[MAXSZ_IP_ADDRESS];
    int rc;

    rc = ip_address_snprintf(prefix, MAXSZ_IP_ADDRESS, &route->remote_addr,
            route->family);
    if (rc < 0)
        return rc;

    return snprintf(s, size, "%*d %*d %s %*d",
            MAXSZ_FACE_ID,
            route->face_id,
            MAXSZ_COST,
            route->cost,
            prefix,
            MAXSZ_LEN,
            route->len);
}

/*----------------------------------------------------------------------------*
 * Face
 *
 * Face support is not directly available in hicn-light, but we can offer such
 * an interface through a combination of listeners and connections. The code
 * starts with some conversion functions between faces/listeners/connections.
 *
 * We also need to make sure that there always exist a (single) listener when a
 * connection is created, and in the hICN face case, that there is a single
 * connection attached to this listener.
 *
 *----------------------------------------------------------------------------*/

/* FACE -> LISTENER */

int
hc_face_to_listener(const hc_face_t * face, hc_listener_t * listener)
{
    const face_t * f = &face->face;

    switch(f->type) {
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

int
hc_listener_to_face(const hc_listener_t * listener, hc_face_t * face)
{
    return -1; /* XXX Not implemented */
}

/* FACE -> CONNECTION */

int
hc_face_to_connection(const hc_face_t * face, hc_connection_t * connection, bool generate_name)
{
    const face_t * f = &face->face;

    switch(f->type) {
        case FACE_TYPE_HICN:
            *connection = (hc_connection_t) {
                .type = CONNECTION_TYPE_HICN,
                .family = f->family,
                .local_addr = f->local_addr,
                .local_port = 0,
                .remote_addr = f->remote_addr,
                .remote_port = 0,
                .admin_state = face_state_to_connection_state(f->admin_state),
                .state = face_state_to_connection_state(f->state),
#ifdef WITH_POLICY
                .tags = f->tags,
#endif /* WITH_POLICY */
            };
            snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s",
                    f->netdevice.name);
            snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                    f->netdevice.name);
            break;
        case FACE_TYPE_TCP:
            *connection = (hc_connection_t) {
                .type = CONNECTION_TYPE_TCP,
                .family = f->family,
                .local_addr = f->local_addr,
                .local_port = f->local_port,
                .remote_addr = f->remote_addr,
                .remote_port = f->remote_port,
                .admin_state = face_state_to_connection_state(f->admin_state),
                .state = face_state_to_connection_state(f->state),
#ifdef WITH_POLICY
                .tags = f->tags,
#endif /* WITH_POLICY */
            };
            if (generate_name) {
                snprintf(connection->name, SYMBOLIC_NAME_LEN, "tcp%u", RANDBYTE());
            } else {
                memset(connection->name, 0, SYMBOLIC_NAME_LEN);
            }
            snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                    f->netdevice.name);
            break;
        case FACE_TYPE_UDP:
            *connection = (hc_connection_t) {
                .type = CONNECTION_TYPE_UDP,
                .family = AF_INET,
                .local_addr = f->local_addr,
                .local_port = f->local_port,
                .remote_addr = f->remote_addr,
                .remote_port = f->remote_port,
                .admin_state = face_state_to_connection_state(f->admin_state),
                .state = face_state_to_connection_state(f->state),
#ifdef WITH_POLICY
                .tags = f->tags,
#endif /* WITH_POLICY */
            };
            if (generate_name) {
                snprintf(connection->name, SYMBOLIC_NAME_LEN, "udp%u", RANDBYTE());
            } else {
                memset(connection->name, 0, SYMBOLIC_NAME_LEN);
            }
            snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                    f->netdevice.name);
            break;
        default:
             return -1;
    }

    snprintf(connection->interface_name, INTERFACE_LEN, "%s",
            f->netdevice.name);

    return 0;
}

/* CONNECTION -> FACE */

int
hc_connection_to_face(const hc_connection_t * connection, hc_face_t * face)
{
    switch (connection->type) {
        case CONNECTION_TYPE_TCP:
            *face = (hc_face_t) {
                .id = connection->id,
                .face = {
                    .type = FACE_TYPE_TCP,
                    .family = connection->family,
                    .local_addr = connection->local_addr,
                    .local_port = connection->local_port,
                    .remote_addr = connection->remote_addr,
                    .remote_port = connection->remote_port,
                    .admin_state = connection_state_to_face_state(connection->admin_state),
                    .state = connection_state_to_face_state(connection->state),
#ifdef WITH_POLICY
                    .tags = connection->tags,
#endif /* WITH_POLICY */
                },
            };
            break;
        case CONNECTION_TYPE_UDP:
            *face = (hc_face_t) {
                .id = connection->id,
                .face = {
                    .type = FACE_TYPE_UDP,
                    .family = connection->family,
                    .local_addr = connection->local_addr,
                    .local_port = connection->local_port,
                    .remote_addr = connection->remote_addr,
                    .remote_port = connection->remote_port,
                    .admin_state = connection_state_to_face_state(connection->admin_state),
                    .state = connection_state_to_face_state(connection->state),
#ifdef WITH_POLICY
                    .tags = connection->tags,
#endif /* WITH_POLICY */
                },
            };
            break;
        case CONNECTION_TYPE_HICN:
            *face = (hc_face_t) {
                .id = connection->id,
                .face = {
                    .type = FACE_TYPE_HICN,
                    .family = connection->family,
                    .netdevice.index = NETDEVICE_UNDEFINED_INDEX, // XXX
                    .local_addr = connection->local_addr,
                    .remote_addr = connection->remote_addr,
                    .admin_state = connection_state_to_face_state(connection->admin_state),
                    .state = connection_state_to_face_state(connection->state),
#ifdef WITH_POLICY
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
    snprintf(face->name, SYMBOLIC_NAME_LEN, "%s", connection->name);
    snprintf(face->face.netdevice.name, INTERFACE_LEN, "%s", connection->interface_name);
    netdevice_update_index(&face->face.netdevice);
    return 0;
}

/* CONNECTION -> LISTENER */

int
hc_connection_to_local_listener(const hc_connection_t * connection, hc_listener_t * listener)
{
    *listener = (hc_listener_t) {
        .id = ~0,
        .type = connection->type,
        .family = connection->family,
        .local_addr = connection->local_addr,
        .local_port = connection->local_port,
    };
    snprintf(listener->name, SYMBOLIC_NAME_LEN, "lst%u", RANDBYTE()); // generate name
    snprintf(listener->interface_name, INTERFACE_LEN, "%s", connection->interface_name);
    return 0;
}

/* FACE CREATE */

int
hc_face_create(hc_sock_t * s, hc_face_t * face)
{
    hc_listener_t listener;
    hc_listener_t * listener_found;

    hc_connection_t connection;
    hc_connection_t * connection_found;

    switch(face->face.type)
    {
        case FACE_TYPE_HICN:
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            if (hc_face_to_connection(face, &connection, true) < 0) {
                ERROR("[hc_face_create] Could not convert face to connection.");
                return -1;
            }

            /* Ensure we have a corresponding local listener */
            if (hc_connection_to_local_listener(&connection, &listener) < 0) {
                ERROR("[hc_face_create] Could not convert face to local listener.");
                return -1;
            }

            if (hc_listener_get(s, &listener, &listener_found) < 0) {
                ERROR("[hc_face_create] Could not retrieve listener");
                return -1;
            }

            if (!listener_found) {
                /* We need to create the listener if it does not exist */
                if (hc_listener_create(s, &listener) < 0) {
                    ERROR("[hc_face_create] Could not create listener.");
                    free(listener_found);
                    return -1;
                }
            } else {
                free(listener_found);
            }

            /* Create corresponding connection */
            if (hc_connection_create(s, &connection) < 0) {
                ERROR("[hc_face_create] Could not create connection.");
                return -1;
            }

            /*
             * Once the connection is created, we need to list all connections
             * and compare with the current one to find the created face ID.
             */
            if (hc_connection_get(s, &connection, &connection_found) < 0) {
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
            if (hc_listener_create(s, &listener) < 0) {
                ERROR("[hc_face_create] Could not create listener.");
                return -1;
            }
            return -1;
            break;
        default:
            ERROR("[hc_face_create] Unknwon face type.");

            return -1;
    };

    return 0;
}

int
hc_face_get(hc_sock_t * s, hc_face_t * face, hc_face_t ** face_found)
{
    hc_listener_t listener;
    hc_listener_t * listener_found;

    hc_connection_t connection;
    hc_connection_t * connection_found;

    switch(face->face.type)
    {
        case FACE_TYPE_HICN:
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            if (hc_face_to_connection(face, &connection, false) < 0)
                 return -1;
            if (hc_connection_get(s, &connection, &connection_found) < 0)
                 return -1;
            if (!connection_found) {
                *face_found = NULL;
                return 0;
            }
            *face_found = malloc(sizeof(face_t));
            hc_connection_to_face(connection_found, *face_found);
            free(connection_found);
            break;

        case FACE_TYPE_HICN_LISTENER:
        case FACE_TYPE_TCP_LISTENER:
        case FACE_TYPE_UDP_LISTENER:
            if (hc_face_to_listener(face, &listener) < 0)
                 return -1;
            if (hc_listener_get(s, &listener, &listener_found) < 0)
                 return -1;
            if (!listener_found) {
                *face_found = NULL;
                return 0;
            }
            *face_found = malloc(sizeof(face_t));
            hc_listener_to_face(listener_found, *face_found);
            free(listener_found);
            break;

        default:
             return -1;
    }

    return 0;

}

/* FACE DELETE */

int
hc_face_delete(hc_sock_t * s, hc_face_t * face)
{
    hc_connection_t connection;
    if (hc_face_to_connection(face, &connection, false) < 0) {
        ERROR("[hc_face_delete] Could not convert face to connection.");
        return -1;
    }

    if (hc_connection_delete(s, &connection) < 0) {
        ERROR("[hc_face_delete] Error removing connection");
        return -1;
    }

    /* If this is the last connection attached to the listener, remove it */

    hc_data_t * connections;
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
    if (hc_connection_list(s, &connections) < 0) {
        ERROR("[hc_face_delete] Error getting the list of listeners");
        return -1;
    }

    bool delete = true;
    foreach_connection(c, connections) {
        if ((ip_address_cmp(&c->local_addr, &listener.local_addr, c->family) == 0) &&
            (c->local_port == listener.local_port) &&
                (strcmp(c->interface_name, listener.interface_name) == 0)) {
            delete = false;
        }
    }

    if (delete) {
        if (hc_listener_delete(s, &listener) < 0) {
            ERROR("[hc_face_delete] Error removing listener");
            return -1;
        }
    }

    hc_data_free(connections);

    return 0;


}

/* FACE LIST */

int
hc_face_list(hc_sock_t * s, hc_data_t ** pdata)
{
    hc_data_t * connection_data;
    hc_face_t face;

    if (hc_connection_list(s, &connection_data) < 0) {
        ERROR("[hc_face_list] Could not list connections.");
        return -1;
    }

    hc_data_t * face_data = hc_data_create(sizeof(hc_connection_t), sizeof(hc_face_t));
    foreach_connection(c, connection_data) {
        if (hc_connection_to_face(c, &face) < 0) {
            ERROR("[hc_face_list] Could not convert connection to face.");
            goto ERR;
        }
        hc_data_push(face_data, &face);
    }

    *pdata = face_data;
    hc_data_free(connection_data);
    return 0;

ERR:
    hc_data_free(connection_data);
    return -1;
}

int
hc_connection_parse_to_face(void * in, hc_face_t * face)
{
    hc_connection_t connection;

    if (hc_connection_parse(in, &connection) < 0) {
        ERROR("[hc_connection_parse_to_face] Could not parse connection");
        return -1;
    }

    if (hc_connection_to_face(&connection, face) < 0) {
        ERROR("[hc_connection_parse_to_face] Could not convert connection to face.");
        return -1;
    }

    return 0;
}


int
hc_face_list_async(hc_sock_t * s) //, hc_data_t ** pdata)
{
    struct {
        header_control_message hdr;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = LIST_CONNECTIONS,
            .length = 0,
            .seqNum = 0,
        },
    };

    hc_command_params_t params = {
        .cmd = ACTION_LIST,
        .cmd_id = LIST_CONNECTIONS,
        .size_in = sizeof(list_connections_command),
        .size_out = sizeof(hc_face_t),
        .parse = (HC_PARSE)hc_connection_parse_to_face,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, true);
}

/* /!\ Please update constants in header file upon changes */
int
hc_face_snprintf(char * s, size_t size, hc_face_t * face)
{
    /* URLs are also big enough to contain IP addresses in the hICN case */
    char local[MAXSZ_URL];
    char remote[MAXSZ_URL];
#ifdef WITH_POLICY
    char tags[MAXSZ_POLICY_TAGS];
#endif /* WITH_POLICY */
    int rc;

    switch(face->face.type) {
        case FACE_TYPE_HICN:
        case FACE_TYPE_HICN_LISTENER:
            rc = ip_address_snprintf(local, MAXSZ_URL,
                    &face->face.local_addr,
                    face->face.family);
            if (rc < 0)
                return rc;
            rc = ip_address_snprintf(remote, MAXSZ_URL,
                    &face->face.remote_addr,
                    face->face.family);
            if (rc < 0)
                return rc;
            break;
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
        case FACE_TYPE_TCP_LISTENER:
        case FACE_TYPE_UDP_LISTENER:
            rc = url_snprintf(local, MAXSZ_URL, face->face.family,
                    &face->face.local_addr,
                    face->face.local_port); if (rc < 0)
                return rc;
            rc = url_snprintf(remote, MAXSZ_URL, face->face.family,
                    &face->face.remote_addr,
                    face->face.remote_port); if (rc < 0)
            if (rc < 0)
                return rc;
            break;
        default:
            return -1;
    }

    // [#ID NAME] TYPE LOCAL_URL REMOTE_URL STATE/ADMIN_STATE (TAGS)
#ifdef WITH_POLICY
    rc = policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->face.tags);
    if (rc < 0)
        return rc;

    return snprintf(s, size, "[#%d %s] %s %s %s %s/%s (%s)",
            face->id,
            face->name,
            face_type_str[face->face.type],
            local,
            remote,
            face_state_str[face->face.state],
            face_state_str[face->face.admin_state],
            tags);
#else
    return snprintf(s, size, "[#%d %s] %s %s %s %s/%s",
            face->id,
            face->name,
            face_type_str[face->face.type],
            local,
            remote,
            face_state_str[face->face.state],
            face_state_str[face->face.admin_state]);
#endif /* WITH_POLICY */
    return 0;
}

int
hc_face_set_admin_state(hc_sock_t * s, const char * conn_id_or_name, // XXX wrong identifier
        face_state_t admin_state)
{
    return hc_connection_set_admin_state(s, conn_id_or_name, admin_state);
}

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

int
_hc_punting_create(hc_sock_t * s, hc_punting_t * punting, bool async)
{
    if (hc_punting_validate(punting) < 0)
        return -1;

    struct {
        header_control_message hdr;
        add_punting_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = ADD_PUNTING,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = punting->prefix,
            .addressType = (u8)map_to_addr_type[punting->family],
            .len = punting->prefix_len,
        }
    };
    snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", punting->face_id);

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_PUNTING,
        .size_in = sizeof(add_punting_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_punting_create(hc_sock_t * s, hc_punting_t * punting)
{
    return _hc_punting_create(s, punting, false);
}

int
hc_punting_create_async(hc_sock_t * s, hc_punting_t * punting)
{
    return _hc_punting_create(s, punting, true);
}

int hc_punting_get(hc_sock_t * s, hc_punting_t * punting, hc_punting_t ** punting_found)
{
    ERROR("hc_punting_get not (yet) implemented.");
    return -1;
}

int hc_punting_delete(hc_sock_t * s, hc_punting_t * punting)
{
    ERROR("hc_punting_delete not (yet) implemented.");
    return -1;
}

int hc_punting_list(hc_sock_t * s, hc_data_t ** pdata)
{
    ERROR("hc_punting_list not (yet) implemented.");
    return -1;
}

int hc_punting_validate(const hc_punting_t * punting)
{
    if (!IS_VALID_FAMILY(punting->family))
         return -1;

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

int hc_punting_cmp(const hc_punting_t * p1, const hc_punting_t * p2)
{
    return ((p1->face_id == p2->face_id) &&
            (p1->family == p2->family) &&
            (ip_address_cmp(&p1->prefix, &p2->prefix, p1->family) == 0) &&
            (p1->prefix_len == p2->prefix_len))
        ? 0
        : -1;
}

int hc_punting_parse(void * in, hc_punting_t * punting)
{
    ERROR("hc_punting_parse not (yet) implemented.");
    return -1;
}

int hc_punting_snprintf(char * s, size_t size, hc_punting_t * punting)
{
    ERROR("hc_punting_snprintf not (yet) implemented.");
    return -1;
}


/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int
_hc_cache_set_store(hc_sock_t * s, int enabled, bool async)
{
    struct {
        header_control_message hdr;
        cache_store_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = CACHE_STORE,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .activate = enabled,
        }
    };

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CACHE_STORE,
        .size_in = sizeof(cache_store_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_cache_set_store(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_store(s, enabled, false);
}

int
hc_cache_set_store_async(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_store(s, enabled, true);
}

int
_hc_cache_set_serve(hc_sock_t * s, int enabled, bool async)
{
    struct {
        header_control_message hdr;
        cache_serve_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = CACHE_SERVE,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .activate = enabled,
        }
    };

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CACHE_SERVE,
        .size_in = sizeof(cache_serve_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_cache_set_serve(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_serve(s, enabled, false);
}

int
hc_cache_set_serve_async(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_serve(s, enabled, true);
}

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
int
hc_strategy_set(hc_sock_t * s /* XXX */)
{
     return 0;
}

/* How to retrieve that from the forwarder ? */
static const char * strategies[] = {
    "random",
    "load_balancer",
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

int
hc_strategy_list(hc_sock_t * s, hc_data_t ** data)
{
    *data = hc_data_create(0, sizeof(hc_strategy_t));

    for (unsigned i = 0; i < ARRAY_SIZE(strategies); i++) {
        hc_strategy_t * strategy = (hc_strategy_t*)hc_data_get_next(*data);
        if (!strategy)
             return -1;
        snprintf(strategy->name, MAXSZ_HC_STRATEGY, "%s", strategies[i]);
        (*data)->size++;
    }

    return 0;
}

/* /!\ Please update constants in header file upon changes */
int
hc_strategy_snprintf(char * s, size_t size, hc_strategy_t * strategy)
{
    return snprintf(s, size, "%s", strategy->name);
}

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
int
hc_wldr_set(hc_sock_t * s /* XXX */)
{
     return 0;
}

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

int
hc_mapme_set(hc_sock_t * s, int enabled)
{
     return 0;
}

int
hc_mapme_set_discovery(hc_sock_t * s, int enabled)
{
     return 0;
}

int
hc_mapme_set_timescale(hc_sock_t * s, double timescale)
{
     return 0;
}

int
hc_mapme_set_retx(hc_sock_t * s, double timescale)
{
     return 0;
}

/*----------------------------------------------------------------------------*
 * Policy
 *----------------------------------------------------------------------------*/

#ifdef WITH_POLICY

/* POLICY CREATE */

int
_hc_policy_create(hc_sock_t * s, hc_policy_t * policy, bool async)
{
    if (!IS_VALID_FAMILY(policy->family))
         return -1;

    struct {
        header_control_message hdr;
        add_policy_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = ADD_POLICY,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = policy->remote_addr,
            .addressType = (u8)map_to_addr_type[policy->family],
            .len = policy->len,
            .policy = policy->policy,
        }
    };

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_POLICY,
        .size_in = sizeof(add_policy_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_policy_create(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_create(s, policy, false);
}

int
hc_policy_create_async(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_create(s, policy, true);
}

/* POLICY DELETE */

int
_hc_policy_delete(hc_sock_t * s, hc_policy_t * policy, bool async)
{
    if (!IS_VALID_FAMILY(policy->family))
         return -1;

    struct {
        header_control_message hdr;
        remove_policy_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = REMOVE_POLICY,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .address = policy->remote_addr,
            .addressType = (u8)map_to_addr_type[policy->family],
            .len = policy->len,
        }
    };

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_POLICY,
        .size_in = sizeof(remove_policy_command),
        .size_out = 0,
        .parse = NULL,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

int
hc_policy_delete(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_delete(s, policy, false);
}

int
hc_policy_delete_async(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_delete(s, policy, true);
}

/* POLICY LIST */

int
_hc_policy_list(hc_sock_t * s, hc_data_t ** pdata, bool async)
{
    struct {
        header_control_message hdr;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = LIST_POLICIES,
            .length = 0,
            .seqNum = 0,
        },
    };

    hc_command_params_t params = {
        .cmd = ACTION_LIST,
        .cmd_id = LIST_POLICIES,
        .size_in = sizeof(list_policies_command),
        .size_out = sizeof(hc_policy_t),
        .parse = (HC_PARSE)hc_policy_parse,
    };

    return hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

int
hc_policy_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_policy_list(s, pdata, false);
}

int
hc_policy_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_policy_list(s, pdata, true);
}

/* POLICY PARSE */

int
hc_policy_parse(void * in, hc_policy_t * policy)
{
    list_policies_command * cmd = (list_policies_command *) in;

    if (!IS_VALID_ADDR_TYPE(cmd->addressType))
         return -1;

    int family = map_from_addr_type[cmd->addressType];
    if (!IS_VALID_FAMILY(family))
         return -1;

    *policy = (hc_policy_t) {
        .family = family,
        .remote_addr = UNION_CAST(cmd->address, ip_address_t),
        .len = cmd->len,
        .policy = cmd->policy,
    };
    return 0;
}

/* POLICY SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int
hc_policy_snprintf(char * s, size_t size, hc_policy_t * policy)
{
     return 0;
}

#endif /* WITH_POLICY */
