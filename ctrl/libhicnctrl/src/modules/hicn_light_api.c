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

#include "api_private.h"

#include <assert.h> // assert
#include <stdbool.h>
#include <stdio.h> // snprintf
#include <string.h> // memmove, strcasecmp
#include <sys/socket.h> // socket
#include <unistd.h> // close, fcntl
#include <fcntl.h> // fcntl
#include <sys/types.h> // getpid
#include <unistd.h>    // getpid
#ifdef __linux__
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif /* __linux__ */
#include <strings.h>

#define PORT 9695

#define BOOLSTR(x) ((x) ? "true" : "false")

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

struct hc_sock_light_s {
    /* This must be the first element of the struct */
    hc_sock_t vft;

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

typedef struct hc_sock_light_s hc_sock_light_t;

#define TO_HC_SOCK_LIGHT(s) (hc_sock_light_t*)(s)

hc_sock_request_t *
hc_sock_request_create(int seq, hc_data_t * data, HC_PARSE parse)
{
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
hc_sock_light_request_free(hc_sock_request_t * request)
{
    free(request);
}

/*
 * list was working with all seq set to 0, but it seems hicnLightControl uses
 * 1, and replies with the same seqno
 */
#define HICN_CTRL_SEND_SEQ_INIT 1
#define HICN_CTRL_RECV_SEQ_INIT 1

#define MAX(x, y) ((x > y) ? x : y)

/**
 * In practise, we want to preserve enough room to store a full packet of
 * average expected size (say a header + N payload elements).
 */
#define AVG_ELEMENTS (1 << DEFAULT_SIZE_LOG)
#define AVG_BUFLEN (sizeof(hc_msg_header_t) + AVG_ELEMENTS * sizeof(hc_msg_payload_t))

/*
 * We should at least have buffer space allowing to store one processable unit
 * of data, either the header of the maximum possible payload
 */
#define MIN_BUFLEN MAX(sizeof(hc_msg_header_t), sizeof(hc_msg_payload_t))

static const struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

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
 * Control socket
 ******************************************************************************/

/**
 * \brief Parse a connection URL into a sockaddr
 * \param [in] url - URL
 * \param [out] sa - Resulting struct sockaddr, expected zero'ed.
 * \return 0 if parsing succeeded, a negative error value otherwise.
 */
static int
_hc_sock_light_parse_url(const char * url, struct sockaddr * sa)
{
    /* FIXME URL parsing is currently not implemented */
    assert(!url);

#ifdef __linux__
    srand(time(NULL) ^ getpid() ^ gettid());
#else
    srand((unsigned int )(time(NULL) ^ getpid()));
#endif /* __linux__ */

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

static int
_hc_sock_light_reset(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    s->roff = s->woff = 0;
    s->remaining = 0;
    return 0;
}

void
_hc_sock_light_free(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    hc_sock_request_t ** request_array = NULL;
    int n = hc_sock_map_get_value_array(s->map, &request_array);
    if (n < 0) {
       ERROR("Could not retrieve pending request array for freeing up resources");
    } else {
        for (unsigned i = 0; i < n; i++) {
            hc_sock_request_t * request = request_array[i];
            if (hc_sock_map_remove(s->map, request->seq, NULL) < 0)
                ERROR("[hc_sock_light_process] Error removing request from map");
            hc_sock_light_request_free(request);
        }
        free(request_array);
    }

    hc_sock_map_free(s->map);
    if (s->url)
        free(s->url);
    close(s->fd);
    free(s);
}

static int
_hc_sock_light_get_next_seq(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    return s->seq++;
}

static int
_hc_sock_light_set_nonblocking(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    return (fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL) | O_NONBLOCK) < 0);
}

static int
_hc_sock_light_get_fd(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    return s->fd;
}

static int
_hc_sock_light_connect(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(struct sockaddr_storage));

    if (_hc_sock_light_parse_url(s->url, (struct sockaddr *)&ss) < 0)
        goto ERR_PARSE;

    size_t size = ss.ss_family == AF_INET
        ? sizeof(struct sockaddr_in)
        : sizeof(struct sockaddr_in6);
    if (connect(s->fd, (struct sockaddr *)&ss, (socklen_t)size) < 0) //sizeof(struct sockaddr)) < 0)
        goto ERR_CONNECT;

     return 0;

ERR_CONNECT:
ERR_PARSE:
     return -1;
}

static int
_hc_sock_light_send(hc_sock_t * socket, hc_msg_t * msg, size_t msglen, int seq)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    int rc;
    msg->hdr.seqNum = seq;
    rc = (int)send(s->fd, msg, msglen, 0);
    if (rc < 0) {
        perror("hc_sock_light_send");
        return -1;
    }
    return 0;
}

static int
_hc_sock_light_get_available(hc_sock_t * socket, u8 ** buffer, size_t * size)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    *buffer = s->buf + s->woff;
    *size = RECV_BUFLEN - s->woff;

     return 0;
}

static int
_hc_sock_light_recv(hc_sock_t * socket)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    int rc;

    /*
     * This condition should be ensured to guarantee correct processing of
     * messages
     */
    assert(RECV_BUFLEN - s->woff > MIN_BUFLEN);

    rc = (int)recv(s->fd, s->buf + s->woff, RECV_BUFLEN - s->woff, 0);
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
        perror("hc_sock_light_recv");
        return -1;
    }
    s->woff += rc;
    return rc;
}

/*
 * Returns -99 in case of internal error, -1 in case of API command failure
 */
static int
_hc_sock_light_process(hc_sock_t * socket, hc_data_t ** data)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    int err = 0;

    /* We must have received at least one byte */
    size_t available = s->woff - s->roff;

    while(available > 0) {

        if (!s->cur_request) { // No message being parsed, alternatively (remaining == 0)
            hc_msg_t * msg = (hc_msg_t*)(s->buf + s->roff);

            /* We expect a message header */
            if (available < sizeof(hc_msg_header_t)) {
                break;
            }

            hc_sock_request_t * request = NULL;
            if (hc_sock_map_get(s->map, msg->hdr.seqNum, &request) < 0) {
                ERROR("[hc_sock_light_process] Error searching for matching request");
                return -99;
            }
            if (!request) {
                ERROR("[hc_sock_light_process] No request matching received sequence number");
                return -99;
            }

            s->remaining = msg->hdr.length;
            switch(msg->hdr.messageType) {
                case ACK_LIGHT:
                    assert(s->remaining == 1);
                    assert(!data);
                    s->cur_request = request;
                    break;
                case NACK_LIGHT:
                    assert(s->remaining == 1);
                    assert(!data);
                    hc_data_set_error(request->data);
                    s->cur_request = request;
                    err = -1;
                    break;
                case RESPONSE_LIGHT:
                    assert(data);
                    if (s->remaining == 0) {
                        hc_data_set_complete(request->data);
                        *data = request->data;
                        if (hc_sock_map_remove(s->map, request->seq, NULL) < 0)
                            ERROR("[hc_sock_light_process] Error removing request from map");
                        hc_sock_light_request_free(request);
                    } else {
                        /* We only remember it if there is still data to parse */
                        s->cur_request = request;
                    }
                    break;
                default:
                    ERROR("[hc_sock_light_process] Invalid response received");
                    return -99;
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
                if (rc < 0) {
                    ERROR("[hc_sock_light_process] Error in hc_data_ensure_available");
                    return -99;
                }
                for (int i = 0; i < num_chunks; i++) {
                    u8 * dst = hc_data_get_next(s->cur_request->data);
                    if (!dst) {
                        ERROR("[hc_sock_light_process] Error in hc_data_get_next");
                        return -99;
                    }

                    rc = s->cur_request->parse(s->buf + s->roff + i * s->cur_request->data->in_element_size, dst);
                    if (rc < 0) {
                        ERROR("[hc_sock_light_process] Error in parse");
                        err = -99; /* FIXME we let the loop complete (?) */
                    }
                    s->cur_request->data->size++;
                }
            }

            s->remaining -= num_chunks;
            available -= num_chunks * s->cur_request->data->in_element_size;
            s->roff += num_chunks * s->cur_request->data->in_element_size;
            if (s->remaining == 0) {
                if (hc_sock_map_remove(s->map, s->cur_request->seq, NULL) < 0) {
                    ERROR("[hc_sock_light_process] Error removing request from map");
                    return -99;
                }
                hc_data_set_complete(s->cur_request->data);
                if (data)
                    *data = s->cur_request->data;
                hc_sock_light_request_free(s->cur_request);
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

static int
_hc_sock_light_callback(hc_sock_t * socket, hc_data_t ** pdata)
{
    hc_data_t * data;

    for (;;) {
        int n = _hc_sock_light_recv(socket);
        if (n == 0)
            goto ERR_EOF;
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
                    perror("hc_sock_light_recv");
                    goto ERR;
            }
        }
        if (_hc_sock_light_process(socket, &data) < 0) {
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

static int
_hc_execute_command(hc_sock_t * socket, hc_msg_t * msg, size_t msg_len,
        hc_command_params_t * params, hc_data_t ** pdata, bool async)
{
    hc_sock_light_t *s = TO_HC_SOCK_LIGHT(socket);
    int ret;
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

    //hc_sock_light_reset(s);

    /* XXX data will at least store the result (complete) */
    hc_data_t * data = hc_data_create(params->size_in, params->size_out, NULL);
    if (!data) {
        ERROR("[_hc_execute_command] Could not create data storage");
        goto ERR_DATA;
    }

    int seq = _hc_sock_light_get_next_seq(socket);

    /* Create state used to process the request */
    hc_sock_request_t * request = NULL;
    request = hc_sock_request_create(seq, data, params->parse);
    if (!request) {
        ERROR("[_hc_execute_command] Could not create request state");
        goto ERR_REQUEST;
    }

    /* Add state to map */
    if (hc_sock_map_add(s->map, seq, request) < 0) {
        ERROR("[_hc_execute_command] Error adding request state to map");
        goto ERR_MAP;
    }

    if (_hc_sock_light_send(socket, msg, msg_len, seq) < 0) {
        ERROR("[_hc_execute_command] Error sending message");
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
        int n = _hc_sock_light_recv(socket);
        if (n == 0)
            goto ERR_EOF;
        if (n < 0)
            continue; //break;
        int rc = _hc_sock_light_process(socket, pdata);
        switch(rc) {
            case 0:
                break;
            case -1:
                ret = rc;
                break;
            case -99:
                ERROR("[_hc_execute_command] Error processing socket results");
                goto ERR;
                break;
            default:
                ERROR("[_hc_execute_command] Unexpected return value");
                goto ERR;
        }
    }

ERR_EOF:
    ret = data->ret;
    if (!data->complete)
        return -1;
    if (!pdata)
        hc_data_free(data);

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

static int
_hc_listener_create_internal(hc_sock_t * socket, hc_listener_t * listener, bool async)
{
    char listener_s[MAXSZ_HC_LISTENER];
    int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
    if (rc >= MAXSZ_HC_LISTENER)
        WARN("[_hc_listener_create] Unexpected truncation of listener string");
    DEBUG("[_hc_listener_create] listener=%s async=%s", listener_s,
            BOOLSTR(async));

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

    rc = snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", listener->name);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_listener_create] Unexpected truncation of symbolic name string");

    rc = snprintf(msg.payload.interfaceName, INTERFACE_LEN, "%s", listener->interface_name);
    if (rc >= INTERFACE_LEN)
        WARN("[_hc_listener_create] Unexpected truncation of interface name string");

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_LISTENER,
        .size_in = sizeof(add_listener_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_listener_create(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_create_internal(s, listener, false);
}

static int
_hc_listener_create_async(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_create_internal(s, listener, true);
}

/* LISTENER LIST */

static int
_hc_listener_list_internal(hc_sock_t * socket, hc_data_t ** pdata, bool async)
{
    DEBUG("[hc_listener_list] async=%s", BOOLSTR(async));

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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

static int
_hc_listener_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_listener_list_internal(s, pdata, false);
}

static int
_hc_listener_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_listener_list_internal(s, pdata, true);
}

/* LISTENER GET */

static int
_hc_listener_get(hc_sock_t * socket, hc_listener_t * listener,
        hc_listener_t ** listener_found)
{
    hc_data_t * listeners;
    hc_listener_t * found;

    char listener_s[MAXSZ_HC_LISTENER];
    int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
    if (rc >= MAXSZ_HC_LISTENER)
        WARN("[hc_listener_get] Unexpected truncation of listener string");
    DEBUG("[hc_listener_get] listener=%s", listener_s);

    if (_hc_listener_list(socket, &listeners) < 0)
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

static int
_hc_listener_delete_internal(hc_sock_t * socket, hc_listener_t * listener, bool async)
{
    char listener_s[MAXSZ_HC_LISTENER];
    int rc = hc_listener_snprintf(listener_s, MAXSZ_HC_LISTENER, listener);
    if (rc >= MAXSZ_HC_LISTENER)
        WARN("[_hc_listener_delete] Unexpected truncation of listener string");
    DEBUG("[_hc_listener_delete] listener=%s async=%s", listener_s,
            BOOLSTR(async));

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
        rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d", listener->id);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_listener_delete] Unexpected truncation of symbolic name string");
    } else if (*listener->name) {
        rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%s", listener->name);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_listener_delete] Unexpected truncation of symbolic name string");
    } else {
        hc_listener_t * listener_found;
        if (_hc_listener_get(socket, listener, &listener_found) < 0)
            return -1;
        if (!listener_found)
            return -1;
        rc = snprintf(msg.payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d", listener_found->id);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_listener_delete] Unexpected truncation of symbolic name string");
        free(listener_found);
    }

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_LISTENER,
        .size_in = sizeof(remove_listener_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_listener_delete(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_delete_internal(s, listener, false);
}

static int
_hc_listener_delete_async(hc_sock_t * s, hc_listener_t * listener)
{
    return _hc_listener_delete_internal(s, listener, true);
}

/*----------------------------------------------------------------------------*
 * CONNECTION
 *----------------------------------------------------------------------------*/

/* CONNECTION CREATE */

static int
_hc_connection_create_internal(hc_sock_t * socket, hc_connection_t * connection, bool async)
{
    char connection_s[MAXSZ_HC_CONNECTION];
    int rc = hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
    if (rc >= MAXSZ_HC_CONNECTION)
        WARN("[_hc_connection_create] Unexpected truncation of connection string");
    DEBUG("[_hc_connection_create] connection=%s async=%s", connection_s, BOOLSTR(async));

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
            .priority = connection->priority,
            .tags = connection->tags,
#endif /* WITH_POLICY */
        }
    };
    rc = snprintf(msg.payload.symbolic, SYMBOLIC_NAME_LEN, "%s", connection->name);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_connection_create] Unexpected truncation of symbolic name string");
    //snprintf(msg.payload.interfaceName, INTERFACE_NAME_LEN, "%s", connection->interface_name);

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_CONNECTION,
        .size_in = sizeof(add_connection_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_connection_create(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_create_internal(s, connection, false);
}

static int
_hc_connection_create_async(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_create_internal(s, connection, true);
}

/* CONNECTION LIST */

static int
_hc_connection_list_internal(hc_sock_t * socket, hc_data_t ** pdata, bool async)
{
    DEBUG("[hc_connection_list] async=%s", BOOLSTR(async));

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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

static int
_hc_connection_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_connection_list_internal(s, pdata, false);
}

static int
_hc_connection_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_connection_list_internal(s, pdata, true);
}

/* CONNECTION GET */

static int
_hc_connection_get(hc_sock_t * socket, hc_connection_t * connection,
        hc_connection_t ** connection_found)
{
    hc_data_t * connections;
    hc_connection_t * found;

    char connection_s[MAXSZ_HC_CONNECTION];
    int rc = hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
    if (rc >= MAXSZ_HC_CONNECTION)
        WARN("[hc_connection_get] Unexpected truncation of connection string");
    DEBUG("[hc_connection_get] connection=%s", connection_s);

    if (_hc_connection_list(socket, &connections) < 0)
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

static int
_hc_connection_delete_internal(hc_sock_t * socket, hc_connection_t * connection, bool async)
{
    char connection_s[MAXSZ_HC_CONNECTION];
    int rc = hc_connection_snprintf(connection_s, MAXSZ_HC_CONNECTION, connection);
    if (rc >= MAXSZ_HC_CONNECTION)
        WARN("[_hc_connection_delete] Unexpected truncation of connection string");
    DEBUG("[_hc_connection_delete] connection=%s async=%s", connection_s, BOOLSTR(async));

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
        rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", connection->id);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_connection_delete] Unexpected truncation of symbolic name string");
    } else if (*connection->name) {
        rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", connection->name);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_connection_delete] Unexpected truncation of symbolic name string");
    } else {
        hc_connection_t * connection_found;
        if (_hc_connection_get(socket, connection, &connection_found) < 0)
            return -1;
        if (!connection_found)
            return -1;
        rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", connection_found->id);
        if (rc >= SYMBOLIC_NAME_LEN)
            WARN("[_hc_connection_delete] Unexpected truncation of symbolic name string");
        free(connection_found);
    }

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_CONNECTION,
        .size_in = sizeof(remove_connection_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_connection_delete(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_delete_internal(s, connection, false);
}

static int
_hc_connection_delete_async(hc_sock_t * s, hc_connection_t * connection)
{
    return _hc_connection_delete_internal(s, connection, true);
}

static int
_hc_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                            hc_connection_t *connection)
{
    // Not implemented
    return -1;
}

static int
_hc_connection_update(hc_sock_t *s, hc_connection_t *connection_current,
                      hc_connection_t *connection_updated)
{
    // Not implemented
    return -1;
}

/* CONNECTION SET ADMIN STATE */

static int
_hc_connection_set_admin_state_internal(hc_sock_t * socket, const char * conn_id_or_name,
        face_state_t state, bool async)
{
    int rc;
    DEBUG("[hc_connection_set_admin_state] connection_id/name=%s admin_state=%s async=%s",
            conn_id_or_name, face_state_str[state], BOOLSTR(async));
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
    rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", conn_id_or_name);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_connection_set_admin_state] Unexpected truncation of symbolic name string");

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CONNECTION_SET_ADMIN_STATE,
        .size_in = sizeof(connection_set_admin_state_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_connection_set_admin_state(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t state)
{
    return _hc_connection_set_admin_state_internal(s, conn_id_or_name, state, false);
}

static int
_hc_connection_set_admin_state_async(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t state)
{
    return _hc_connection_set_admin_state_internal(s, conn_id_or_name, state, true);
}

#ifdef WITH_POLICY

static int
_hc_connection_set_priority_internal(hc_sock_t * socket, const char * conn_id_or_name,
        uint32_t priority, bool async)
{
    int rc;
    DEBUG("[hc_connection_set_priority] connection_id/name=%s priority=%d async=%s",
            conn_id_or_name, priority, BOOLSTR(async));
    struct {
        header_control_message hdr;
        connection_set_priority_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = CONNECTION_SET_PRIORITY,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .priority = priority,
        },
    };
    rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", conn_id_or_name);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_connection_set_priority] Unexpected truncation of symbolic name string");

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CONNECTION_SET_PRIORITY,
        .size_in = sizeof(connection_set_priority_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_connection_set_priority(hc_sock_t * s, const char * conn_id_or_name,
        uint32_t priority)
{
    return _hc_connection_set_priority_internal(s, conn_id_or_name, priority, false);
}

static int
_hc_connection_set_priority_async(hc_sock_t * s, const char * conn_id_or_name,
        uint32_t priority)
{
    return _hc_connection_set_priority_internal(s, conn_id_or_name, priority, true);
}

#endif // WITH_POLICY

static int
_hc_connection_set_tags_internal(hc_sock_t * s, const char * conn_id_or_name,
        policy_tags_t tags, bool async)
{
    int rc;
    DEBUG("[hc_connection_set_tags] connection_id/name=%s tags=%d async=%s",
            conn_id_or_name, tags, BOOLSTR(async));
    struct {
        header_control_message hdr;
        connection_set_tags_command payload;
    } msg = {
        .hdr = {
            .messageType = REQUEST_LIGHT,
            .commandID = CONNECTION_SET_TAGS,
            .length = 1,
            .seqNum = 0,
        },
        .payload = {
            .tags = tags,
        },
    };
    rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%s", conn_id_or_name);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_connection_set_tags] Unexpected truncation of symbolic name string");

    hc_command_params_t params = {
        .cmd = ACTION_SET,
        .cmd_id = CONNECTION_SET_TAGS,
        .size_in = sizeof(connection_set_tags_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(s, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_connection_set_tags(hc_sock_t * s, const char * conn_id_or_name,
        policy_tags_t tags)
{
    return _hc_connection_set_tags_internal(s, conn_id_or_name, tags, false);
}

static int
_hc_connection_set_tags_async(hc_sock_t * s, const char * conn_id_or_name,
        policy_tags_t tags)
{
    return _hc_connection_set_tags_internal(s, conn_id_or_name, tags, true);
}

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

/* ROUTE CREATE */

static int
_hc_route_create_internal(hc_sock_t * socket, hc_route_t * route, bool async)
{
    char route_s[MAXSZ_HC_ROUTE];
    int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, route);
    if (rc >= MAXSZ_HC_ROUTE)
        WARN("[_hc_route_create] Unexpected truncation of route string");
    if (rc < 0)
        WARN("[_hc_route_create] Error building route string");
    else
        DEBUG("[hc_route_create] route=%s async=%s", route_s, BOOLSTR(async));

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
    rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", route->face_id);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_route_create] Unexpected truncation of symbolic name string");

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_ROUTE,
        .size_in = sizeof(add_route_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_route_create(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_create_internal(s, route, false);
}

static int
_hc_route_create_async(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_create_internal(s, route, true);
}

/* ROUTE DELETE */

static int
_hc_route_delete_internal(hc_sock_t * socket, hc_route_t * route, bool async)
{
    char route_s[MAXSZ_HC_ROUTE];
    int rc = hc_route_snprintf(route_s, MAXSZ_HC_ROUTE, route);
    if (rc >= MAXSZ_HC_ROUTE)
        WARN("[_hc_route_delete] Unexpected truncation of route string");
    DEBUG("[hc_route_delete] route=%s async=%s", route_s, BOOLSTR(async));

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

    /*
     * The route commands expects the ID (or name that we don't use) as part of
     * the symbolicOrConnid attribute.
     */
    snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", route->face_id);

    hc_command_params_t params = {
        .cmd = ACTION_DELETE,
        .cmd_id = REMOVE_ROUTE,
        .size_in = sizeof(remove_route_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_route_delete(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_delete_internal(s, route, false);
}

static int
_hc_route_delete_async(hc_sock_t * s, hc_route_t * route)
{
    return _hc_route_delete_internal(s, route, true);
}

/* ROUTE LIST */

static int
_hc_route_list_internal(hc_sock_t * socket, hc_data_t ** pdata, bool async)
{
    //DEBUG("[hc_route_list] async=%s", BOOLSTR(async));

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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

static int
_hc_route_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_route_list_internal(s, pdata, false);
}

static int
_hc_route_list_async(hc_sock_t * s)
{
    return _hc_route_list_internal(s, NULL, true);
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

/* FACE CREATE */

static int
_hc_face_create(hc_sock_t * socket, hc_face_t * face)
{
    hc_listener_t listener;
    hc_listener_t * listener_found;

    hc_connection_t connection;
    hc_connection_t * connection_found;

    char face_s[MAXSZ_HC_FACE];
    int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
    if (rc >= MAXSZ_HC_FACE)
        WARN("[hc_face_create] Unexpected truncation of face string");
    DEBUG("[hc_face_create] face=%s", face_s);

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

            if (_hc_listener_get(socket, &listener, &listener_found) < 0) {
                ERROR("[hc_face_create] Could not retrieve listener");
                return -1;
            }

            if (!listener_found) {
                /* We need to create the listener if it does not exist */
                if (_hc_listener_create(socket, &listener) < 0) {
                    ERROR("[hc_face_create] Could not create listener.");
                    free(listener_found);
                    return -1;
                }
            } else {
                free(listener_found);
            }

            /* Create corresponding connection */
            if (_hc_connection_create(socket, &connection) < 0) {
                ERROR("[hc_face_create] Could not create connection.");
                return -1;
            }

            /*
             * Once the connection is created, we need to list all connections
             * and compare with the current one to find the created face ID.
             */
            if (_hc_connection_get(socket, &connection, &connection_found) < 0) {
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
            if (_hc_listener_create(socket, &listener) < 0) {
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

static int
_hc_face_get(hc_sock_t * socket, hc_face_t * face, hc_face_t ** face_found)
{
    hc_listener_t listener;
    hc_listener_t * listener_found;

    hc_connection_t connection;
    hc_connection_t * connection_found;

    char face_s[MAXSZ_HC_FACE];
    int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
    if (rc >= MAXSZ_HC_FACE)
        WARN("[hc_face_get] Unexpected truncation of face string");
    DEBUG("[hc_face_get] face=%s", face_s);

    switch(face->face.type)
    {
        case FACE_TYPE_HICN:
        case FACE_TYPE_TCP:
        case FACE_TYPE_UDP:
            if (hc_face_to_connection(face, &connection, false) < 0)
                 return -1;
            if (_hc_connection_get(socket, &connection, &connection_found) < 0)
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
            if (hc_face_to_listener(face, &listener) < 0)
                 return -1;
            if (_hc_listener_get(socket, &listener, &listener_found) < 0)
                 return -1;
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

static int
_hc_face_delete(hc_sock_t * socket, hc_face_t * face)
{
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

    if (_hc_connection_delete(socket, &connection) < 0) {
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
    if (_hc_connection_list(socket, &connections) < 0) {
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
        if (_hc_listener_delete(socket, &listener) < 0) {
            ERROR("[hc_face_delete] Error removing listener");
            return -1;
        }
    }

    hc_data_free(connections);

    return 0;


}

/* FACE LIST */

static int
_hc_face_list(hc_sock_t * socket, hc_data_t ** pdata)
{
    hc_data_t * connection_data;
    hc_face_t face;

    //DEBUG("[hc_face_list]");

    if (_hc_connection_list(socket, &connection_data) < 0) {
        ERROR("[hc_face_list] Could not list connections.");
        return -1;
    }

    hc_data_t * face_data = hc_data_create(sizeof(hc_connection_t), sizeof(hc_face_t), NULL);
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

static int
_hc_face_list_async(hc_sock_t * socket)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, true);
}

static int
_hc_face_set_admin_state(hc_sock_t * s, const char * conn_id_or_name,
        face_state_t admin_state)
{
    return hc_connection_set_admin_state(s, conn_id_or_name, admin_state);
}

#ifdef WITH_POLICY
static int
_hc_face_set_priority(hc_sock_t * s, const char * conn_id_or_name,
        uint32_t priority)
{
    return hc_connection_set_priority(s, conn_id_or_name, priority);
}

static int
_hc_face_set_tags(hc_sock_t * s, const char * conn_id_or_name,
        policy_tags_t tags)
{
    return hc_connection_set_tags(s, conn_id_or_name, tags);
}
#endif // WITH_POLICY

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

static int
_hc_punting_create_internal(hc_sock_t * socket, hc_punting_t * punting, bool async)
{
    int rc;

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
    rc = snprintf(msg.payload.symbolicOrConnid, SYMBOLIC_NAME_LEN, "%d", punting->face_id);
    if (rc >= SYMBOLIC_NAME_LEN)
        WARN("[_hc_punting_create] Unexpected truncation of symbolic name string");

    hc_command_params_t params = {
        .cmd = ACTION_CREATE,
        .cmd_id = ADD_PUNTING,
        .size_in = sizeof(add_punting_command),
        .size_out = 0,
        .parse = NULL,
    };

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_punting_create(hc_sock_t * s, hc_punting_t * punting)
{
    return _hc_punting_create_internal(s, punting, false);
}

static int
_hc_punting_create_async(hc_sock_t * s, hc_punting_t * punting)
{
    return _hc_punting_create_internal(s, punting, true);
}

static int
_hc_punting_get(hc_sock_t * s, hc_punting_t * punting, hc_punting_t ** punting_found)
{
    ERROR("hc_punting_get not (yet) implemented.");
    return -1;
}

static int
_hc_punting_delete(hc_sock_t * s, hc_punting_t * punting)
{
    ERROR("hc_punting_delete not (yet) implemented.");
    return -1;
}

static int
_hc_punting_list(hc_sock_t * s, hc_data_t ** pdata)
{
    ERROR("hc_punting_list not (yet) implemented.");
    return -1;
}


/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

static int
_hc_cache_set_store_internal(hc_sock_t * socket, int enabled, bool async)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_cache_set_store(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_store_internal(s, enabled, false);
}

static int
_hc_cache_set_store_async(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_store_internal(s, enabled, true);
}

static int
_hc_cache_set_serve_internal(hc_sock_t * socket, int enabled, bool async)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_cache_set_serve(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_serve_internal(s, enabled, false);
}

static int
_hc_cache_set_serve_async(hc_sock_t * s, int enabled)
{
    return _hc_cache_set_serve_internal(s, enabled, true);
}

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
static int
_hc_strategy_set(hc_sock_t * s /* XXX */)
{
     return 0;
}

/* How to retrieve that from the forwarder ? */
static const char * strategies[] = {
    "random",
    "load_balancer",
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

static int
_hc_strategy_list(hc_sock_t * s, hc_data_t ** data)
{
    int rc;

    *data = hc_data_create(0, sizeof(hc_strategy_t), NULL);

    for (unsigned i = 0; i < ARRAY_SIZE(strategies); i++) {
        hc_strategy_t * strategy = (hc_strategy_t*)hc_data_get_next(*data);
        if (!strategy)
             return -1;
        rc = snprintf(strategy->name, MAXSZ_HC_STRATEGY, "%s", strategies[i]);
        if (rc >= MAXSZ_HC_STRATEGY)
            WARN("[hc_strategy_list] Unexpected truncation of strategy name string");
        (*data)->size++;
    }

    return 0;
}

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
static int
_hc_wldr_set(hc_sock_t * s /* XXX */)
{
     return 0;
}

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

static int
_hc_mapme_set(hc_sock_t * s, int enabled)
{
     return 0;
}

static int
_hc_mapme_set_discovery(hc_sock_t * s, int enabled)
{
     return 0;
}

static int
_hc_mapme_set_timescale(hc_sock_t * s, double timescale)
{
     return 0;
}

static int
_hc_mapme_set_retx(hc_sock_t * s, double timescale)
{
     return 0;
}

/*----------------------------------------------------------------------------*
 * Policy
 *----------------------------------------------------------------------------*/

#ifdef WITH_POLICY

/* POLICY CREATE */

static int
_hc_policy_create_internal(hc_sock_t * socket, hc_policy_t * policy, bool async)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_policy_create(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_create_internal(s, policy, false);
}

static int
_hc_policy_create_async(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_create_internal(s, policy, true);
}

/* POLICY DELETE */

static int
_hc_policy_delete_internal(hc_sock_t * socket, hc_policy_t * policy, bool async)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, NULL, async);
}

static int
_hc_policy_delete(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_delete_internal(s, policy, false);
}

static int
_hc_policy_delete_async(hc_sock_t * s, hc_policy_t * policy)
{
    return _hc_policy_delete_internal(s, policy, true);
}

/* POLICY LIST */

static int
_hc_policy_list_internal(hc_sock_t * socket, hc_data_t ** pdata, bool async)
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

    return _hc_execute_command(socket, (hc_msg_t*)&msg, sizeof(msg), &params, pdata, async);
}

static int
_hc_policy_list(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_policy_list_internal(s, pdata, false);
}

static int
_hc_policy_list_async(hc_sock_t * s, hc_data_t ** pdata)
{
    return _hc_policy_list_internal(s, pdata, true);
}

#endif /* WITH_POLICY */

static hc_sock_t hc_sock_light_interface = (hc_sock_t) {
    .hc_sock_get_next_seq = _hc_sock_light_get_next_seq,
    .hc_sock_set_nonblocking = _hc_sock_light_set_nonblocking,
    .hc_sock_get_fd = _hc_sock_light_get_fd,
    .hc_sock_connect = _hc_sock_light_connect,
    .hc_sock_get_available = _hc_sock_light_get_available,
    .hc_sock_send = _hc_sock_light_send,
    .hc_sock_recv = _hc_sock_light_recv,
    .hc_sock_process = _hc_sock_light_process,
    .hc_sock_callback = _hc_sock_light_callback,
    .hc_sock_reset = _hc_sock_light_reset,
    .hc_sock_free = _hc_sock_light_free,
    .hc_listener_create = _hc_listener_create,
    .hc_listener_create_async = _hc_listener_create_async,
    .hc_listener_get = _hc_listener_get,
    .hc_listener_delete = _hc_listener_delete,
    .hc_listener_delete_async = _hc_listener_delete_async,
    .hc_listener_list = _hc_listener_list,
    .hc_listener_list_async = _hc_listener_list_async,
    .hc_connection_create = _hc_connection_create,
    .hc_connection_create_async = _hc_connection_create_async,
    .hc_connection_get = _hc_connection_get,
    .hc_connection_update_by_id = _hc_connection_update_by_id,
    .hc_connection_update = _hc_connection_update,
    .hc_connection_delete = _hc_connection_delete,
    .hc_connection_delete_async = _hc_connection_delete_async,
    .hc_connection_list = _hc_connection_list,
    .hc_connection_list_async = _hc_connection_list_async,
    .hc_connection_set_admin_state = _hc_connection_set_admin_state,
    .hc_connection_set_admin_state_async = _hc_connection_set_admin_state_async,

#ifdef WITH_POLICY
    .hc_connection_set_priority = _hc_connection_set_priority,
    .hc_connection_set_priority_async = _hc_connection_set_priority_async,
    .hc_connection_set_tags = _hc_connection_set_tags,
    .hc_connection_set_tags_async = _hc_connection_set_tags_async,
#endif // WITH_POLICY

    .hc_face_create = _hc_face_create,
    .hc_face_get = _hc_face_get,
    .hc_face_delete = _hc_face_delete,
    .hc_face_list = _hc_face_list,
    .hc_face_list_async = _hc_face_list_async,
    .hc_face_set_admin_state = _hc_face_set_admin_state,

#ifdef WITH_POLICY
    .hc_face_set_priority = _hc_face_set_priority,
    .hc_face_set_tags = _hc_face_set_tags,
#endif // WITH_POLICY

    .hc_route_create = _hc_route_create,
    .hc_route_create_async = _hc_route_create_async,
    .hc_route_delete = _hc_route_delete,
    .hc_route_delete_async = _hc_route_delete_async,
    .hc_route_list = _hc_route_list,
    .hc_route_list_async = _hc_route_list_async,

    .hc_punting_create = _hc_punting_create,
    .hc_punting_create_async = _hc_punting_create_async,
    .hc_punting_get = _hc_punting_get,
    .hc_punting_delete = _hc_punting_delete,
    .hc_punting_list = _hc_punting_list,

    .hc_cache_set_store = _hc_cache_set_store,
    .hc_cache_set_store_async = _hc_cache_set_store_async,
    .hc_cache_set_serve = _hc_cache_set_serve,
    .hc_cache_set_serve_async = _hc_cache_set_serve_async,

    .hc_strategy_list = _hc_strategy_list,
    .hc_strategy_set = _hc_strategy_set,
    .hc_wldr_set = _hc_wldr_set,

    .hc_mapme_set = _hc_mapme_set,
    .hc_mapme_set_discovery = _hc_mapme_set_discovery,
    .hc_mapme_set_timescale = _hc_mapme_set_timescale,
    .hc_mapme_set_retx = _hc_mapme_set_retx,

#ifdef WITH_POLICY
    .hc_policy_create = _hc_policy_create,
    .hc_policy_create_async = _hc_policy_create_async,
    .hc_policy_delete = _hc_policy_delete,
    .hc_policy_delete_async = _hc_policy_delete_async,
    .hc_policy_list = _hc_policy_list,
    .hc_policy_list_async = _hc_policy_list_async
#endif // WITH_POLICY
};

// Public contructors

hc_sock_t *
_hc_sock_create_url(const char * url)
{
    hc_sock_light_t * s = malloc(sizeof(hc_sock_light_t));
    if (!s)
        goto ERR_MALLOC;

    s->vft = hc_sock_light_interface;
    s->url = url ? strdup(url) : NULL;

    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0)
        goto ERR_SOCKET;

    if (_hc_sock_light_reset((hc_sock_t*)s) < 0)
        goto ERR_RESET;

    s->seq = 0;
    s->cur_request = NULL;

    s->map = hc_sock_map_create();
    if (!s->map)
        goto ERR_MAP;

    return (hc_sock_t*)(s);

    //hc_sock_light_map_free(s->map);
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
_hc_sock_create(void)
{
    return _hc_sock_create_url(NULL);
}
