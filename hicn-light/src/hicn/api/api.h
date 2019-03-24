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
 * \file api.h
 * \brief hICN control library API
 */

#ifndef HICNTRL_API
#define HICNTRL_API

#include <stdbool.h>
#include <stdint.h>

#include <hicn/api/face.h>

/**
 * This allows to selectively define convenience types to avoid any collision
 * when using the library in conjunction with other frameworks including similar
 * defines
 */
#ifdef _HICNTRL_NO_DEFS
#define _HICNTRL_NO_DEF_TYPES
#define _HICNTRL_NO_DEF_IPADDR
#define _HICNTRL_NO_DEF_UNIONCAST
#endif

#ifndef _HICNTRL_NO_DEF_TYPES
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif /* _HICNTRL_NO_DEF_TYPES */

#ifndef _HICNTRL_NO_DEF_IPADDR
#include <hicn/api/util/ip_address.h>
#endif /* _HICNTRL_NO_DEF_IPADDR */

#ifndef _HICNTRL_NO_DEF_UNIONCAST
/* Helper for avoiding warnings about type-punning */
#define UNION_CAST(x, destType) \
  (((union {                    \
     __typeof__(x) a;           \
     destType b;                \
   })x)                         \
       .b)
#endif /* _HICNTRL_NO_DEF_UNIONCAST */

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_command \
  _(UNDEFINED)          \
  _(CREATE)             \
  _(DELETE)             \
  _(LIST)               \
  _(SET)                \
  _(N)

typedef enum {
#define _(x) ACTION_##x,
  foreach_command
#undef _
} hc_action_t;

/**
 * \brief hICN control message header
 */
typedef struct hc_msg_s hc_msg_t;

/******************************************************************************
 * Control Data
 ******************************************************************************/

struct hc_data_s;
typedef int (*data_callback_t)(struct hc_data_s *, void *);

/**
 * \brief Holds the results of an hICN control request
 */
typedef struct hc_data_s {
  size_t size;
  size_t max_size_log;
  size_t in_element_size;
  size_t out_element_size;
  u8 command_id; /**< Expected message type (should give element size) */
  u8 *buffer;
  bool complete;

  /* Callbacks */
  data_callback_t
      complete_cb;  // XXX int (*complete_cb)(struct hc_data_s * data);
  void *complete_cb_data;
} hc_data_t;

/**
 * Create a structure holding the results of an hICN control request.
 * \result The newly create data structure.
 */
hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size);

/**
 * Free a structure holding the results of an hICN control request.
 * \param [in] data - The data structure to free.
 */
void hc_data_free(hc_data_t *data);

/**
 * \brief Adds many new results at the end of the data structure, eventually
 * allocating buffer space for it.
 * \param [in] data - The data structure to which to add elements.
 * \param [in] elements - The array of elements to add.
 * \param [in] count - The number of elements to add.
 * \return Error code
 *
 * NOTE: The size of the element should match the one declared at structure
 * initialization.
 */
int hc_data_push_many(hc_data_t *data, const void *elements, size_t count);

/**
 * \brief Adds a new result at the end of the data structure, eventually
 * allocating buffer space for it.
 * \param [in] data - The data structure to which to add an element.
 * \param [in] element - The element to add
 * \return Error code
 *
 * NOTE: The size of the element should match the one declared at structure
 * initialization.
 */
int hc_data_push(hc_data_t *data, const void *element);

/**
 * \brief Configure a callback (along with private data) to be called upon
 * completion of a request
 * \param [in] data - hICN control data
 * \param [in] cb - Callback function
 * \param [in] cb_data - Callback private data
 */
int hc_data_set_callback(hc_data_t *data, data_callback_t cb, void *cb_data);

/**
 * \brief Mark the data structure as complete.
 * \param [in] data - The data structure to which to add an element.
 * \return The error code resulting from callback execution if any. 0 is
 * returned if the callback executed successfully, or if no callback were
 * defined.
 */
int hc_data_set_complete(hc_data_t *data);

/**
 * \brief Reset the data structure holding control data
 * \param [in] data - hICN control data
 * \return Error code
 */
int hc_data_reset(hc_data_t *data);

/**
 * \brief Find en element in the data structure
 * \param [in] data - The data structure in which to find
 * \param [in] element - The element to find
 * \param [in] cmp - The element compare function
 * \param [out] found - A pointer to the element, or NULL if not found.
 * \return Error code
 */
int hc_data_find(hc_data_t *data, const void *element, cmp_t cmp, void **found);

/******************************************************************************
 * Control socket
 ******************************************************************************/

/* This should be at least equal to the maximum packet size */
#define RECV_BUFLEN 8192

/**
 * \brief Holds the state of an hICN control socket
 */
typedef struct {
  char *url;
  int fd;
  u32 seq;

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
  u32 send_seq;
  u32 recv_seq;
} hc_sock_t;

/**
 * \brief Create an hICN control socket using the specified URL.
 * \param [in] url - The URL to connect to.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create_url(const char *url);

/**
 * \brief Create an hICN control socket using the default connection type.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create(void);

/**
 * \brief Frees an hICN control socket
 */
void hc_sock_free(hc_sock_t *s);

/**
 * \brief Sets the socket as non-blocking
 * \return Error code
 */
int hc_sock_set_nonblocking(hc_sock_t *s);

/**
 * \brief Connect the socket
 * \return Error code
 */
int hc_sock_connect(hc_sock_t *s);

/**
 * \brief Return the offset and size of available buffer space
 * \param [in] sock - hICN control socket
 * \param [out] buffer - Offset in buffer
 * \param [out] size - Remaining size
 * \return Error code
 */
int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size);

/**
 * \brief Write/read iexchance on the control socket (internal helper function)
 * \param [in] sock - hICN control socket
 * \param [in] msg - Message to send
 * \param [in] msglen - Length of the message to send
 * \return Error code
 */
int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen);

/**
 * \brief Helper for reading socket contents
 * \param [in] sock - hICN control socket
 * \param [in] data - Result data buffer
 * \param [in] parse - Parse function to convert remote types into lib native
 *      types, or NULL not to perform any translation.
 * \return Error code
 */
int hc_sock_recv(hc_sock_t *s, hc_data_t *data);

/**
 * \brief Processing data received by socket
 * \param [in] sock - hICN control socket
 * \param [in] data - Result data buffer
 * \param [in] parse - Parse function to convert remote types into lib native
 *      types, or NULL not to perform any translation.
 * \return Error code
 */
int hc_sock_process(hc_sock_t *s, hc_data_t *data,
                    int (*parse)(const u8 *src, u8 *dst));

/**
 * \brief Reset the state of the sock (eg. to handle a reconnecton)
 * \param [in] sock - hICN control socket
 * \return Error code
 */
int hc_sock_reset(hc_sock_t *s);

/******************************************************************************
 * Command-specific structures and functions
 ******************************************************************************/

/*
 * The following definitions are organized by sections each dealing with a
 * specific object being manipulated. All follow a similar structure.
 *
 * TYPE DEFINITIONS AND ALIASES
 *
 * We redefine command struct:
 *  - for uniformization
 *  - to use enum instead of type specifiers more appropriate for packet format
 *  - to use more flexible types such as for manipulating IP addresses
 *  - host endianness
 *  - more intuitive field name, ordering, consistency, and hierarchy removal
 *  - to have command types in between add/list/... commands
 *
 * COMMAND IMPLEMENTATION
 *
 * All commands return information in a common format
 *
 * TODO describe + explain for commands with only return code.
 *
 * RETURN DATA FIXME
 *
 * \param [out] pdata - Pointer to the structure storing the results of the call
 * (NULL if no data has been received). If the pointer is NULL, no result will
 * be stored and only the error code will be exposed to the caller. It is
 * expected that the caller frees this structure using hc_data_free() after
 * usage.
 * \see hc_data_free.
 *
 * PARSING
 *
 * While this is not made mandatory by the library, the returned data can be
 * converted to the library's own data structures as described before.
 *
 * ITERATORS
 *
 * Macros are defined to facilitate iteration on the returned data structures.
 */

#ifndef SPACES
#define SPACES(x) x
#endif
#ifndef SPACE
#define SPACE SPACES(1)
#endif
#ifndef NULLTERM
#define NULLTERM 1
#endif

#define NAME_LEN 16 /* NULL-terminated right ? */
#define MAXSZ_HC_NAME_ NAME_LEN
#define MAXSZ_HC_NAME MAXSZ_HC_NAME_ + NULLTERM

#define MAXSZ_HC_ID_ 10 /* Number of digits for MAX_INT */
#define MAXSZ_HC_ID MAXSZ_HC_ID_ + NULLTERM

#define MAXSZ_HC_PROTO_ 8 /* inetX:// */
#define MAXSZ_HC_PROTO MAXSZ_HC_PROTO_ + NULLTERM

#define MAXSZ_HC_URL4_ MAXSZ_HC_PROTO_ + MAXSZ_IP4_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_HC_URL6_ MAXSZ_HC_PROTO_ + MAXSZ_IP6_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_HC_URL_ MAXSZ_HC_URL6_
#define MAXSZ_HC_URL4 MAXSZ_HC_URL4_ + NULLTERM
#define MAXSZ_HC_URL6 MAXSZ_HC_URL6_ + NULLTERM
#define MAXSZ_HC_URL MAXSZ_HC_URL_ + NULLTERM

size_t hc_url_snprintf(char *s, size_t size, int family,
                       ip_address_t *ip_address, u16 port);

#define foreach_type(TYPE, VAR, data)                                      \
  for (TYPE *VAR = (TYPE *)data->buffer;                                   \
       VAR < (TYPE *)(data->buffer + data->size * data->out_element_size); \
       VAR++)

/**
 * New type is defined to reconciliate different enum for add and list.
 * Also, values not implemented have been removed for clarity.
 */
#define foreach_connection_type \
  _(UNDEFINED)                  \
  _(TCP)                        \
  _(UDP)                        \
  _(HICN)                       \
  _(N)

typedef enum {
#define _(x) CONNECTION_TYPE_##x,
  foreach_connection_type
#undef _
} hc_connection_type_t;

#define MAXSZ_HC_CONNECTION_TYPE_ 9
#define MAXSZ_HC_CONNECTION_TYPE MAXSZ_HC_CONNECTION_TYPE_ + NULLTERM

extern const char *connection_type_str[];

hc_connection_type_t connection_type_from_str(const char *str);

#define foreach_connection_state \
  _(UNDEFINED)                   \
  _(UP)                          \
  _(DOWN)                        \
  _(N)

typedef enum {
#define _(x) CONNECTION_STATE_##x,
  foreach_connection_state
#undef _
} hc_connection_state_t;

#define MAXSZ_HC_CONNECTION_STATE_ 9
#define MAXSZ_HC_CONNECTION_STATE MAXSZ_HC_CONNECTION_STATE_ + NULLTERM

extern const char *connection_state_str[];

typedef int (*HC_PARSE)(const u8 *, u8 *);

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

typedef struct {
  char name[NAME_LEN]; /* K.w */  // XXX clarify what used for
  u32 conn_id;                    /* Kr. */
  hc_connection_type_t type;      /* .rw */
  int family;                     /* .rw */
  ip_address_t local_addr;        /* .rw */
  u16 local_port;                 /* .rw */
} hc_listener_t;

int hc_parse_listener(void *in, hc_listener_t *listener);

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener);
// XXX int hc_listener_delete(hc_sock_t * s, hc_listener_t * listener);
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_listener(VAR, data) foreach_type(hc_listener_t, VAR, data)

#define MAXSZ_HC_LISTENER_ MAXSZ_HC_URL_ + SPACE + MAXSZ_HC_CONNECTION_TYPE_
#define MAXSZ_HC_LISTENER MAXSZ_HC_LISTENER_ + NULLTERM

int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2);

size_t hc_listener_snprintf(char *s, size_t size, hc_listener_t *listener);

/*----------------------------------------------------------------------------*
 * Connections
 *----------------------------------------------------------------------------*/

typedef struct {
  u32 id;                    /* Kr. */
  char name[NAME_LEN];       /* K.w */
  hc_connection_type_t type; /* .rw */
  int family;                /* .rw */
  ip_address_t local_addr;   /* .rw */
  u16 local_port;            /* .rw */
  ip_address_t remote_addr;  /* .rw */
  u16 remote_port;           /* .rw */
#ifdef WITH_POLICY
  face_state_t desired_state;  /* .rw */
  face_tags_t tags;            /* .rw */
#endif                         /* WITH_POLICY */
  hc_connection_state_t state; /* .r. */
} hc_connection_t;

int hc_parse_connection(void *in, hc_connection_t *connection);

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection);
int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection);
/*
int hc_connection_remove_by_id(hc_sock_t * s, char * name);
int hc_connection_remove_by_name(hc_sock_t * s, char * name);
*/
#ifdef WITH_POLICY
int hc_connection_set_state(hc_sock_t *s, const char *conn_id_or_name,
                            face_state_t state);
#endif /* WITH_POLICY */
int hc_connection_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_connection(VAR, data) foreach_type(hc_connection_t, VAR, data)

#define MAXSZ_HC_CONNECTION_                                                   \
  MAXSZ_HC_CONNECTION_STATE_ + 2 * MAXSZ_HC_URL_ + MAXSZ_HC_CONNECTION_TYPE_ + \
      SPACES(3)
#define MAXSZ_HC_CONNECTION MAXSZ_HC_CONNECTION_ + NULLTERM

size_t hc_connection_snprintf(char *s, size_t size,
                              hc_connection_t *connection);

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

typedef struct {
  u8 conn_id;               /* Kr. */
  char conn_name[NAME_LEN]; /* K.w */
  int family;               /* Krw */
  ip_address_t remote_addr; /* krw */
  u8 len;                   /* krw */
  u16 cost;                 /* .rw */
} hc_route_t;

int hc_parse_route(void *in, hc_route_t *route);

int hc_route_create(hc_sock_t *s, hc_route_t *route);
int hc_route_delete(hc_sock_t *s, hc_route_t *route);
int hc_route_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_route(VAR, data) foreach_type(hc_route_t, VAR, data)

#define MAXSZ_HC_ROUTE_ 0
#define MAXSZ_HC_ROUTE MAXSZ_HC_ROUTE_ + NULLTERM

size_t hc_route_snprintf(char *s, size_t size, hc_route_t *route);

/*----------------------------------------------------------------------------*
 * Faces
 *
 * A face is an abstraction introduced by the control library to abstract the
 * forwarder implementation details. It encompasses connections and listeners
 * and ensures the right dependencies are enforced, eg that we always have a
 * listener when a connection is created.
 *
 *----------------------------------------------------------------------------*/

typedef struct {
  u32 id;
  char name[NAME_LEN];
  face_t face;  // or embed ?
                // face_id_t parent; /* Pointer from connection to listener */
} hc_face_t;

int hc_face_create(hc_sock_t *s, hc_face_t *face);
int hc_face_delete(hc_sock_t *s, hc_face_t *face);
int hc_face_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_face(VAR, data) foreach_type(hc_face_t, VAR, data)

#define MAXSZ_HC_FACE_ 0
#define MAXSZ_HC_FACE MAXSZ_HC_FACE_ + NULLTERM

size_t hc_face_snprintf(char *s, size_t size, hc_face_t *face);

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int hc_cache_set_store(hc_sock_t *s, int enabled);
int hc_cache_set_serve(hc_sock_t *s, int enabled);

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

int hc_punting_create(hc_sock_t *s /* XXX */);

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
int hc_strategy_set(hc_sock_t *s /* XXX */);

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
int hc_wldr_set(hc_sock_t *s /* XXX */);

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

int hc_mapme_set(hc_sock_t *s, int enabled);
int hc_mapme_set_discovery(hc_sock_t *s, int enabled);
int hc_mapme_set_timescale(hc_sock_t *s, double timescale);
int hc_mapme_set_retx(hc_sock_t *s, double timescale);

#endif /* HICNTRL_API */
