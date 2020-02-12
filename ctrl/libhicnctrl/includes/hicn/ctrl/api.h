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
 *
 * This API supports basic hICN objects (face, route, punting) plus
 * implementation-specific ones (connection, listener). Currently, this library
 * only supports the hicn-light forwarder.
 *
 * For each object, a set of methods is provided among:
 *  - CREATE, GET, UPDATE, DELETE, LIST
 *  - CMP, PARSE, SNPRINTF
 *  - additionally, attribute getters and/or setters are provided and denoted
 *    GET( attribute ) and SET( attribute )
 *
 * A summary per-object is presented here:
 *
 *              | CRE GET UPD DEL LST | VAL CMP PAR SNP | attributes [GET/SET]
 * +------------+---------------------+-------------+---------------------------
 * | face       |  O   O   !   O   O  |      !   !   O  | state [-S]
 * | route      |  O   -   !   O   O  |      !   O   -  |
 * | punting    |  !   -   !   !   !  |      !   !   !  |
 * +------------+---------------------+-----------------+---------------------------
 * | cache      |                     |                 | store [!!], serve [!!]
 * | strategy   |                     |                 |
 * | FIB        |                     |                 |
 * | PIT        |                     |                 |
 * | WLDR       |                     |                 |
 * | MAP-Me     |                     |                 |
 * +------------+---------------------+-----------------+---------------------------
 * | connection |  O   O   !   O   O  |      O   O   O  | state [-S]
 * | listener   |  O   O   !   O   O  |  O   O   O   O  |
 * +------------+---------------------+-----------------+---------------------------
 *
 * LEGEND: [O] implemented, [!] in progress / TODO, [-] not supported
 *
 * NOTES:
 *
 *  - Different extensions of the forwarder functionalities bring both new API
 *    calls, and new object attributes. While it is expected that the former
 * will only raised NACK answers because of unsupported API calls, the latter
 * will certainly trigger incompatibilities. It is expected that the forwarder
 *    validates the message length and returns a NACK too. In that case, we
 *    provide a set of defines to preserve backwards compatibility. At the
 *    moment, those defines are :
 *
 *  WITH_POLICY:
 *
 */

#ifndef HICNTRL_API
#define HICNTRL_API

#include <stdbool.h>
#include <stdint.h>

#include <hicn/util/ip_address.h>
#include <hicn/ctrl/commands.h>
#include <hicn/strategy.h>
#include "face.h"

#define HICN_DEFAULT_PORT 9695

#define HOTFIXMARGIN 0

/* Helper for avoiding warnings about type-punning */
#ifndef UNION_CAST
#define UNION_CAST(x, destType) \
  (((union {                    \
     __typeof__(x) a;           \
     destType b;                \
   })x)                         \
       .b)
#endif
/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_command \
  _(UNDEFINED)          \
  _(CREATE)             \
  _(UPDATE)             \
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
  size_t current;
  size_t max_size_log;
  size_t in_element_size;
  size_t out_element_size;
  u8 command_id; /**< Expected message type (should give element size) */
  u8 *buffer;
  bool complete;

  /* Callbacks */
  data_callback_t complete_cb;  // XXX int (*complete_cb)(struct hc_data_s * data);
  void *complete_cb_data;
  int ret;
} hc_data_t;

/**
 * Create a structure holding the results of an hICN control request.
 * \result The newly create data structure.
 */
hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size, data_callback_t complete_cb);

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
 * \param [out] found - A pointer to the element, or NULL if not found.
 * \return Error code
 */
#define GENERATE_FIND_HEADER(TYPE)                                          \
int                                                                         \
hc_ ## TYPE ## _find(hc_data_t * data, const hc_ ## TYPE ## _t * element,   \
        hc_ ## TYPE ## _t **found)

#define GENERATE_FIND(TYPE)                                                 \
int                                                                         \
hc_ ## TYPE ## _find(hc_data_t * data, const hc_ ## TYPE ## _t * element,   \
        hc_ ## TYPE ## _t **found)                                          \
{                                                                           \
    foreach_type(hc_ ## TYPE ## _t, x, data) {                              \
        if (hc_ ## TYPE ## _cmp(x, element) == 0) {                         \
            *found = x;                                                     \
            return 0;                                                       \
        }                                                                   \
    };                                                                      \
    *found = NULL; /* this is optional */                                   \
    return 0;                                                               \
}

/******************************************************************************
 * Control socket
 ******************************************************************************/

/* This should be at least equal to the maximum packet size */
#define RECV_BUFLEN 8192

/**
 * \brief Holds the state of an hICN control socket
 */
typedef struct hc_sock_s hc_sock_t;

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
 * \param [in] s - hICN control socket
 */
void hc_sock_free(hc_sock_t *s);

/**
 * \brief Returns the next available sequence number to use for requests to the
 * API.
 * \param [in] s - hICN control socket
 */
int hc_sock_get_next_seq(hc_sock_t *s);

/**
 * \brief Sets the socket as non-blocking
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_set_nonblocking(hc_sock_t *s);

/**
 * \brief Return the file descriptor associated to the hICN contorl sock
 * \param [in] s - hICN control socket
 * \return The file descriptor (positive value), or a negative integer in case
 * of error
 */
int hc_sock_get_fd(hc_sock_t *s);

/**
 * \brief Connect the socket
 * \return Error code
 */
int hc_sock_connect(hc_sock_t *s);

/**
 * \brief Return the offset and size of available buffer space
 * \param [in] s - hICN control socket
 * \param [out] buffer - Offset in buffer
 * \param [out] size - Remaining size
 * \return Error code
 */
int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size);

/**
 * \brief Write/read iexchance on the control socket (internal helper function)
 * \param [in] s - hICN control socket
 * \param [in] msg - Message to send
 * \param [in] msglen - Length of the message to send
 * \return Error code
 */
int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, int seq);

/**
 * \brief Helper for reading socket contents
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_recv(hc_sock_t *s);

/**
 * \brief Processing data received by socket
 * \param [in] s - hICN control socket
 * \param [in] parse - Parse function to convert remote types into lib native
 *      types, or NULL not to perform any translation.
 * \return Error code
 */
int hc_sock_process(hc_sock_t *s, hc_data_t **data);

/**
 * \brief Callback used in async mode when data is available on the socket
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_callback(hc_sock_t *s, hc_data_t **data);

/**
 * \brief Reset the state of the sock (eg. to handle a reconnecton)
 * \param [in] s - hICN control socket
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

#ifdef HICN_VPP_PLUGIN
  #define INTERFACE_LEN 64
#else
  #define INTERFACE_LEN IFNAMSIZ
#endif

#define MAXSZ_HC_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_HC_NAME MAXSZ_HC_NAME_ + NULLTERM

#define MAXSZ_HC_ID_ 10 /* Number of digits for MAX_INT */
#define MAXSZ_HC_ID MAXSZ_HC_ID_ + NULLTERM

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
#define MAXSZ_HC_CONNECTION_TYPE MAXSZ_HC_CONNECTION_TYPE_ + NULLTERM + HOTFIXMARGIN

extern const char *connection_type_str[];

hc_connection_type_t connection_type_from_str(const char *str);

/* Same order as connection_state_t in hicn/core/connectionState.h */
#define foreach_connection_state \
  _(UNDEFINED)                   \
  _(DOWN)                        \
  _(UP)                          \
  _(N)

typedef enum {
#define _(x) HC_CONNECTION_STATE_##x,
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

// FIXME the listener should not require any port for hICN...
typedef struct {
  char name[SYMBOLIC_NAME_LEN]; /* K.w */  // XXX clarify what used for
  char interface_name[INTERFACE_LEN];      /* Kr. */
  u32 id;
  hc_connection_type_t type; /* .rw */
  int family;                /* .rw */
  ip_address_t local_addr;   /* .rw */
  u16 local_port;            /* .rw */
} hc_listener_t;

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener);
/* listener_found might eventually be allocated, and needs to be freed */
int hc_listener_get(hc_sock_t *s, hc_listener_t *listener,
                    hc_listener_t **listener_found);
int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener);
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata);

int hc_listener_validate(const hc_listener_t *listener);
int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2);
int hc_listener_parse(void *in, hc_listener_t *listener);

#define foreach_listener(VAR, data) foreach_type(hc_listener_t, VAR, data)

#define MAXSZ_HC_LISTENER_ \
  INTERFACE_LEN + SPACE + MAXSZ_URL_ + SPACE + MAXSZ_HC_CONNECTION_TYPE_
#define MAXSZ_HC_LISTENER MAXSZ_HC_LISTENER_ + NULLTERM

GENERATE_FIND_HEADER(listener);

int hc_listener_snprintf(char *s, size_t size, hc_listener_t *listener);

/*----------------------------------------------------------------------------*
 * Connections
 *----------------------------------------------------------------------------*/

/*
 * NOTE :
 *  - interface_name is mainly used to derive listeners from connections, but is
 *  not itself used to create connections.
 */
typedef struct {
  u32 id;                             /* Kr. */
  char name[SYMBOLIC_NAME_LEN];       /* K.w */
  char interface_name[INTERFACE_LEN]; /* Kr. */
  hc_connection_type_t type;          /* .rw */
  int family;                         /* .rw */
  ip_address_t local_addr;            /* .rw */
  u16 local_port;                     /* .rw */
  ip_address_t remote_addr;           /* .rw */
  u16 remote_port;                    /* .rw */
  hc_connection_state_t admin_state;  /* .rw */
#ifdef WITH_POLICY
    uint32_t priority;           /* .rw */
    policy_tags_t tags;          /* .rw */
#endif /* WITH_POLICY */
    hc_connection_state_t state; /* .r. */
} hc_connection_t;

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection);
/* connection_found will be allocated, and must be freed */
int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_connection_t **connection_found);
int hc_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                               hc_connection_t *connection);
int hc_connection_update(hc_sock_t *s, hc_connection_t *connection_current,
                         hc_connection_t *connection_updated);
int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection);
/*
int hc_connection_remove_by_id(hc_sock_t * s, char * name);
int hc_connection_remove_by_name(hc_sock_t * s, char * name);
*/
int hc_connection_list(hc_sock_t *s, hc_data_t **pdata);

int hc_connection_validate(const hc_connection_t *connection);
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2);
int hc_connection_parse(void *in, hc_connection_t *connection);

int hc_connection_set_admin_state(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);
#ifdef WITH_POLICY
int hc_connection_set_priority(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
int hc_connection_set_tags(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
#endif /* WITH_POLICY */

#define foreach_connection(VAR, data) foreach_type(hc_connection_t, VAR, data)

#define MAXSZ_HC_CONNECTION_                                            \
  MAXSZ_HC_CONNECTION_STATE_ + INTERFACE_LEN + SPACE + 2 * MAXSZ_URL_ + \
      MAXSZ_HC_CONNECTION_TYPE_ + SPACES(3)
#define MAXSZ_HC_CONNECTION MAXSZ_HC_CONNECTION_ + NULLTERM

GENERATE_FIND_HEADER(connection);

int hc_connection_snprintf(char *s, size_t size,
                           const hc_connection_t *connection);

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
  face_id_t id;
  char name[SYMBOLIC_NAME_LEN];
  face_t face;  // or embed ?
                // face_id_t parent; /* Pointer from connection to listener */
} hc_face_t;

/**
 * \brief Create a face
 * \param [in] s - hICN socket
 * \param [in,out] face - Parameters of the face to create
 * \return Error code
 *
 * The face parameters will be updated with the face ID.
 */
int hc_face_create(hc_sock_t *s, hc_face_t *face);
int hc_face_get(hc_sock_t *s, hc_face_t *face, hc_face_t **face_found);
int hc_face_delete(hc_sock_t *s, hc_face_t *face);
int hc_face_list(hc_sock_t *s, hc_data_t **pdata);
int hc_face_list_async(hc_sock_t *s);  //, hc_data_t ** pdata);

int hc_face_set_admin_state(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);
#ifdef WITH_POLICY
int hc_face_set_priority(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
int hc_face_set_tags(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
#endif /* WITH_POLICY */

#define foreach_face(VAR, data) foreach_type(hc_face_t, VAR, data)

#define MAX_FACE_ID 255
#define MAXSZ_FACE_ID_ 3
#define MAXSZ_FACE_ID MAXSZ_FACE_ID_ + NULLTERM
#define MAXSZ_FACE_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_FACE_NAME MAXSZ_FACE_NAME_ + NULLTERM

#define MAXSZ_HC_FACE_ MAXSZ_FACE_ID_ + MAXSZ_FACE_NAME_ + MAXSZ_FACE_ + 5 + HOTFIXMARGIN
#define MAXSZ_HC_FACE MAXSZ_HC_FACE_ + NULLTERM

int hc_face_snprintf(char *s, size_t size, hc_face_t *face);

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

typedef struct {
  face_id_t face_id;               /* Kr. */
  int family;               /* Krw */
  ip_address_t remote_addr; /* krw */
  u8 len;                   /* krw */
  u16 cost;                 /* .rw */
} hc_route_t;

int hc_route_parse(void *in, hc_route_t *route);

int hc_route_create(hc_sock_t * s, hc_route_t * route);
int hc_route_delete(hc_sock_t * s, hc_route_t * route);
int hc_route_list(hc_sock_t * s, hc_data_t ** pdata);
int hc_route_list_async(hc_sock_t * s);

#define foreach_route(VAR, data) foreach_type(hc_route_t, VAR, data)

#define MAX_COST 65535
#define MAXSZ_COST 5
#define MAX_LEN 255
#define MAXSZ_LEN 3

#define MAXSZ_HC_ROUTE_ \
  MAXSZ_FACE_ID + 1 + MAXSZ_COST + 1 + MAXSZ_IP_ADDRESS + 1 + MAXSZ_LEN
#define MAXSZ_HC_ROUTE MAXSZ_HC_ROUTE_ + NULLTERM

int hc_route_snprintf(char *s, size_t size, hc_route_t *route);

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

typedef struct {
  face_id_t face_id; /* Kr. */  // XXX listener id, could be NULL for all ?
  int family;            /* Krw */
  ip_address_t prefix;   /* krw */
  u8 prefix_len;         /* krw */
} hc_punting_t;

int hc_punting_create(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_get(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found);
int hc_punting_delete(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_list(hc_sock_t *s, hc_data_t **pdata);

int hc_punting_validate(const hc_punting_t *punting);
int hc_punting_cmp(const hc_punting_t *c1, const hc_punting_t *c2);
int hc_punting_parse(void *in, hc_punting_t *punting);

#define foreach_punting(VAR, data) foreach_type(hc_punting_t, VAR, data)

#define MAXSZ_HC_PUNTING_ 0
#define MAXSZ_HC_PUNTING MAXSZ_HC_PUNTING_ + NULLTERM

GENERATE_FIND_HEADER(punting);

int hc_punting_snprintf(char *s, size_t size, hc_punting_t *punting);

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int hc_cache_set_store(hc_sock_t *s, int enabled);
int hc_cache_set_serve(hc_sock_t *s, int enabled);

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

typedef struct {
  ip_prefix_t prefix;
  hicn_strategy_t strategy_id;
  uint8_t num_related_prefixes;
  ip_prefix_t related_prefixes[MAX_FWD_STRATEGY_RELATED_PREFIXES];
} hc_strategy_t;

int hc_strategy_create(hc_sock_t * s, hc_strategy_t * strategy);
int hc_strategy_create_async(hc_sock_t * s, hc_strategy_t * strategy);

int hc_strategy_list(hc_sock_t * s, hc_data_t ** pdata);
int hc_strategy_list_async(hc_sock_t * s);

#define foreach_strategy(VAR, data) foreach_type(hc_strategy_t, VAR, data)

#define HC_STRATEGY_RELATED_PREFIXES_HEADER " Related prefixes:"
#define MAXSZ_HC_STRATEGY_RELATED_PREFIXES_HEADER 18
#define MAXSZ_HC_STRATEGY_ MAXSZ_IP_PREFIX_ + SPACE +                        \
    MAXSZ_HICN_STRATEGY_NAME_ +                                              \
    SPACE + MAXSZ_HC_STRATEGY_RELATED_PREFIXES_HEADER +                      \
    ((SPACE + MAXSZ_IP_PREFIX_) * MAX_FWD_STRATEGY_RELATED_PREFIXES)
#define MAXSZ_HC_STRATEGY MAXSZ_HC_STRATEGY_ + NULLTERM

int hc_strategy_parse(void *in, hc_strategy_t *strategy);
int hc_strategy_snprintf(char *s, size_t size, hc_strategy_t *strategy);

int hc_strategies_get_by_name(const char * name, hicn_strategy_t * strategy);

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

/*----------------------------------------------------------------------------*
 * Policies
 *----------------------------------------------------------------------------*/

#ifdef WITH_POLICY

typedef struct {
  int family;               /* Krw */
  ip_address_t remote_addr; /* krw */
  u8 len;                   /* krw */
  policy_t policy;          /* .rw */
} hc_policy_t;

int hc_policy_parse(void *in, hc_policy_t *policy);

int hc_policy_create(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_delete(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_policy(VAR, data) foreach_type(hc_policy_t, VAR, data)

/* TODO */
#define MAXSZ_HC_POLICY_ 0
#define MAXSZ_HC_POLICY MAXSZ_HC_POLICY_ + NULLTERM

int hc_policy_snprintf(char *s, size_t size, hc_policy_t *policy);

#endif /* WITH_POLICY */

#endif /* HICNTRL_API */
