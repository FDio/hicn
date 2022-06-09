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
#include <stddef.h>  // object_offset_t

#include <hicn/util/ip_address.h>
#include <hicn/face.h>
#include <hicn/strategy.h>
#include <hicn/base.h>
/*
 * This has to be common between hicn-light and hicn-plugin. We now we keep the
 * minimum of the two
 */
#define SYMBOLIC_NAME_LEN 16

#define HICN_DEFAULT_PORT 9695

#define HOTFIXMARGIN 0

#define INVALID_FACE_ID ~0
#define INVALID_NETDEVICE_ID ~0

/**
 * \brief Defines the default size for the allocated data arrays holding the
 * results of API calls.
 *
 * This size should not be too small to avoid wasting memoyy, but also not too
 * big to avoid unnecessary realloc's. Later on this size is doubled at each
 * reallocation.
 */
#define DEFAULT_SIZE_LOG 3

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

/* Action */

#define foreach_action \
  _(UNDEFINED)         \
  _(CREATE)            \
  _(UPDATE)            \
  _(DELETE)            \
  _(LIST)              \
  _(SET)               \
  _(SERVE)             \
  _(STORE)             \
  _(CLEAR)             \
  _(GET)               \
  _(N)

typedef enum {
#define _(x) ACTION_##x,
  foreach_action
#undef _
} hc_action_t;

extern const char *action_str[];

#define action_str(x) action_str[x]

hc_action_t action_from_str(const char *action_str);

/* Object type */

#define foreach_object \
  _(UNDEFINED)         \
  _(CONNECTION)        \
  _(LISTENER)          \
  _(ROUTE)             \
  _(FACE)              \
  _(STRATEGY)          \
  _(PUNTING)           \
  _(POLICY)            \
  _(CACHE)             \
  _(MAPME)             \
  _(LOCAL_PREFIX)      \
  _(PROBE)             \
  _(SUBSCRIPTION)      \
  _(STATS)             \
  _(N)

typedef enum {
#define _(x) OBJECT_##x,
  foreach_object
#undef _
} hc_object_type_t;

extern const char *object_str[];

#define object_str(x) object_str[x]

hc_object_type_t object_from_str(const char *object_str);

#define IS_VALID_OBJECT_TYPE(x) IS_VALID_ENUM_TYPE(OBJECT, x)
#define IS_VALID_ACTION(x) IS_VALID_ENUM_TYPE(ACTION, x)

/**
 * \brief hICN control message header
 */
typedef struct hc_msg_s hc_msg_t;
typedef struct hc_result_s hc_result_t;
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
  data_callback_t
      complete_cb;  // XXX int (*complete_cb)(struct hc_data_s * data);
  void *complete_cb_data;
  int ret;
} hc_data_t;

/**
 * Create a structure holding the results of an hICN control request.
 * \result The newly create data structure.
 */
hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size,
                          data_callback_t complete_cb);

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
#define GENERATE_FIND_HEADER(TYPE)                                    \
  int hc_##TYPE##_find(hc_data_t *data, const hc_##TYPE##_t *element, \
                       hc_##TYPE##_t **found)

#define GENERATE_FIND(TYPE)                                           \
  int hc_##TYPE##_find(hc_data_t *data, const hc_##TYPE##_t *element, \
                       hc_##TYPE##_t **found) {                       \
    foreach_type(hc_##TYPE##_t, x, data) {                            \
      if (hc_##TYPE##_cmp(x, element) == 0) {                         \
        *found = x;                                                   \
        return 0;                                                     \
      }                                                               \
    };                                                                \
    *found = NULL; /* this is optional */                             \
    return 0;                                                         \
  }

/******************************************************************************
 * Control socket
 ******************************************************************************/

/* With UDP, the buffer should be able to receieve a full packet, and thus MTU
 * (max 9000) is sufficient. Messages will be received fully one by one.
 * With TCP, the buffer should be at least able to receive a message header and
 * the maximum size of a data element, so any reasonable size will be correct,
 * it might just optimize performance. Messages might arrive in chunks that the
 * library is able to parse.
 */
#define JUMBO_MTU 9000
#define RECV_BUFLEN 65535

#define foreach_forwarder_type \
  _(UNDEFINED)                 \
  _(HICNLIGHT)                 \
  _(HICNLIGHT_NG)              \
  _(VPP)                       \
  _(N)

typedef enum {
#define _(x) x,
  foreach_forwarder_type
#undef _
} forwarder_type_t;

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
 * \brief Create an hICN control socket using the provided forwarder.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create_forwarder(forwarder_type_t forwarder);

/**
 * \brief Create an hICN control socket using the provided forwarder and a URL.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create_forwarder_url(forwarder_type_t forwarder,
                                        const char *url);

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
int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, uint32_t seq);

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

void hc_sock_increment_woff(hc_sock_t *s, size_t bytes);

int hc_sock_prepare_send(hc_sock_t *s, hc_result_t *result,
                         data_callback_t complete_cb, void *complete_cb_data);

int hc_sock_set_recv_timeout_ms(hc_sock_t *s, long timeout_ms);

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

#define INTERFACE_LEN 16

#define MAXSZ_HC_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_HC_NAME MAXSZ_HC_NAME_ + NULLTERM

#define MAXSZ_HC_ID_ 10 /* Number of digits for MAX_INT */
#define MAXSZ_HC_ID MAXSZ_HC_ID_ + NULLTERM

#define foreach_type(TYPE, VAR, data)                                      \
  for (TYPE *VAR = (TYPE *)data->buffer;                                   \
       VAR < (TYPE *)(data->buffer + data->size * data->out_element_size); \
       VAR++)

typedef int (*HC_PARSE)(const u8 *, u8 *);

#define INPUT_ERROR -2
#define UNSUPPORTED_CMD_ERROR -3

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

// FIXME the listener should not require any port for hICN...
typedef struct {
  char name[SYMBOLIC_NAME_LEN]; /* K.w */  // XXX clarify what used for
  char interface_name[INTERFACE_LEN];      /* Kr. */
  u32 id;
  face_type_t type;        /* .rw */
  int family;              /* .rw */
  ip_address_t local_addr; /* .rw */
  u16 local_port;          /* .rw */
} hc_listener_t;

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener);
/* listener_found might eventually be allocated, and needs to be freed */
hc_result_t *hc_listener_create_conf(hc_sock_t *s, hc_listener_t *listener);
int hc_listener_get(hc_sock_t *s, hc_listener_t *listener,
                    hc_listener_t **listener_found);
int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener);
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata);
hc_result_t *hc_listener_list_conf(hc_sock_t *s);

int hc_listener_validate(const hc_listener_t *listener);
int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2);

#define foreach_listener(VAR, data) foreach_type(hc_listener_t, VAR, data)

#define MAXSZ_HC_LISTENER_ \
  INTERFACE_LEN + SPACE + MAXSZ_URL_ + SPACE + MAXSZ_FACE_TYPE_
#define MAXSZ_HC_LISTENER MAXSZ_HC_LISTENER_ + NULLTERM

GENERATE_FIND_HEADER(listener);

int hc_listener_snprintf(char *s, size_t size, hc_listener_t *listener);

/*----------------------------------------------------------------------------*
 * Connections
 *----------------------------------------------------------------------------*/

/*
 * NOTE :
 *  - interface_name is mainly used to derive listeners from connections,
 * but is not itself used to create connections.
 */
typedef struct {
  u32 id;                             /* Kr. */
  char name[SYMBOLIC_NAME_LEN];       /* K.w */
  char interface_name[INTERFACE_LEN]; /* Kr. */
  face_type_t type;                   /* .rw */
  int family;                         /* .rw */
  ip_address_t local_addr;            /* .rw */
  u16 local_port;                     /* .rw */
  ip_address_t remote_addr;           /* .rw */
  u16 remote_port;                    /* .rw */
  face_state_t admin_state;           /* .rw */
#ifdef WITH_POLICY
  uint32_t priority;  /* .rw */
  policy_tags_t tags; /* .rw */
#endif                /* WITH_POLICY */
  face_state_t state; /* .r. */
} hc_connection_t;

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection);
hc_result_t *hc_connection_create_conf(hc_sock_t *s,
                                       hc_connection_t *connection);
/* connection_found will be allocated, and must be freed */
int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_connection_t **connection_found);
int hc_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                               hc_connection_t *connection);
int hc_connection_update(hc_sock_t *s, hc_connection_t *connection_current,
                         hc_connection_t *connection_updated);
int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection);
hc_result_t *hc_connection_delete_conf(hc_sock_t *s,
                                       hc_connection_t *connection);
/*
int hc_connection_remove_by_id(hc_sock_t * s, char * name);
int hc_connection_remove_by_name(hc_sock_t * s, char * name);
*/
int hc_connection_list(hc_sock_t *s, hc_data_t **pdata);

int hc_connection_validate(const hc_connection_t *connection);
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2);

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state);
#ifdef WITH_POLICY
int hc_connection_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                               uint32_t priority);
int hc_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                           policy_tags_t tags);
#endif /* WITH_POLICY */

#define foreach_connection(VAR, data) foreach_type(hc_connection_t, VAR, data)

#define MAXSZ_HC_CONNECTION_                                   \
  MAXSZ_FACE_STATE_ + INTERFACE_LEN + SPACE + 2 * MAXSZ_URL_ + \
      MAXSZ_FACE_TYPE_ + SPACES(3)
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
int hc_face_delete(hc_sock_t *s, hc_face_t *face, uint8_t delete_listener);
int hc_face_list(hc_sock_t *s, hc_data_t **pdata);
int hc_face_list_async(hc_sock_t *s);  //, hc_data_t ** pdata);

int hc_face_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                            face_state_t state);
#ifdef WITH_POLICY
int hc_face_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                         uint32_t priority);
int hc_face_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                     policy_tags_t tags);
#endif /* WITH_POLICY */

#define foreach_face(VAR, data) foreach_type(hc_face_t, VAR, data)

#define MAX_FACE_ID 255
#define MAXSZ_FACE_ID_ 3
#define MAXSZ_FACE_ID MAXSZ_FACE_ID_ + NULLTERM
#define MAXSZ_FACE_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_FACE_NAME MAXSZ_FACE_NAME_ + NULLTERM

#define MAXSZ_HC_FACE_ \
  MAXSZ_FACE_ID_ + MAXSZ_FACE_NAME_ + MAXSZ_FACE_ + 5 + HOTFIXMARGIN
#define MAXSZ_HC_FACE MAXSZ_HC_FACE_ + NULLTERM

int hc_face_snprintf(char *s, size_t size, hc_face_t *face);

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

typedef struct {
  face_id_t face_id;            /* Kr.  use when name == NULL */
  char name[SYMBOLIC_NAME_LEN]; /* Kr.  use by default vs face_id */
  int family;                   /* Krw */
  ip_address_t remote_addr;     /* krw */
  u8 len;                       /* krw */
  u16 cost;                     /* .rw */
  hc_face_t face;               /* TODO remove, used by hicn_plugin_api */
} hc_route_t;

int hc_route_create(hc_sock_t *s, hc_route_t *route);
hc_result_t *hc_route_create_conf(hc_sock_t *s, hc_route_t *route);
int hc_route_delete(hc_sock_t *s, hc_route_t *route);
int hc_route_list(hc_sock_t *s, hc_data_t **pdata);
int hc_route_list_async(hc_sock_t *s);

#define foreach_route(VAR, data) foreach_type(hc_route_t, VAR, data)

#define MAX_COST 65535
#define MAXSZ_COST 5
#define MAX_LEN 255
#define MAXSZ_LEN 3

#define MAXSZ_HC_ROUTE_ \
  MAXSZ_FACE_ID + 1 + MAXSZ_COST + 1 + MAXSZ_IP_ADDRESS + 1 + MAXSZ_LEN
#define MAXSZ_HC_ROUTE MAXSZ_HC_ROUTE_ + NULLTERM

int hc_route_snprintf(char *s, size_t size, hc_route_t *route);
int hc_route_validate(const hc_route_t *route);

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

typedef struct {
  face_id_t face_id; /* Kr. */  // XXX listener id, could be NULL for all ?
  int family;                   /* Krw */
  ip_address_t prefix;          /* krw */
  u8 prefix_len;                /* krw */
} hc_punting_t;

int hc_punting_create(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_get(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found);
int hc_punting_delete(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_list(hc_sock_t *s, hc_data_t **pdata);

int hc_punting_validate(const hc_punting_t *punting);
int hc_punting_cmp(const hc_punting_t *c1, const hc_punting_t *c2);

#define foreach_punting(VAR, data) foreach_type(hc_punting_t, VAR, data)

#define MAXSZ_HC_PUNTING_ 0
#define MAXSZ_HC_PUNTING MAXSZ_HC_PUNTING_ + NULLTERM

GENERATE_FIND_HEADER(punting);

int hc_punting_snprintf(char *s, size_t size, hc_punting_t *punting);

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

typedef struct {
  uint8_t serve;  // 1 = on, 0 = off
  uint8_t store;  // 1 = on, 0 = off
} hc_cache_t;

typedef struct {
  bool store;
  bool serve;
  size_t cs_size;
  size_t num_stale_entries;
} hc_cache_info_t;

int hc_cache_set_store(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_set_serve(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_clear(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_list(hc_sock_t *s, hc_data_t **pdata);
int hc_cache_snprintf(char *s, size_t size, const hc_cache_info_t *cache_info);

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

#define MAXSZ_STRATEGY_NAME 255

typedef struct {
  // The name is not set by the controller
  // but populated by the daemon
  char name[MAXSZ_STRATEGY_NAME];
  strategy_type_t type;
  ip_address_t address, local_address;
  int family, local_family;
  u8 len, local_len;
} hc_strategy_t;

int hc_strategy_list(hc_sock_t *s, hc_data_t **data);

#define foreach_strategy(VAR, data) foreach_type(hc_strategy_t, VAR, data)

#define MAXSZ_HC_STRATEGY_ MAXSZ_STRATEGY_NAME
#define MAXSZ_HC_STRATEGY MAXSZ_HC_STRATEGY_ + NULLTERM

int hc_strategy_snprintf(char *s, size_t size, hc_strategy_t *strategy);

// per prefix
int hc_strategy_set(hc_sock_t *s, hc_strategy_t *strategy);
hc_result_t *hc_strategy_set_conf(hc_sock_t *s, hc_strategy_t *strategy);
int hc_strategy_add_local_prefix(hc_sock_t *s, hc_strategy_t *strategy);
hc_result_t *hc_strategy_add_local_prefix_conf(hc_sock_t *s,
                                               hc_strategy_t *strategy);
/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
int hc_wldr_set(hc_sock_t *s /* XXX */);

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

typedef enum {
  MAPME_TARGET_ENABLE,
  MAPME_TARGET_DISCOVERY,
  MAPME_TARGET_TIMESCALE,
  MAPME_TARGET_RETX,
} mapme_target_t;

static inline mapme_target_t mapme_target_from_str(char *mapme_target_str) {
  if (strcasecmp(mapme_target_str, "enable") == 0)
    return MAPME_TARGET_ENABLE;
  else if (strcasecmp(mapme_target_str, "discovery") == 0)
    return MAPME_TARGET_DISCOVERY;
  else if (strcasecmp(mapme_target_str, "timescale") == 0)
    return MAPME_TARGET_TIMESCALE;
  else
    return MAPME_TARGET_RETX;
}

#define MAX_MAPME_ARG_LEN 30

typedef struct {
  mapme_target_t target;
  // Command argument stored as a string
  // before being parsed into 'enabled' or 'timescale'
  char unparsed_arg[MAX_MAPME_ARG_LEN];

  uint8_t enabled;     // 1 = on, 0 = off
  uint32_t timescale;  // Milliseconds

  ip_address_t address;
  int family;
  u8 len;
} hc_mapme_t;

int hc_mapme_set(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_discovery(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_timescale(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_retx(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_send_update(hc_sock_t *s, hc_mapme_t *mapme);

/*----------------------------------------------------------------------------*
 * Policies
 *----------------------------------------------------------------------------*/

#ifdef WITH_POLICY

typedef struct {
  int family;               /* Krw */
  ip_address_t remote_addr; /* krw */
  u8 len;                   /* krw */
  hicn_policy_t policy;     /* .rw */
} hc_policy_t;

int hc_policy_create(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_delete(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_list(hc_sock_t *s, hc_data_t **pdata);

#define foreach_policy(VAR, data) foreach_type(hc_policy_t, VAR, data)

/* TODO */
#define MAXSZ_HC_POLICY_ 0
#define MAXSZ_HC_POLICY MAXSZ_HC_POLICY_ + NULLTERM

int hc_policy_snprintf(char *s, size_t size, hc_policy_t *policy);
int hc_policy_validate(const hc_policy_t *policy);

#endif /* WITH_POLICY */

/*----------------------------------------------------------------------------*
 * Subscription
 *----------------------------------------------------------------------------*/
// Topics

#undef PUNTING  // TODO(eloparco): Undefined to avoid collisions
                // Fix the collision

// Used only to create 'hc_topic_t'
typedef struct {
#define _(x) char x;
  foreach_object
#undef _
} object_offset_t;

// Flags for topic subscriptions
typedef enum {
#define _(x) TOPIC_##x = (1 << offsetof(object_offset_t, x)),
  foreach_object
#undef _
} hc_topic_t;

static inline hc_object_type_t object_from_topic(hc_topic_t topic) {
#define _(x) \
  if (topic == TOPIC_##x) return OBJECT_##x;
  foreach_object
#undef _
      return OBJECT_UNDEFINED;
}

#define NUM_TOPICS OBJECT_N  // Because a topic is created for each object
#define ALL_TOPICS ~0

// Subscriptions
typedef uint32_t hc_topics_t;
typedef struct {
  hc_topics_t topics;
} hc_subscription_t;

int hc_subscription_create(hc_sock_t *s, hc_subscription_t *subscription);
int hc_subscription_delete(hc_sock_t *s, hc_subscription_t *subscription);
hc_result_t *hc_subscription_create_conf(hc_sock_t *s,
                                         hc_subscription_t *subscription);
hc_result_t *hc_subscription_delete_conf(hc_sock_t *s,
                                         hc_subscription_t *subscription);

/*----------------------------------------------------------------------------*
 * Events
 *----------------------------------------------------------------------------*/
#define foreach_event_type \
  _(UNDEFINED)             \
  _(INTERFACE_UPDATE)      \
  _(N)
typedef enum {
#define _(x) EVENT_##x,
  foreach_event_type
#undef _
} event_type_t;

extern const char *event_str[];
#define event_str(x) event_str[x]

typedef enum {
  FLAG_INTERFACE_TYPE_WIRED = 0x1,
  FLAG_INTERFACE_TYPE_WIFI = 0x2,
  FLAG_INTERFACE_TYPE_CELLULAR = 0x4,
} flag_interface_type_t;

typedef struct {
  flag_interface_type_t interface_type;
} hc_event_interface_update_t;

/*----------------------------------------------------------------------------*
 * Statistics
 *----------------------------------------------------------------------------*/
int hc_stats_get(hc_sock_t *s, hc_data_t **pdata);   // General stats
int hc_stats_list(hc_sock_t *s, hc_data_t **pdata);  // Per-face stats
int hc_stats_snprintf(char *s, size_t size, const hicn_light_stats_t *stats);

/* Result */

hc_msg_t *hc_result_get_msg(hc_sock_t *s, hc_result_t *result);
int hc_result_get_cmd_id(hc_sock_t *s, hc_result_t *result);
bool hc_result_get_success(hc_sock_t *s, hc_result_t *result);
void hc_result_free(hc_result_t *result);

/* Object */

typedef struct {
  hc_object_type_t type;
  union {
    hc_connection_t connection;
    hc_listener_t listener;
    hc_route_t route;
    hc_face_t face;
    // hc_data_t *data;
    hc_punting_t punting;
    hc_strategy_t strategy;
#ifdef WITH_POLICY
    hc_policy_t policy;
#endif /* WITH_POLICY */
    hc_subscription_t subscription;
    hc_cache_t cache;
    hc_mapme_t mapme;
    uint8_t as_uint8;
  };
} hc_object_t;

typedef struct {
  hc_action_t action;
  hc_object_t object;
} hc_command_t;

#endif /* HICNTRL_API */
