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
 */

#ifndef HICNTRL_API
#define HICNTRL_API

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>  // object_offset_t

#include <hicn/ctrl/action.h>
#include <hicn/ctrl/callback.h>
#include <hicn/ctrl/data.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/object_type.h>
#include <hicn/ctrl/objects.h>
#include <hicn/ctrl/socket.h>
#include <hicn/util/ip_address.h>
#include <hicn/face.h>
#include <hicn/strategy.h>

#include <hicn/base.h>
/*
 * This has to be common between hicn-light and hicn-plugin. We now we keep the
 * minimum of the two
 */
#define SYMBOLIC_NAME_LEN 16

#include <hicn/ctrl/objects.h>

#define HICN_DEFAULT_PORT 9695

#define HOTFIXMARGIN 0

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

#define MAX2(x1, x2) (x1 > x2 ? x1 : x2)
#define MAX4(x1, x2, x3, x4) (MAX2(MAX2(x1, x2), MAX2(x3, x4)))
#define MAX8(x1, x2, x3, x4, x5, x6, x7, x8) \
  (MAX2(MAX4(x1, x2, x3, x4), MAX4(x5, x6, x7, x8)))

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

/**
 * \brief hICN control message header
 */
typedef struct hc_msg_s hc_msg_t;
typedef struct hc_result_s hc_result_t;

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
 *  - to use enum instead of type specifiers more appropriate for packet
 * format
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
 * \param [out] pdata - Pointer to the structure storing the results of the
 * call (NULL if no data has been received). If the pointer is NULL, no result
 * will be stored and only the error code will be exposed to the caller. It is
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

#define MAXSZ_HC_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_HC_NAME MAXSZ_HC_NAME_ + NULLTERM

#define MAXSZ_HC_ID_ 10 /* Number of digits for MAX_INT */
#define MAXSZ_HC_ID MAXSZ_HC_ID_ + NULLTERM

#if 0
#define foreach_type(TYPE, VAR, data)    \
  for (TYPE *VAR = (TYPE *)data->buffer; \
       VAR < (TYPE *)((data)->buffer + (data)->size * sizeof(TYPE)); VAR++)
#endif

#define INPUT_ERROR -2
#define UNSUPPORTED_CMD_ERROR -3

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
int hc_wldr_set(hc_sock_t *s /* XXX */);

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * Policies
 *----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*
 * Subscription
 *----------------------------------------------------------------------------*/
// Topics

#if 0
/* Result */

hc_msg_t *hc_result_get_msg(hc_sock_t *s, hc_result_t *result);
int hc_result_get_cmd_id(hc_sock_t *s, hc_result_t *result);
bool hc_result_get_success(hc_sock_t *s, hc_result_t *result);
void hc_result_free(hc_result_t *result);
#endif

/* Object */

// FIXME
#define MAXSZ_HC_SUBSCRIPTION 1

#define MAXSZ_HC_OBJECT                                                       \
  MAX8(MAXSZ_HC_CONNECTION, MAXSZ_HC_LISTENER, MAXSZ_HC_ROUTE, MAXSZ_HC_FACE, \
       MAXSZ_HC_PUNTING, MAXSZ_HC_STRATEGY, MAXSZ_HC_POLICY,                  \
       MAXSZ_HC_SUBSCRIPTION)

typedef struct {
  hc_action_t action;
  hc_object_type_t object_type;
  hc_object_t object;
} hc_command_t;

// NEW API CALLS

// XXX private ?
int _hc_execute(hc_sock_t *s, hc_action_t action, hc_object_type_t object_type,
                hc_object_t *object, hc_result_callback_t callback,
                void *callback_data, hc_data_t **pdata);
int hc_execute(hc_sock_t *s, hc_action_t action, hc_object_type_t object_type,
               hc_object_t *object, hc_data_t **pdata);
int hc_execute_async(hc_sock_t *s, hc_action_t action,
                     hc_object_type_t object_type, hc_object_t *object,
                     hc_result_callback_t callback, void *callback_data);

int hc_object_create(hc_sock_t *s, hc_object_type_t object_type,
                     hc_object_t *object);
int hc_object_get(hc_sock_t *s, hc_object_type_t object_type,
                  hc_object_t *object, hc_object_t **found);
int hc_object_delete(hc_sock_t *s, hc_object_type_t object_type,
                     hc_object_t *object);
int hc_object_list(hc_sock_t *s, hc_object_type_t object_type,
                   hc_data_t **pdata);

/* Former API */

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener);
/* listener_found might eventually be allocated, and needs to be freed */
int hc_listener_get(hc_sock_t *s, hc_listener_t *listener, hc_data_t **pdata);
int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener);
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata);

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection);
/* connection_found might eventually be allocated, and needs to be freed */
int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_data_t **pdata);
int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection);
int hc_connection_update_by_id(hc_sock_t *s, int hc_connection_id,
                               hc_connection_t *connection);
int hc_connection_update(hc_sock_t *s, hc_connection_t *connection_current,
                         hc_connection_t *connection_updated);
int hc_connection_list(hc_sock_t *s, hc_data_t **pdata);

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state);
int hc_connection_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                               uint32_t priority);
int hc_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                           policy_tags_t tags);

/*
int hc_connection_remove_by_id(hc_sock_t * s, char * name);
int hc_connection_remove_by_name(hc_sock_t * s, char * name);
*/

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state);
int hc_connection_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                               uint32_t priority);
int hc_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                           policy_tags_t tags);

int hc_route_create(hc_sock_t *s, hc_route_t *route);
// hc_result_t *hc_route_create_conf(hc_sock_t *s, hc_route_t *route);
int hc_route_delete(hc_sock_t *s, hc_route_t *route);
int hc_route_list(hc_sock_t *s, hc_data_t **pdata);
int hc_route_list_async(hc_sock_t *s);

/**
 * \brief Create a face
 * \param [in] s - hICN socket
 * \param [in,out] face - Parameters of the face to create
 * \return Error code
 *
 * The face parameters will be updated with the face ID.
 */
int hc_face_create(hc_sock_t *s, hc_face_t *face);
int hc_face_get(hc_sock_t *s, hc_face_t *face, hc_data_t **pdata);
int hc_face_delete(hc_sock_t *s,
                   hc_face_t *face);  //, uint8_t delete_listener);
int hc_face_list(hc_sock_t *s, hc_data_t **pdata);
int hc_face_list_async(hc_sock_t *s);

int hc_face_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                            face_state_t state);
int hc_face_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                         uint32_t priority);
int hc_face_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                     policy_tags_t tags);

int hc_strategy_list(hc_sock_t *s, hc_data_t **data);
int hc_strategy_set(hc_sock_t *s, hc_strategy_t *strategy);
int hc_strategy_add_local_prefix(hc_sock_t *s, hc_strategy_t *strategy);

int hc_cache_set_store(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_set_serve(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_clear(hc_sock_t *s, hc_cache_t *cache);
int hc_cache_list(hc_sock_t *s, hc_data_t **pdata);

int hc_mapme_set(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_discovery(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_timescale(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_set_retx(hc_sock_t *s, hc_mapme_t *mapme);
int hc_mapme_send_update(hc_sock_t *s, hc_mapme_t *mapme);

int hc_policy_create(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_delete(hc_sock_t *s, hc_policy_t *policy);
int hc_policy_list(hc_sock_t *s, hc_data_t **pdata);

int hc_punting_create(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_get(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found);
int hc_punting_delete(hc_sock_t *s, hc_punting_t *punting);
int hc_punting_list(hc_sock_t *s, hc_data_t **pdata);

int hc_subscription_create(hc_sock_t *s, hc_subscription_t *subscription);
int hc_subscription_delete(hc_sock_t *s, hc_subscription_t *subscription);

int hc_stats_get(hc_sock_t *s, hc_data_t **pdata);   // General stats
int hc_stats_list(hc_sock_t *s, hc_data_t **pdata);  // Per-face stats
int hc_stats_snprintf(char *s, size_t size, const hicn_light_stats_t *stats);

#endif /* HICNTRL_API */
