#ifndef HICNCTRL_MODULE_H
#define HICNCTRL_MODULE_H

#include <stdint.h>

#include <hicn/ctrl/data.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/socket.h>

#include "request.h"

/*
 * execute is used for sync code (eg. in VPP), while serialize/parse for
 * sync/async code (eg. in hicn-light).
 */
typedef int (*hc_execute_t)(hc_sock_t *, hc_object_t *, hc_data_t *);
typedef int (*hc_serialize_t)(const hc_object_t *, uint8_t *);

typedef struct {
  int (*parse)(const uint8_t *buffer, size_t size, hc_object_t *object);
  size_t serialized_size;
  hc_serialize_t serialize[ACTION_N];
  hc_execute_t execute[ACTION_N];
} hc_module_object_ops_t;

#define HC_MODULE_OBJECT_OPS_EMPTY       \
  (hc_module_object_ops_t) {             \
    .parse = NULL, .serialized_size = 0, \
    .execute =                           \
        {                                \
            [ACTION_CREATE] = NULL,      \
            [ACTION_DELETE] = NULL,      \
            [ACTION_LIST] = NULL,        \
        },                               \
    .serialize = {                       \
        [ACTION_CREATE] = NULL,          \
        [ACTION_DELETE] = NULL,          \
        [ACTION_LIST] = NULL,            \
    },                                   \
  }

#define DECLARE_MODULE_OBJECT_OPS_H(PREFIX, NAME) \
  extern const hc_module_object_ops_t PREFIX##_##NAME##_module_ops;

/* Underscore'd functions take a hc_object_t as a parameter */

#define HC_MODULE_OBJECT_OPS(PREFIX, NAME)                  \
  (hc_module_object_ops_t) {                                \
    .parse = _##PREFIX##_##NAME##_parse,                    \
    .serialized_size = sizeof(cmd_##NAME##_list_item_t),    \
    .execute =                                              \
        {                                                   \
            [ACTION_CREATE] = NULL,                         \
            [ACTION_DELETE] = NULL,                         \
            [ACTION_LIST] = NULL,                           \
        },                                                  \
    .serialize = {                                          \
      [ACTION_CREATE] = PREFIX##_##NAME##_serialize_create, \
      [ACTION_DELETE] = PREFIX##_##NAME##_serialize_delete, \
      [ACTION_LIST] = PREFIX##_##NAME##_serialize_list,     \
    }                                                       \
  }

#define DECLARE_MODULE_OBJECT_OPS(PREFIX, NAME)                 \
  const hc_module_object_ops_t PREFIX##_##NAME##_module_ops = { \
      .parse = _##PREFIX##_##NAME##_parse,                      \
      .serialized_size = sizeof(cmd_##NAME##_list_item_t),      \
      .execute =                                                \
          {                                                     \
              [ACTION_CREATE] = NULL,                           \
              [ACTION_DELETE] = NULL,                           \
              [ACTION_LIST] = NULL,                             \
          },                                                    \
      .serialize = {                                            \
          [ACTION_CREATE] = PREFIX##_##NAME##_serialize_create, \
          [ACTION_DELETE] = PREFIX##_##NAME##_serialize_delete, \
          [ACTION_LIST] = PREFIX##_##NAME##_serialize_list,     \
      }};

#define DECLARE_VPP_MODULE_OBJECT_OPS(PREFIX, NAME)             \
  const hc_module_object_ops_t PREFIX##_##NAME##_module_ops = { \
      .execute =                                                \
          {                                                     \
              [ACTION_CREATE] = PREFIX##_##NAME##_create,       \
              [ACTION_DELETE] = PREFIX##_##NAME##_delete,       \
              [ACTION_LIST] = PREFIX##_##NAME##_list,           \
          },                                                    \
      .serialize =                                              \
          {                                                     \
              [ACTION_CREATE] = NULL,                           \
              [ACTION_DELETE] = NULL,                           \
              [ACTION_LIST] = NULL,                             \
          },                                                    \
  };

typedef struct {
  /** Create module-specific data storage */
  void *(*create_data)(const char *);

  /** Release module-specific data storage */
  void (*free_data)(void *);

  /** Retrieve underlying file descriptor */
  int (*get_fd)(hc_sock_t *);

  /** Retrieve underlying receive buffer */
  int (*get_recv_buffer)(hc_sock_t *, uint8_t **buffer, size_t *size);

  /** Connect control socket to the forwarder */
  int (*connect)(hc_sock_t *);

  /** Disconnect control socket from forwarder */
  int (*disconnect)(hc_sock_t *);

  /** Populate the TX buffer with the serialization of the next request to be
   * sent */
  ssize_t (*prepare)(hc_sock_t *, hc_request_t *, uint8_t **buffer);

  /** Send the content of the TX buffer */
  int (*send)(hc_sock_t *, uint8_t *buffer, size_t size);

  /** Receive responses in the RX buffer */
  int (*recv)(hc_sock_t *);

  /** Process the content of the RX buffer to populate result data */
  int (*process)(hc_sock_t *, size_t count);

  hc_module_object_ops_t object_vft[OBJECT_TYPE_N];
} hc_sock_ops_t;

#endif /* HICNCTRL_MODULE_H */
