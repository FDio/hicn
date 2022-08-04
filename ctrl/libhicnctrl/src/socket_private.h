#ifndef HICNCTRL_SOCKET_PRIVATE_H
#define HICNCTRL_SOCKET_PRIVATE_H

#include <hicn/util/map.h>
#include <hicn/ctrl/socket.h>

#include "module.h"

TYPEDEF_MAP_H(hc_sock_map, int, hc_request_t *);

struct hc_sock_s {
  int request_seq;
  hc_sock_map_t *map;

  bool async;
  int seq_request;

  /*
   * Stores the current request being parsed in case of fragmented reception or
   * analysis (as it is the case now) between header and payload
   */
  hc_request_t *current_request;

  hc_sock_ops_t ops;

  void *data;
  void *handle;
};

hc_request_t *hc_sock_create_request(hc_sock_t *s, hc_action_t action,
                                     hc_object_type_t object_type,
                                     hc_object_t *object,
                                     hc_result_callback_t callback,
                                     void *callback_data);

hc_request_t *hc_sock_get_request(hc_sock_t *s);

void hc_sock_free_request(hc_sock_t *s, hc_request_t *request, bool recursive);

ssize_t hc_sock_serialize_object(hc_sock_t *sock, hc_action_t action,
                                 hc_object_type_t object_type,
                                 hc_object_t *object, uint8_t *msg);

int hc_sock_parse_object(hc_sock_t *sock, hc_object_type_t object_type,
                         uint8_t *buffer, size_t size, hc_object_t *object);

#endif /* HICNCTRL_SOCKET_PRIVATE_H */
