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
 * \file modules/hicn_light.h
 * \brief hicn-light module.
 */

#ifndef HICNCTRL_MODULES_HICN_LIGHT_H
#define HICNCTRL_MODULES_HICN_LIGHT_H

#include "hicn_light/base.h"

typedef struct {
  char *url;
  int fd;

  /* Send buffer */
  hc_msg_t msg;

  /* Partial receive buffer */
  u8 buf[RECV_BUFLEN];
  size_t roff; /**< Read offset */
  size_t woff; /**< Write offset */

  bool got_header;
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
} hc_sock_light_data_t;

extern hc_sock_light_data_t *hc_sock_light_data_create(const char *url);
extern void hc_sock_light_data_free(hc_sock_light_data_t *data);

ssize_t hc_light_command_serialize(hc_action_t action,
                                   hc_object_type_t object_type,
                                   hc_object_t *object, uint8_t *msg);

#endif /* HICNCTRL_MODULES_HICN_LIGHT_H */
