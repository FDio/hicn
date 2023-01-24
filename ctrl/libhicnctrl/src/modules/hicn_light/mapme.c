/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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
 * \file modules/hicn_light/mapme.c
 * \brief Implementation of mapme object VFT for hicn_light.
 */

#include <hicn/ctrl/hicn-light.h>
#include "mapme.h"

static int hicnlight_mapme_parse(const uint8_t *buffer, size_t size,
                                 hc_mapme_t *mapme) {
  return -1;
}

int _hicnlight_mapme_parse(const uint8_t *buffer, size_t size,
                           hc_object_t *object) {
  return hicnlight_mapme_parse(buffer, size, &object->mapme);
}

int hicnlight_mapme_serialize_create(const hc_object_t *object,
                                     uint8_t *packet) {
  const hc_mapme_t *mapme = &object->mapme;

  msg_mapme_add_t *msg = (msg_mapme_add_t *)packet;
  *msg = (msg_mapme_add_t){.header =
                               {
                                   .message_type = REQUEST_LIGHT,
                                   .command_id = COMMAND_TYPE_MAPME_ADD,
                                   .length = 1,
                                   .seq_num = 0,
                               },

                           .payload = {.face_id = mapme->face_id,
                                       .family = mapme->family,
                                       .address = mapme->address,
                                       .len = mapme->len}};

  return sizeof(msg_mapme_add_t);
}

int hicnlight_mapme_serialize_delete(const hc_object_t *object,
                                     uint8_t *packet) {
  return -1;
}

int hicnlight_mapme_serialize_list(const hc_object_t *object, uint8_t *packet) {
  return -1;
}

int hicnlight_mapme_serialize_set(const hc_object_t *object, uint8_t *packet) {
  return -1;
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, mapme);

#if 0
static int _hcng_mapme_set(hc_sock_t *socket, int enabled) {
#if 0
  msg_mapme_enable_t msg = {.header =
                                {
                                    .message_type = REQUEST_LIGHT,
                                    .command_id = COMMAND_TYPE_MAPME_ENABLE,
                                    .length = 1,
                                    .seq_num = 0,
                                },
                            .payload = {
                                .activate = enabled,
                            }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_ENABLE,
      .size_in = sizeof(cmd_mapme_enable_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_discovery(hc_sock_t *socket, int enabled) {
#if 0
  msg_mapme_enable_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .activate = enabled,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_DISCOVERY,
      .size_in = sizeof(cmd_mapme_set_discovery_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_timescale(hc_sock_t *socket, uint32_t timescale) {
#if 0
  msg_mapme_set_timescale_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .timePeriod = timescale,
      }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_TIMESCALE,
      .size_in = sizeof(cmd_mapme_set_timescale_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_set_retx(hc_sock_t *socket, uint32_t timescale) {
#if 0
  msg_mapme_set_retx_t msg = {.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_MAPME_SET_RETX,
                                      .length = 1,
                                      .seq_num = 0,
                                  },
                              .payload = {
                                  .timePeriod = timescale,
                              }};

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_MAPME_SET_RETX,
      .size_in = sizeof(msg_mapme_set_retx_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}

static int _hcng_mapme_send_update(hc_sock_t *socket, hc_mapme_t *mapme) {
#if 0
  if (!IS_VALID_FAMILY(mapme->family)) return -1;

  msg_mapme_send_update_t msg = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
              .length = 1,
              .seq_num = 0,
          },
  };

  hc_command_params_t params = {
      .cmd = ACTION_UPDATE,
      .cmd_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
      .size_in = sizeof(msg_mapme_send_update_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hcng_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, false);
#endif
  return 0;  // XXX added
}
#endif
