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

/* dummy */
typedef struct {
} cmd_mapme_list_item_t;

DECLARE_MODULE_OBJECT_OPS(hicnlight, mapme);
