/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
 * \file modules/hicn_light/stats.c
 * \brief Implementation of stats object VFT for hicn_light.
 */

#include <hicn/util/log.h>
#include "base.h"
#include "stats.h"

/* GENERAL STATS */

int hicnlight_stats_parse(const uint8_t *buffer, size_t size,
                          hc_stats_t *stats) {
  if (size != sizeof(cmd_stats_list_item_t)) return -1;

  cmd_stats_list_item_t *item = (cmd_stats_list_item_t *)buffer;
  *stats = item->stats;
  return 0;
}

int _hicnlight_stats_parse(const uint8_t *buffer, size_t size,
                           hc_object_t *object) {
  return hicnlight_stats_parse(buffer, size, &object->stats);
}

int hicnlight_stats_serialize_create(const hc_object_t *object,
                                     uint8_t *packet) {
  return -1;
}

int hicnlight_stats_serialize_delete(const hc_object_t *object,
                                     uint8_t *packet) {
  return -1;
}

int hicnlight_stats_serialize_list(const hc_object_t *object, uint8_t *packet) {
  msg_stats_list_t *msg = (msg_stats_list_t *)packet;
  *msg = (msg_stats_list_t){.header = {
                                .message_type = REQUEST_LIGHT,
                                .command_id = COMMAND_TYPE_STATS_LIST,
                                .length = 0,
                                .seq_num = 0,
                            }};

  return sizeof(msg_header_t);  // Do not use msg_stats_list_t
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, stats);

/* PER-FACE STATS */

int hicnlight_face_stats_parse(const uint8_t *buffer, size_t size,
                               hc_face_stats_t *stats) {
  if (size != sizeof(cmd_face_stats_list_item_t)) return -1;

  cmd_face_stats_list_item_t *item = (cmd_face_stats_list_item_t *)buffer;
  *stats = item->stats;
  return 0;
}

int _hicnlight_face_stats_parse(const uint8_t *buffer, size_t size,
                                hc_object_t *object) {
  return hicnlight_face_stats_parse(buffer, size, &object->face_stats);
}

int hicnlight_face_stats_serialize_create(const hc_object_t *object,
                                          uint8_t *packet) {
  return -1;
}

int hicnlight_face_stats_serialize_delete(const hc_object_t *object,
                                          uint8_t *packet) {
  return -1;
}

int hicnlight_face_stats_serialize_list(const hc_object_t *object,
                                        uint8_t *packet) {
  msg_face_stats_list_t *msg = (msg_face_stats_list_t *)packet;
  *msg = (msg_face_stats_list_t){.header = {
                                     .message_type = REQUEST_LIGHT,
                                     .command_id = COMMAND_TYPE_FACE_STATS_LIST,
                                     .length = 0,
                                     .seq_num = 0,
                                 }};

  return sizeof(msg_header_t);  // Do not use msg_stats_list_t
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, face_stats);
