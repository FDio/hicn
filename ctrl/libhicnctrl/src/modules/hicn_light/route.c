/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file modules/hicn_light/route.c
 * \brief Implementation of route object VFT for hicn_light.
 */

#include <assert.h>
#include <hicn/ctrl/api.h>
#include <hicn/util/log.h>
#include "base.h"
#include "route.h"
#include <hicn/ctrl/hicn-light.h>

#include "../../object_private.h"

static int hicnlight_route_parse(const uint8_t *buffer, size_t size,
                                 hc_route_t *route) {
  if (size != sizeof(cmd_route_list_item_t)) return -1;
  cmd_route_list_item_t *item = (cmd_route_list_item_t *)buffer;

  if (!IS_VALID_NAME(item->face_name)) {
    ERROR("[hc_connection_parse] Invalid face_name received");
    return -1;
  }

  if (!IS_VALID_ID(item->face_id)) {
    ERROR("[hc_connection_parse] Invalid face_id received");
    return -1;
  }

  if (!IS_VALID_FAMILY(item->family)) {
    ERROR("[hc_listener_parse] Invalid family received");
    return -1;
  }

  if (!IS_VALID_ADDRESS(item->remote_addr)) {
    ERROR("[hc_connection_parse] Invalid address received");
    return -1;
  }

  // LEN
  // COST

  *route = (hc_route_t){
      .face_name = "", /* This is not reported back */
      .face_id = item->face_id,
      .family = (int)(item->family),
      .remote_addr = item->remote_addr,
      .len = item->len,
      .cost = item->cost,
  };

  if (hc_route_validate(route, false) < 0) return -1;
  return 0;
}

int _hicnlight_route_parse(const uint8_t *buffer, size_t size,
                           hc_object_t *object) {
  return hicnlight_route_parse(buffer, size, &object->route);
}

/* ROUTE CREATE */

int hicnlight_route_serialize_create(const hc_object_t *object,
                                     uint8_t *packet) {
  const hc_route_t *route = &object->route;
  int rc;

  msg_route_add_t *msg = (msg_route_add_t *)packet;
  *msg = (msg_route_add_t){.header =
                               {
                                   .message_type = REQUEST_LIGHT,
                                   .command_id = COMMAND_TYPE_ROUTE_ADD,
                                   .length = 1,
                                   .seq_num = 0,
                               },
                           .payload = {
                               .address = route->remote_addr,
                               .cost = route->cost,
                               .family = route->family,
                               .len = route->len,
                           }};

  /*
   * The route commands expects the ID or name as part of the
   * symbolic_or_connid attribute.
   */
  if (route->face_name[0] != '\0') {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  route->face_name);
  } else {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  route->face_id);
  }

  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  return sizeof(msg_route_add_t);
}

/* ROUTE DELETE */

int hicnlight_route_serialize_delete(const hc_object_t *object,
                                     uint8_t *packet) {
  const hc_route_t *route = &object->route;
  int rc;

  msg_route_remove_t *msg = (msg_route_remove_t *)packet;
  memset(msg, 0, sizeof(msg_route_remove_t));
  *msg = (msg_route_remove_t){.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_ROUTE_REMOVE,
                                      .length = 1,
                                      .seq_num = 0,
                                  },
                              .payload = {
                                  .family = (uint8_t)route->family,
                                  .len = route->len,
                              }};

  /*
   * Direct copy as part of the previous assignment does not work correctly...
   * to be investigated
   */
  memcpy(&msg->payload.address, &route->remote_addr, sizeof(hicn_ip_address_t));

  /*
   * The route commands expects the ID or name as part of the
   * symbolic_or_connid attribute.
   */
  if (route->face_name[0] != '\0') {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  route->face_name);
  } else {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  route->face_id);
  }

  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  return sizeof(msg_route_remove_t);
}

/* ROUTE LIST */

int hicnlight_route_serialize_list(const hc_object_t *object, uint8_t *packet) {
  msg_route_list_t *msg = (msg_route_list_t *)packet;
  *msg = (msg_route_list_t){.header = {
                                .message_type = REQUEST_LIGHT,
                                .command_id = COMMAND_TYPE_ROUTE_LIST,
                                .length = 0,
                                .seq_num = 0,
                            }};

  return sizeof(msg_header_t);  // Do not use msg_route_list_t
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, route);
