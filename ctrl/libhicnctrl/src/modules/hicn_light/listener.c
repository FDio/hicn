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

#include <assert.h>
#include <hicn/ctrl/api.h>
#include <hicn/util/log.h>

#include "base.h"
#include "../../object_private.h"
#include "listener.h"

static int hicnlight_listener_parse(const u8 *buffer, size_t size,
                                    hc_listener_t *listener) {
  int rc;

  if (size != sizeof(cmd_listener_list_item_t)) return -1;
  cmd_listener_list_item_t *item = (cmd_listener_list_item_t *)buffer;

  if (!IS_VALID_ADDRESS(item->local_address)) {
    ERROR("[hc_listener_parse] Invalid address received");
    return -1;
  }
  if (!IS_VALID_NAME(item->name)) {
    ERROR("[hc_listener_parse] Invalid name received");
    return -1;
  }
  if (!IS_VALID_INTERFACE_NAME(item->interface_name)) {
    ERROR("[hc_listener_parse] Invalid interface_name received");
    return -1;
  }
  if (!IS_VALID_ID(item->id)) {
    ERROR("[hc_listener_parse] Invalid id received");
    return -1;
  }
  if (!IS_VALID_PORT(ntohs(item->local_port))) {
    ERROR("[hc_listener_parse] Invalid port received");
    return -1;
  }
  if (!IS_VALID_FAMILY(item->family)) {
    ERROR("[hc_listener_parse] Invalid family received");
    return -1;
  }
  if (!IS_VALID_TYPE(item->type)) {
    ERROR("[hc_listener_parse] Invalid type received");
    return -1;
  }
  // if (!(IS_VALID_CONNECTION_TYPE(item->type)))
  //      return -1;

  *listener = (hc_listener_t){
      .id = item->id,
      .type = (face_type_t)(item->type),
      .family = (int)(item->family),
      .local_addr =
          item->local_addr,  // UNION_CAST(item->local_addr, ip_address_t),
      .local_port = ntohs(item->local_port),
  };

  rc = snprintf(listener->name, SYMBOLIC_NAME_LEN, "%s", item->name);
  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  rc = snprintf(listener->interface_name, INTERFACE_LEN, "%s",
                item->interface_name);
  if ((rc < 0) || (rc >= INTERFACE_LEN)) return -1;

  if (hc_listener_validate(listener, false) < 0) return -1;
  return 0;
}

int _hicnlight_listener_parse(const uint8_t *buffer, size_t size,
                              hc_object_t *object) {
  return hicnlight_listener_parse(buffer, size, &object->listener);
}

/* LISTENER CREATE */

int hicnlight_listener_serialize_create(const hc_object_t *object,
                                        uint8_t *packet) {
  int rc;
  const hc_listener_t *listener = &object->listener;

  msg_listener_add_t *msg = (msg_listener_add_t *)packet;
  *msg = (msg_listener_add_t){.header =
                                  {
                                      .message_type = REQUEST_LIGHT,
                                      .command_id = COMMAND_TYPE_LISTENER_ADD,
                                      .length = 1,
                                      .seq_num = 0,
                                  },

                              .payload = {
                                  .address = listener->local_addr,
                                  .port = htons(listener->local_port),
                                  .family = (uint8_t)listener->family,
                                  .type = (uint8_t)listener->type,
                              }};

  rc = snprintf(msg->payload.symbolic, SYMBOLIC_NAME_LEN, "%s", listener->name);
  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  rc = snprintf(msg->payload.interface_name, INTERFACE_LEN, "%s",
                listener->interface_name);
  if ((rc < 0) || (rc >= INTERFACE_LEN)) return -1;

  return sizeof(msg_listener_add_t);
}

/* LISTENER DELETE */

int hicnlight_listener_serialize_delete(const hc_object_t *object,
                                        uint8_t *packet) {
  int rc;
  const hc_listener_t *listener = &object->listener;

  msg_listener_remove_t *msg = (msg_listener_remove_t *)packet;
  *msg = (msg_listener_remove_t){.header = {
                                     .message_type = REQUEST_LIGHT,
                                     .command_id = COMMAND_TYPE_LISTENER_REMOVE,
                                     .length = 1,
                                     .seq_num = 0,
                                 }};

  if (listener->id) {
    rc = snprintf(msg->payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d",
                  listener->id);
  } else if (*listener->name) {
    rc = snprintf(msg->payload.symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%s",
                  listener->name);
  } else {
    return -1;
  }

  // For now we only support delete by name or id
#if 0
    hc_listener_t *listener_found;
    if (hc_listener_get(socket, listener, &listener_found) < 0) return -1;
    if (!listener_found) return -1;
    rc = snprintf(payload->symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%d",
                  listener_found->id);
    free(listener_found);
  }
#endif

  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  return sizeof(msg_listener_remove_t);
}

/* LISTENER LIST */

int hicnlight_listener_serialize_list(const hc_object_t *object,
                                      uint8_t *packet) {
  msg_listener_list_t *msg = (msg_listener_list_t *)packet;
  *msg = (msg_listener_list_t){.header = {
                                   .message_type = REQUEST_LIGHT,
                                   .command_id = COMMAND_TYPE_LISTENER_LIST,
                                   .length = 0,
                                   .seq_num = 0,
                               }};

  return sizeof(msg_header_t);  // Do not use msg_listener_list_t
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, listener);
