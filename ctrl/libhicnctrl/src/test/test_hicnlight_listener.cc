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

#include <sstream>

extern "C" {
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/listener.h>
#include "../modules/hicn_light/listener.h"
}

#include "common.h"

namespace {

static const hc_object_t valid_listener = {
    .listener = {.name = {'l', 's', 't', 0},
                 .interface_name = {'l', 'o', 0},
                 .id = 0,
                 .type = FACE_TYPE_UDP_LISTENER,
                 .family = AF_INET,
                 .local_addr = IPV4_LOOPBACK,
                 .local_port = 9695}};

const std::vector<uint8_t> valid_listener_create_payload = {
    /* header */
    0xc0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* char name[SYMBOLIC_NAME_LEN] = "lst"; */
    0x6c, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* char interface_name[INTERFACE_LEN] = "lo"; */
    0x6c, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* ip_address_t local_addr = [padding] 127.0.0.1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* uint16_t local_port = 9695;     */
    0x25, 0xdf,
    /* int family = AF_INET; */
    0x02,
    /* face_type_t type = FACE_TYPE_UDP_LISTENER; */
    0x06};

const std::vector<uint8_t> valid_listener_delete_payload = {
    /* header */
    0xc0, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* char symbolicOrListenerid[SYMBOLIC_NAME_LEN] = "lst"; */
    0x6c, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

const std::vector<uint8_t> valid_listener_list_payload = {
    /* header */
    0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* @see <hicn/ctrl/objects/listener.h> */
const std::vector<uint8_t> valid_listener_payload = {
    /* char name[SYMBOLIC_NAME_LEN] = "lst"; */
    0x6c, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* char interface_name[INTERFACE_LEN] = "lo"; */
    0x6c, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* ip_address_t local_addr =  [padding] 127.0.0.1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* uint32_t id = 0; */
    0x00, 0x00, 0x00, 0x00,
    /* uint16_t local_port = 9695;     */
    0x25, 0xdf,
    /* face_type_t type = FACE_TYPE_UDP */
    0x06,
    /* int family = AF_INET; */
    0x02};

TEST_F(TestHicnLightParse, TestHicnLightParseListener) {
  /* Parse payload into an object */
  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  int rc = hicnlight_listener_module_ops.parse(
      &valid_listener_payload[0], valid_listener_payload.size(), &obj);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(hc_listener_cmp(&obj.listener, &valid_listener.listener), 0);
}

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeListenerCreate) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.listener, &valid_listener, sizeof(hc_listener_t));

  hc_serialize_t fn = hicnlight_listener_module_ops.serialize[ACTION_CREATE];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_listener_create_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_listener_create_payload);
}

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeListenerDelete) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.listener, &valid_listener, sizeof(hc_listener_t));

  hc_serialize_t fn = hicnlight_listener_module_ops.serialize[ACTION_DELETE];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_listener_delete_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_listener_delete_payload);
}

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeListenerList) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.listener, &valid_listener, sizeof(hc_listener_t));

  hc_serialize_t fn = hicnlight_listener_module_ops.serialize[ACTION_LIST];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_listener_list_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_listener_list_payload);
}
}  // namespace
