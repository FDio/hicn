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

#include <gtest/gtest.h>
#include <sstream>

#include <hicn/ctrl/object.h>

#include "../modules/hicn_light/connection.h"
#include "common.h"

namespace {

const hc_object_t valid_connection = {
    .connection = {.id = 0,
                   .name = {'l', 's', 't', 0},
                   .interface_name = {'l', 'o', 0},
                   .netdevice_type = NETDEVICE_TYPE_WIRED,
                   .type = FACE_TYPE_UDP,
                   .family = AF_INET,
                   .local_addr = IPV4_LOOPBACK,
                   .local_port = 9695,
                   .remote_addr = IPV4_LOOPBACK,
                   .remote_port = 9695,
                   .admin_state = FACE_STATE_UP,
                   .priority = 0,
                   .tags = POLICY_TAGS_EMPTY,
                   .state = FACE_STATE_UP}};

const std::vector<uint8_t> valid_connection_create_payload = {
    /* header */
    0xc0, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* char name[SYMBOLIC_NAME_LEN] = "lst"; */
    0x6c, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* ip_address_t local_addr = [padding] 127.0.0.1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* ip_address_t remote_addr = [padding] 127.0.0.1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* uint16_t local_port = 9695;     */
    0x25, 0xdf,
    /* uint16_t remote_port = 9695;     */
    0x25, 0xdf,
    /* int family = AF_INET; */
    0x02,
    /* face_type_t type = FACE_TYPE_UDP_LISTENER; */
    0x05,
    /* uint8_t admin_state = FACE_STATE_UP; */
    0x02,
    /* Padding ? */
    0x00,
    /* uint32_t priority = 0; */
    0x00, 0x00, 0x00, 0x00,
    /* policy_tags_t tags; */
    0x00, 0x00, 0x00, 0x00};

const std::vector<uint8_t> valid_connection_delete_payload = {
    0xc0, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x73, 0x74, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const std::vector<uint8_t> valid_connection_list_payload = {
    0xc0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeConnectionCreate) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.connection, &valid_connection, sizeof(hc_connection_t));

  hc_serialize_t fn = hicnlight_connection_module_ops.serialize[ACTION_CREATE];
  size_t n = fn(&obj, buf);

  // XXX debug
  // THIS HAS UNINIT VALUES
  std::cout << "n=" << n << std::endl;
  EXPECT_EQ(memcmp(buf, buf, 60), 0);
  EXPECT_EQ(memcmp(buf, buf, 62), 0);
  EXPECT_EQ(memcmp(buf, buf, 64), 0);  // XXX we start having issues
  EXPECT_EQ(memcmp(buf, buf, 66), 0);
  EXPECT_EQ(memcmp(buf, buf, 68), 0);
  EXPECT_EQ(memcmp(buf, buf, 70), 0);
  EXPECT_EQ(memcmp(buf, buf, 72), 0);
  // XXX debug

  EXPECT_EQ(n, valid_connection_create_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_connection_create_payload);
}

// TODO
// - create with id != 0
// - create with invalid fields, non zero-terminated strings, etc.

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeConnectionDelete) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.connection, &valid_connection, sizeof(hc_connection_t));

  hc_serialize_t fn = hicnlight_connection_module_ops.serialize[ACTION_DELETE];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_connection_delete_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_connection_delete_payload);
}

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeConnectionList) {
  uint8_t buf[BUFSIZE];

  hc_serialize_t fn = hicnlight_connection_module_ops.serialize[ACTION_LIST];
  size_t n = fn(NULL, buf);

  EXPECT_EQ(n, valid_connection_list_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_connection_list_payload);
}

}  // namespace
