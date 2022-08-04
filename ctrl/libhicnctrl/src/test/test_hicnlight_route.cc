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

extern "C" {
#include <hicn/ctrl/object.h>
#include "../modules/hicn_light/route.h"
}

#include "common.h"

namespace {

const hc_object_t valid_route = {
    .route = {.face_id = 1,
              .face_name = {0},  // NULL, use face_id instead
              .family = AF_INET,
              .remote_addr = IPV4_LOOPBACK,
              .len = 16,
              .cost = 1,
              .face = {0}}};

const std::vector<uint8_t> valid_route_create_payload = {
    /* uint8_t message_type = REQUEST_LIGHT */
    0xc0,
    /* uint8_t command_id = COMMAND_TYPE_ROUTE_ADD */
    0x08,
    /* uint16_t length = 1 */
    0x01, 0x00,
    /* uint32_t seq_num = 0 */
    0x00, 0x00, 0x00, 0x00,
    /* char symbolic_or_connid[16] = "1\0" */
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* hicn_ip_address_t address = {0, 0, 0, 127.0.0.1} */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* */
    0x01,
    /* */
    0x00,
    /* */
    0x02,
    /* */
    0x10};

const std::vector<uint8_t> valid_route_delete_payload = {
    /* uint8_t message_type = REQUEST_LIGHT */
    0xc0,
    /* uint8_t command_id = COMMAND_TYPE_ROUTE_REMOVE */
    0x09,
    /* uint16_t length = 1 */
    0x01, 0x00,
    /* uint32_t seq_num = 0 */
    0x00, 0x00, 0x00, 0x00,

    /* char symbolic_or_connid[16] = "1\0" */
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* hicn_ip_address_t address = {0, 0, 0, 127.0.0.1} */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    /* uint8_t family = AF_INET (2) */
    0x02,
    /* uint8_t len = 16 */
    0x10,
    /* 2-byte padding */
    0x00, 0x00};

const std::vector<uint8_t> valid_route_list_payload = {0xc0, 0x0a, 0x00, 0x00,
                                                       0x00, 0x00, 0x00, 0x00};

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeRouteCreate) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.route, &valid_route, sizeof(hc_route_t));

  hc_serialize_t fn = hicnlight_route_module_ops.serialize[ACTION_CREATE];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_route_create_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_route_create_payload);
}

// TODO
// - create with id != 0
// - create with invalid fields, non zero-terminated strings, etc.

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeRouteDelete) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.route, &valid_route, sizeof(hc_route_t));

  hc_serialize_t fn = hicnlight_route_module_ops.serialize[ACTION_DELETE];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_route_delete_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_route_delete_payload);
}

TEST_F(TestHicnLightSerialize, TestHicnLightSerializeRouteList) {
  uint8_t buf[BUFSIZE];

  hc_object_t obj;
  memset(&obj, 0, sizeof(hc_object_t));
  memcpy(&obj.route, &valid_route, sizeof(hc_route_t));

  hc_serialize_t fn = hicnlight_route_module_ops.serialize[ACTION_LIST];
  size_t n = fn(&obj, buf);

  EXPECT_EQ(n, valid_route_list_payload.size());
  EXPECT_PAYLOAD_EQ(buf, n, valid_route_list_payload);
}

}  // namespace
