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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/connection_table.h>
}

#define CONNECTION_NAME "connection_name_test"
#define CONNECTION_NAME_2 "connection_name_test_2"

class ConnectionTableTest : public ::testing::Test {
 protected:
  ConnectionTableTest() {
    log_conf.log_level = LOG_INFO;

    conn_table_ = connection_table_create();
    pair_ =
        address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));
  }
  virtual ~ConnectionTableTest() { connection_table_free(conn_table_); }

  connection_table_t *conn_table_;
  connection_t *connection_;
  address_pair_t pair_;
};

TEST_F(ConnectionTableTest, CreateTable) {
  /* Check connection_table allocation */
  EXPECT_NE(conn_table_, nullptr);

  /* Check connection_table size */
  size_t conn_table_size = connection_table_len(conn_table_);
  EXPECT_EQ(conn_table_size, (size_t)0);
}

TEST_F(ConnectionTableTest, AddConnection) {
  // Add connection to connection table
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  size_t conn_table_size = connection_table_len(conn_table_);
  EXPECT_EQ(conn_table_size, (size_t)1);
  EXPECT_NE(connection_, nullptr);

  // Get connection by name and by pair
  khiter_t k_name = kh_get_ct_name(conn_table_->id_by_name, CONNECTION_NAME);
  EXPECT_NE(k_name, kh_end(conn_table_->id_by_name));
  khiter_t k_pair = kh_get_ct_pair(conn_table_->id_by_pair, &pair_);
  EXPECT_NE(k_pair, kh_end(conn_table_->id_by_pair));
}

TEST_F(ConnectionTableTest, GetConnection) {
  // Add connection to connection table
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  size_t conn_table_size = connection_table_len(conn_table_);
  EXPECT_EQ(conn_table_size, (size_t)1);
  EXPECT_NE(connection_, nullptr);

  // Get connection by name
  connection_t *connection_retrieved =
      connection_table_get_by_name(conn_table_, CONNECTION_NAME);
  ASSERT_NE(connection_retrieved, nullptr);
  EXPECT_EQ(connection_retrieved, connection_);

  // Get connection by pair
  connection_retrieved = connection_table_get_by_pair(conn_table_, &pair_);
  ASSERT_NE(connection_retrieved, nullptr);
  EXPECT_EQ(connection_retrieved, connection_);
}

TEST_F(ConnectionTableTest, GetConnectionWithIdOutOfRange) {
  connection_t *connection = _connection_table_get_by_id(conn_table_, ~0);
  EXPECT_EQ(connection, nullptr);
}

TEST_F(ConnectionTableTest, GetConnectionWithInvalidId) {
  // First connection inserted has always id equal to 0
  int non_valid_id = 5;

  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  connection_t *connection_not_found =
      connection_table_get_by_id(conn_table_, non_valid_id);
  ASSERT_EQ(connection_not_found, nullptr);
}

TEST_F(ConnectionTableTest, GetConnectionWithValidId) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  int id = connection_table_get_connection_id(conn_table_, connection_);
  connection_t *connection_found = connection_table_get_by_id(conn_table_, id);
  ASSERT_EQ(connection_found, connection_);
}

TEST_F(ConnectionTableTest, GetConnectionIdFromValidName) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  int id = connection_table_get_id_by_name(conn_table_, CONNECTION_NAME);
  ASSERT_TRUE(listener_id_is_valid(id));
}

TEST_F(ConnectionTableTest, GetConnectionIdFromInvalidName) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  int id = connection_table_get_id_by_name(conn_table_, CONNECTION_NAME_2);
  ASSERT_FALSE(listener_id_is_valid(id));
}

TEST_F(ConnectionTableTest, RemoveConnection) {
  // Add connection (connection name and pair must be set)
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  connection_->name = (char *)CONNECTION_NAME;
  connection_->pair = pair_;

  // Remove connection
  int id = connection_table_get_connection_id(conn_table_, connection_);
  connection_table_remove_by_id(conn_table_, id);

  // Check connection table size
  size_t conn_table_size = connection_table_len(conn_table_);
  EXPECT_EQ(conn_table_size, (size_t)0);

  // Check that previous connection is not valid anymore
  connection_t *connection_not_found =
      connection_table_get_by_id(conn_table_, id);
  EXPECT_EQ(connection_not_found, nullptr);
  connection_not_found =
      connection_table_get_by_name(conn_table_, CONNECTION_NAME);
  EXPECT_EQ(connection_not_found, nullptr);
  connection_not_found = connection_table_get_by_pair(conn_table_, &pair_);
  EXPECT_EQ(connection_not_found, nullptr);
}

TEST_F(ConnectionTableTest, PrintTable) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  // Insert an additional connection
  address_pair_t pair_2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(3), _ADDRESS4_LOCALHOST(4));
  connection_t *connection_2 =
      connection_table_allocate(conn_table_, &pair_2, CONNECTION_NAME_2);
  connection_2->type = FACE_TYPE_TCP;

  testing::internal::CaptureStdout();
  connection_table_print_by_pair(conn_table_);
  std::string std_out = testing::internal::GetCapturedStdout();

  ASSERT_NE(std_out, "");

  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:1"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:2"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:3"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:4"));
}

TEST_F(ConnectionTableTest, AddMultipleConnections) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;

  // Insert an additional connection
  address_pair_t pair_2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(3), _ADDRESS4_LOCALHOST(4));
  connection_t *connection_2 =
      connection_table_allocate(conn_table_, &pair_2, CONNECTION_NAME_2);
  connection_2->type = FACE_TYPE_TCP;

  // Check connection table size
  size_t conn_table_size = connection_table_len(conn_table_);
  EXPECT_EQ(conn_table_size, (size_t)2);

  connection_t *c1 = connection_table_get_by_name(conn_table_, CONNECTION_NAME);
  ASSERT_NE(c1, nullptr);
  connection_t *c2 =
      connection_table_get_by_name(conn_table_, CONNECTION_NAME_2);
  ASSERT_NE(c2, nullptr);
  EXPECT_NE(c1, c2);
}

TEST_F(ConnectionTableTest, Iterate) {
  connection_ = connection_table_allocate(conn_table_, &pair_, CONNECTION_NAME);
  connection_->type = FACE_TYPE_TCP;
  connection_->pair = pair_;

  // Insert an additional connection
  address_pair_t pair_2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(3), _ADDRESS4_LOCALHOST(4));
  connection_t *connection_2 =
      connection_table_allocate(conn_table_, &pair_2, CONNECTION_NAME_2);
  connection_2->type = FACE_TYPE_TCP;
  connection_2->pair = pair_2;

  // Iterate over the connection table and count the connections
  connection_t *c;
  int count = 0;
  connection_table_foreach(conn_table_, c, { count++; });
  EXPECT_EQ(count, 2);

  // Iterate over the connection table and check the connections
  char local_addr_str[NI_MAXHOST], remote_addr_str[NI_MAXHOST];
  int local_port, remote_port;
  testing::internal::CaptureStdout();
  connection_table_foreach(conn_table_, c, {
    const address_pair_t *pair = connection_get_pair(c);
    address_to_string(&pair->local, local_addr_str, &local_port);
    address_to_string(&pair->remote, remote_addr_str, &remote_port);

    printf("%s:%d\t%s:%d\n", local_addr_str, local_port, remote_addr_str,
           remote_port);
  });

  std::string std_out = testing::internal::GetCapturedStdout();
  ASSERT_NE(std_out, "");
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:1"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:2"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:3"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:4"));
}
