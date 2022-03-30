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
#include <hicn/core/listener_table.h>
}

#define LISTENER_NAME "listener_name_test"
#define LISTENER_NAME_2 "listener_name_test_2"

class ListenerTableTest : public ::testing::Test {
 protected:
  ListenerTableTest() {
    log_conf.log_level = LOG_INFO;

    listener_table_ = listener_table_create();
    key_ = listener_key_factory(_ADDRESS4_LOCALHOST(1), FACE_TYPE_UDP_LISTENER);
  }
  virtual ~ListenerTableTest() { listener_table_free(listener_table_); }

  listener_table_t *listener_table_;
  listener_t *listener_;
  listener_key_t key_;
};

TEST_F(ListenerTableTest, CreateTable) {
  // Check listener_table allocation
  EXPECT_NE(listener_table_, nullptr);

  // Check listener_table size
  size_t listener_table_size = listener_table_len(listener_table_);
  EXPECT_EQ(listener_table_size, (size_t)0);
}

TEST_F(ListenerTableTest, AddListener) {
  // Add listener to listener table
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  size_t listener_table_size = listener_table_len(listener_table_);
  EXPECT_EQ(listener_table_size, (size_t)1);
  EXPECT_NE(listener_, nullptr);

  // Get listener by name and by key
  khiter_t k_name = kh_get_lt_name(listener_table_->id_by_name, LISTENER_NAME);
  EXPECT_NE(k_name, kh_end(listener_table_->id_by_name));
  khiter_t k_key = kh_get_lt_key(listener_table_->id_by_key, &key_);
  EXPECT_NE(k_key, kh_end(listener_table_->id_by_key));
}

TEST_F(ListenerTableTest, GetListener) {
  // Add listener to listener table
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  size_t listener_table_size = listener_table_len(listener_table_);
  EXPECT_EQ(listener_table_size, (size_t)1);
  ASSERT_NE(listener_, nullptr);

  // Get listener by name
  listener_t *listener_retrieved =
      listener_table_get_by_name(listener_table_, LISTENER_NAME);
  ASSERT_NE(listener_retrieved, nullptr);
  EXPECT_EQ(listener_retrieved, listener_);

  // Get listener by key
  listener_retrieved = listener_table_get_by_key(listener_table_, &key_);
  ASSERT_NE(listener_retrieved, nullptr);
  EXPECT_EQ(listener_retrieved, listener_);
}

TEST_F(ListenerTableTest, GetListenerWithIdOutOfRange) {
  listener_t *listener = _listener_table_get_by_id(listener_table_, ~0);
  EXPECT_EQ(listener, nullptr);
}

TEST_F(ListenerTableTest, GetListenerWithInvalidId) {
  // First listener inserted has always id equal to 0
  int non_valid_id = 5;

  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  listener_t *listener_not_found =
      listener_table_get_by_id(listener_table_, non_valid_id);
  ASSERT_EQ(listener_not_found, nullptr);
}

TEST_F(ListenerTableTest, GetListenerWithValidId) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  int id = listener_table_get_listener_id(listener_table_, listener_);
  listener_t *listener_found = listener_table_get_by_id(listener_table_, id);
  ASSERT_EQ(listener_found, listener_);
}

TEST_F(ListenerTableTest, GetListenerIdFromValidName) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  int id = listener_table_get_id_by_name(listener_table_, LISTENER_NAME);
  ASSERT_TRUE(listener_id_is_valid(id));
}

TEST_F(ListenerTableTest, GetListenerIdFromInvalidName) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  int id = listener_table_get_id_by_name(listener_table_, LISTENER_NAME_2);
  ASSERT_FALSE(listener_id_is_valid(id));
}

TEST_F(ListenerTableTest, RemoveListener) {
  // Add listener (listerner name and key must be set)
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;
  listener_->name = (char *)LISTENER_NAME;
  listener_->key = key_;

  // Remove listener
  int id = listener_table_get_listener_id(listener_table_, listener_);
  listener_table_remove_by_id(listener_table_, id);

  // Check listener table size
  size_t listener_table_size = listener_table_len(listener_table_);
  EXPECT_EQ(listener_table_size, (size_t)0);

  // Check that previous listener is not valid anymore
  listener_t *listener_not_found =
      listener_table_get_by_id(listener_table_, id);
  EXPECT_EQ(listener_not_found, nullptr);
  listener_not_found =
      listener_table_get_by_name(listener_table_, LISTENER_NAME);
  EXPECT_EQ(listener_not_found, nullptr);
  listener_not_found = listener_table_get_by_key(listener_table_, &key_);
  EXPECT_EQ(listener_not_found, nullptr);
}

TEST_F(ListenerTableTest, PrintTable) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  // Insert an additional listener
  listener_key_t key_2 =
      listener_key_factory(_ADDRESS4_LOCALHOST(2), FACE_TYPE_TCP_LISTENER);
  listener_t *listener_2 =
      listener_table_allocate(listener_table_, &key_2, LISTENER_NAME_2);
  listener_2->type = FACE_TYPE_UDP_LISTENER;

  testing::internal::CaptureStdout();
  listener_table_print_by_key(listener_table_);
  std::string std_out = testing::internal::GetCapturedStdout();

  ASSERT_NE(std_out, "");
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:1"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:2"));
}

TEST_F(ListenerTableTest, AddMultipleListeners) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;

  // Insert an additional listener
  listener_key_t key_2 =
      listener_key_factory(_ADDRESS4_LOCALHOST(2), FACE_TYPE_TCP_LISTENER);
  listener_t *listener_2 =
      listener_table_allocate(listener_table_, &key_2, LISTENER_NAME_2);
  listener_2->type = FACE_TYPE_UDP_LISTENER;

  // Check listener table size
  size_t listener_table_size = listener_table_len(listener_table_);
  EXPECT_EQ(listener_table_size, (size_t)2);

  listener_t *l1 = listener_table_get_by_name(listener_table_, LISTENER_NAME);
  ASSERT_NE(l1, nullptr);
  listener_t *l2 = listener_table_get_by_name(listener_table_, LISTENER_NAME_2);
  ASSERT_NE(l2, nullptr);
  EXPECT_NE(l1, l2);
}

TEST_F(ListenerTableTest, Iterate) {
  listener_ = listener_table_allocate(listener_table_, &key_, LISTENER_NAME);
  listener_->type = FACE_TYPE_UDP_LISTENER;
  listener_->key = key_;

  // Insert an additional listener
  listener_key_t key_2 =
      listener_key_factory(_ADDRESS4_LOCALHOST(2), FACE_TYPE_TCP_LISTENER);
  listener_t *listener_2 =
      listener_table_allocate(listener_table_, &key_2, LISTENER_NAME_2);
  listener_2->type = FACE_TYPE_UDP_LISTENER;
  listener_2->key = key_2;

  // Iterate over the listener table and count the listeners
  listener_t *l;
  int count = 0;
  listener_table_foreach(listener_table_, l, { count++; });
  EXPECT_EQ(count, 2);

  // Iterate over the listener table and check the listeners
  char addr_str[NI_MAXHOST];
  int port;
  testing::internal::CaptureStdout();
  listener_table_foreach(listener_table_, l, {
    address_to_string(&l->address, addr_str, &port);
    printf("%s\t%s:%d\n", face_type_str(l->type), addr_str, port);
  });

  std::string std_out = testing::internal::GetCapturedStdout();
  ASSERT_NE(std_out, "");
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:1"));
  EXPECT_THAT(std_out, testing::HasSubstr("127.0.0.1:2"));
  EXPECT_THAT(std_out, testing::HasSubstr("UDP"));
  EXPECT_THAT(std_out, testing::HasSubstr("TCP"));
}
