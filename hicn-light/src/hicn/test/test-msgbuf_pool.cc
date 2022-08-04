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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/msgbuf_pool.h>
#include <hicn/util/pool.h>
}

class MsgbufPoolTest : public ::testing::Test {
 protected:
  MsgbufPoolTest() { msgbuf_pool = msgbuf_pool_create(); }
  virtual ~MsgbufPoolTest() { msgbuf_pool_free(msgbuf_pool); }

  msgbuf_pool_t *msgbuf_pool;
};

TEST_F(MsgbufPoolTest, Create) {
  /* Check msgbuf_pool allocation */
  EXPECT_NE(msgbuf_pool, nullptr);

  /* Check msgbuf_pool size */
  size_t msgbuf_pool_size = pool_hdr(msgbuf_pool->buffers)->alloc_size;
  EXPECT_EQ(msgbuf_pool_size, (size_t)PACKET_POOL_DEFAULT_INIT_SIZE);
}

TEST_F(MsgbufPoolTest, GetMsgbuf) {
  msgbuf_t *msgbuf = NULL;

  /* Get valid msgbuf from msgbuf_pool */
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

  /* Check if the returned id is correct */
  off_t id = msgbuf_pool_get_id(msgbuf_pool, msgbuf);
  EXPECT_EQ(id, msgbuf_id);

  /* Check if the returned msgbuf is correct */
  msgbuf_t *msgbuf_retrieved = msgbuf_pool_at(msgbuf_pool, id);
  EXPECT_EQ(msgbuf_retrieved, msgbuf);
}

TEST_F(MsgbufPoolTest, PutMsgbuf) {
  /* Check that asking a msgbuf right after releasing another one
  returns the same msgbuf */

  msgbuf_t *msgbuf = NULL;

  off_t id1 = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  EXPECT_NE(msgbuf, nullptr);

  msgbuf_pool_put(msgbuf_pool, msgbuf);

  off_t id2 = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  EXPECT_NE(msgbuf, nullptr);

  EXPECT_EQ(id2, id1);
}

TEST_F(MsgbufPoolTest, GetMultipleMsgbufs) {
  const int NUM_MSG = 3;
  msgbuf_t *msgbufs[NUM_MSG];

  /* Check if successful allocation */
  int ret = msgbuf_pool_getn(msgbuf_pool, msgbufs, NUM_MSG);
  EXPECT_EQ(ret, 0);

  /* Check if all msgbufs are valid */
  for (unsigned i = 0; i < NUM_MSG; i++) {
    msgbuf_pool_get_id(msgbuf_pool, msgbufs[i]);
    EXPECT_NE(msgbufs[i], nullptr) << "Invalid index: " << i;
  }
}

TEST_F(MsgbufPoolTest, AcquireMsgbuf) {
  msgbuf_t *msgbuf = NULL;

  // Get msgbuf from msgbuf_pool
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  msgbuf_set_type(msgbuf, HICN_PACKET_TYPE_COMMAND);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

  // Acquire the msgbuf
  msgbuf_pool_acquire(msgbuf);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_EQ(msgbuf->refs, 1u);

  msgbuf_pool_acquire(msgbuf);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_EQ(msgbuf->refs, 2u);
}

TEST_F(MsgbufPoolTest, ReleaseMsgbuf) {
  msgbuf_t *msgbuf = NULL;

  // Get msgbuf from msgbuf_pool
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  msgbuf_set_type(msgbuf, HICN_PACKET_TYPE_COMMAND);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

  // Acquire the msgbuf
  msgbuf_pool_acquire(msgbuf);
  EXPECT_EQ(msgbuf->refs, 1u);

  // Release the msgbuf
  msgbuf_pool_release(msgbuf_pool, &msgbuf);
  EXPECT_EQ(msgbuf, nullptr);
}

TEST_F(MsgbufPoolTest, ReleaseNotAcquiredMsgbuf) {
  msgbuf_t *msgbuf = NULL;

  // Get valid msgbuf from msgbuf_pool
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  msgbuf_set_type(msgbuf, HICN_PACKET_TYPE_COMMAND);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

#ifndef NDEBUG
  // Release the msgbuf even if it is not been acquired
  ASSERT_DEATH(
      {
        msgbuf_pool_release(msgbuf_pool, &msgbuf);
        ;
      },
      ".*Assertion.*");
#endif
}

TEST_F(MsgbufPoolTest, MultipleAcquireAndReleaseMsgbuf) {
  msgbuf_t *msgbuf = NULL;

  // Get msgbuf from msgbuf_pool
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  msgbuf_set_type(msgbuf, HICN_PACKET_TYPE_COMMAND);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

  // Acquire the msgbuf multiple times
  msgbuf_pool_acquire(msgbuf);
  msgbuf_pool_acquire(msgbuf);
  EXPECT_EQ(msgbuf->refs, 2u);

  // Release the msgbuf
  msgbuf_pool_release(msgbuf_pool, &msgbuf);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_EQ(msgbuf->refs, 1u);
  msgbuf_pool_release(msgbuf_pool, &msgbuf);
  EXPECT_EQ(msgbuf, nullptr);
}

TEST_F(MsgbufPoolTest, CloneMsgbuf) {
  msgbuf_t *msgbuf = NULL;
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  msgbuf_set_type(msgbuf, HICN_PACKET_TYPE_COMMAND);
  EXPECT_NE(msgbuf, nullptr);
  EXPECT_NE(msgbuf_id_is_valid((unsigned long)msgbuf_id), 0);

  msgbuf_t *new_msgbuf;
  off_t new_msg_id = msgbuf_pool_clone(msgbuf_pool, &new_msgbuf, msgbuf_id);

  EXPECT_EQ(new_msgbuf, msgbuf_pool_at(msgbuf_pool, new_msg_id));
  EXPECT_NE(new_msgbuf, msgbuf_pool_at(msgbuf_pool, msgbuf_id));
  EXPECT_NE(new_msgbuf, msgbuf);
  EXPECT_TRUE(memcmp(msgbuf, new_msgbuf, sizeof(msgbuf_t)) == 0);
}
