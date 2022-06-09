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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#define WITH_TESTS
#include <hicn/util/ring.h>
}

#define DEFAULT_SIZE 10UL

class RingTest : public ::testing::Test {
 protected:
  RingTest() { ring_init(ring, DEFAULT_SIZE); }
  virtual ~RingTest() { ring_free(ring); }

  int *ring = NULL;
};

/* TEST: Ring allocation and initialization */
TEST_F(RingTest, RingAddOne) {
  int val = -1;
  /* Allocated size should be the next power of two */
  EXPECT_EQ(ring_get_size(ring), 0UL);
  ring_add_value(ring, 1);
  EXPECT_EQ(ring_get_size(ring), 1UL);
  ring_get(ring, 0, &val);
  EXPECT_EQ(val, 1);
  EXPECT_EQ(ring_get_size(ring), 1UL);
  ring_advance(ring, 1);
  EXPECT_EQ(ring_get_size(ring), 0UL);
}

TEST_F(RingTest, RingAddMany) {
  size_t i = 0;
  int val = -1;
  size_t count = 0;

  /* Allocated size should be the next power of two */
  EXPECT_EQ(ring_get_size(ring), 0UL);
  for (unsigned i = 0; i < DEFAULT_SIZE; i++) ring_add_value(ring, i);
  EXPECT_EQ(ring_get_size(ring), DEFAULT_SIZE);

  count = 0;
  ring_enumerate_n(ring, i, &val, 1, {
    EXPECT_EQ(val, (int)(i));
    count++;
  });
  EXPECT_EQ(count, 1UL);

  count = 0;
  ring_enumerate_n(ring, i, &val, DEFAULT_SIZE, {
    EXPECT_EQ(val, (int)(i));
    count++;
  });
  EXPECT_EQ(count, DEFAULT_SIZE);

  count = 0;
  ring_enumerate_n(ring, i, &val, DEFAULT_SIZE + 1, {
    EXPECT_EQ(val, (int)(i));
    count++;
  });
  EXPECT_EQ(count, DEFAULT_SIZE);

  // Drop one
  ring_add_value(ring, DEFAULT_SIZE);
  EXPECT_EQ(ring_get_size(ring), DEFAULT_SIZE);

  count = 0;
  ring_enumerate_n(ring, i, &val, DEFAULT_SIZE, {
    EXPECT_EQ(val, (int)(i + 1));  // all values shoud be shifted
    count++;
  });
  EXPECT_EQ(count, DEFAULT_SIZE);

  ring_advance(ring, DEFAULT_SIZE);
  EXPECT_EQ(ring_get_size(ring), 0UL);
}
