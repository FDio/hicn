/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <hicn/base/vector.h>
#include <hicn/base/bitmap.h>
}

class BitmapTest : public ::testing::Test {
 protected:
  BitmapTest() {
  }

  virtual ~BitmapTest() {
   
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    bitmap_init(bitmap, 1024);
  }

  virtual void TearDown() {
    free(bitmap);
  }
  uint32_t *bitmap;
};

TEST_F(BitmapTest, BitmapSet)
{
  bitmap_set(bitmap, 20);
  EXPECT_TRUE(bitmap_is_set(bitmap, 20) == true);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 20) == false);
  EXPECT_TRUE(bitmap_is_set(bitmap, 19) == false);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 19) == true);

}

TEST_F(BitmapTest, BitmapUnSet) {
  bitmap_set(bitmap, 20);
  bitmap_set(bitmap, 19);
  bitmap_unset(bitmap, 20);
  EXPECT_TRUE(bitmap_is_set(bitmap, 20) == false);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 20) == true);
  EXPECT_TRUE(bitmap_is_set(bitmap, 19) == true);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 19) == false);

}

TEST_F(BitmapTest, BitmapSetTo) {
  bitmap_set_to(bitmap, 40);
  EXPECT_TRUE(bitmap_is_set(bitmap, 20) == true);
  EXPECT_TRUE(bitmap_is_set(bitmap, 21) == true);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 41) == true);
  EXPECT_TRUE(bitmap_is_unset(bitmap, 42) == true);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
