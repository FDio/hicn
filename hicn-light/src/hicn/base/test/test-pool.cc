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
#include <hicn/base/pool.h>
}

class PoolTest : public ::testing::Test {
 protected:
  PoolTest() {
  }

  virtual ~PoolTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
   
  }

  virtual void TearDown() {
    pool_free(pool);
  }

  int *pool;
};

TEST_F(PoolTest, PoolPut)
{
   pool_init(pool, 1024);
  int* elt;
  pool_get(pool, elt);
  *elt = 10;
    printf("2\n");
  pool_put(pool, elt);
    printf("3\n");
  
  //pool_get(pool)
    //loop_ = loop_create();
    //EXPECT_TRUE(loop_ != NULL);
}


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
