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
}

class VectorTest : public ::testing::Test {
 protected:
  VectorTest() {
  }

  virtual ~VectorTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {;
    vector_init(vector, 1024, 0);
  }

  virtual void TearDown() {
    vector_free(vector);
  }

  int *vector = NULL;

};

TEST_F(VectorTest, VectorSize)
{
  vector_push(vector, 109);
  vector_push(vector, 109);
  int size = vector_len(vector);
  EXPECT_EQ(size, 2);
  vector_push(vector, 109);
  size = vector_len(vector);
  EXPECT_EQ(size, 3);

}

TEST_F(VectorTest, VectorCheckValue)
{
  vector_push(vector, 109);
  vector_push(vector, 200);
  EXPECT_EQ(vector[0], 109);
  EXPECT_EQ(vector[1], 200);
}

TEST_F(VectorTest, VectorEnsurePos)
{
  printf (" %p\n", vector);
  vector_ensure_pos(vector, 1025);
  for (int i = 0; i <1025; i++) {
    printf("i %d\n", i);
    printf (" %p\n", vector);
    vector_push(vector, i);
  }
  int size = vector_len(vector);
  EXPECT_EQ(size, 1025);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
