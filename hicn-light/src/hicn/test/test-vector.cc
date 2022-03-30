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
#include <hicn/base/vector.h>
}

/*
 * TODO
 * - test max_size
 */

#define DEFAULT_SIZE 10
const size_t N_ELEMENTS = 5;

class VectorTest : public ::testing::Test {
 protected:
  VectorTest() { vector_init(vector, DEFAULT_SIZE, 0); }
  virtual ~VectorTest() { vector_free(vector); }

  int *vector = NULL;
};

/* TEST: Vector allocation and initialization */
TEST_F(VectorTest, VectorAllocate) {
  /* Allocated size should be the next power of two */
  EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

  /* Setting elements within the allocated size should not trigger a resize */
  vector_ensure_pos(vector, 15);
  EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

  /* Setting elements after should through */
  vector_ensure_pos(vector, 16);
  EXPECT_EQ(vector_get_alloc_size(vector), 32UL);

  /* Check that free indices and bitmaps are correctly updated */
}

TEST_F(VectorTest, VectorSize) {
  vector_push(vector, 109);
  int size = vector_len(vector);
  EXPECT_EQ(size, 1);
  vector_push(vector, 109);
  size = vector_len(vector);
  EXPECT_EQ(size, 2);
  vector_push(vector, 109);
  size = vector_len(vector);
  EXPECT_EQ(size, 3);
}

TEST_F(VectorTest, VectorCheckValue) {
  vector_push(vector, 109);
  vector_push(vector, 200);
  EXPECT_EQ(vector[0], 109);
  EXPECT_EQ(vector[1], 200);
}

TEST_F(VectorTest, VectorEnsurePos) {
  printf(" %p\n", vector);
  vector_ensure_pos(vector, 1025);
  for (int i = 0; i < 1025; i++) {
    // printf("i %d\n", i);
    // printf (" %p\n", vector);
    vector_push(vector, i);
  }
  int size = vector_len(vector);
  EXPECT_EQ(size, 1025);
}

TEST_F(VectorTest, RemoveElement) {
  // Populate vector
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);
  EXPECT_EQ(vector_len(vector), N_ELEMENTS);
  for (size_t i = 0; i < vector_len(vector); i++) EXPECT_EQ(vector[i], (int)i);

  // Remove element
  int value_to_remove = 3;
  int num_removed = vector_remove_unordered(vector, value_to_remove);

  EXPECT_EQ(vector_len(vector), N_ELEMENTS - 1);
  EXPECT_EQ(num_removed, 1);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_NE(vector[i], value_to_remove);
}

TEST_F(VectorTest, RemoveDuplicatedElement) {
  // Populate vector
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);
  EXPECT_EQ(vector_len(vector), N_ELEMENTS);
  for (size_t i = 0; i < vector_len(vector); i++) EXPECT_EQ(vector[i], (int)i);
  vector[0] = 3;  // Duplicate element

  // Remove (duplicated) elements
  int value_to_remove = 3;
  int num_removed = vector_remove_unordered(vector, value_to_remove);

  EXPECT_EQ(vector_len(vector), N_ELEMENTS - 2);
  EXPECT_EQ(num_removed, 2);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_NE(vector[i], value_to_remove);
}

TEST_F(VectorTest, Iterate) {
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);

  int count = 0;
  int *elem;
  vector_foreach(vector, elem, { EXPECT_EQ(*elem, count++); });
}

TEST_F(VectorTest, MultipleResize) {
  // Use small vector (size=1) to force multiple realloc operations
  int *small_vector;
  vector_init(small_vector, 1, 0);

  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(small_vector, i);

  for (size_t i = 0; i < N_ELEMENTS; i++) EXPECT_EQ(small_vector[i], (int)i);

  EXPECT_EQ(vector_len(small_vector), 5UL);
  EXPECT_EQ(vector_get_alloc_size(small_vector), 8UL);

  vector_free(small_vector);
}