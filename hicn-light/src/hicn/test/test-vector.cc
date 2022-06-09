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

extern "C" {
#include <hicn/util/vector.h>
}

static constexpr size_t DEFAULT_SIZE = 10;
static constexpr size_t N_ELEMENTS = 5;

class VectorTest : public ::testing::Test {
 protected:
  VectorTest() { vector_init(vector, DEFAULT_SIZE, 0); }
  virtual ~VectorTest() { vector_free(vector); }

  int *vector = NULL;
};

TEST_F(VectorTest, VectorAllocateAndResize) {
  // Allocated size should be the next power of two
  EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

  // Setting elements within the allocated size should not trigger a resize
  vector_ensure_pos(vector, 15);
  EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

  // Setting elements after should through
  vector_ensure_pos(vector, 16);
  EXPECT_EQ(vector_get_alloc_size(vector), 32UL);
}

TEST_F(VectorTest, VectorSize) {
  EXPECT_EQ(vector_len(vector), 0);

  // Check size after pushing one element
  vector_push(vector, 1);
  EXPECT_EQ(vector_len(vector), 1);

  // Check size after pushing additional elements
  vector_push(vector, 2);
  vector_push(vector, 3);
  EXPECT_EQ(vector_len(vector), 3);

  // Try adding multiple elements
  const int n_elements_to_add = 5;
  size_t expected_new_len = vector_len(vector) + n_elements_to_add;
  for (int i = 0; i < n_elements_to_add; i++) vector_push(vector, i);
  EXPECT_EQ(vector_len(vector), expected_new_len);
}

TEST_F(VectorTest, VectorCheckValue) {
  // Add elements
  vector_push(vector, 109);
  vector_push(vector, 200);
  EXPECT_EQ(vector_at(vector, 0), 109);
  EXPECT_EQ(vector_at(vector, 1), 200);

  // Update element
  vector_set(vector, 1, 400);
  EXPECT_EQ(vector_at(vector, 1), 400);

  // Add at last available position
  size_t prev_size = vector_len(vector);
  vector_set(vector, vector_len(vector) - 1, 123);
  EXPECT_EQ(vector_at(vector, vector_len(vector) - 1), 123);
  EXPECT_EQ(prev_size, vector_len(vector)) << "Size should not have changed";
}

TEST_F(VectorTest, RemoveElement) {
  // Populate vector
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);
  EXPECT_EQ(vector_len(vector), N_ELEMENTS);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_EQ(vector_at(vector, i), (int)i);

  // Remove element
  int value_to_remove = 3;
  int num_removed = vector_remove_unordered(vector, value_to_remove);

  EXPECT_EQ(vector_len(vector), N_ELEMENTS - 1);
  EXPECT_EQ(num_removed, 1);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_NE(vector_at(vector, i), value_to_remove);
}

TEST_F(VectorTest, RemoveNonExistingElement) {
  // Push some initial values
  vector_push(vector, 1);
  vector_push(vector, 2);
  vector_push(vector, 3);
  EXPECT_EQ(vector_len(vector), 3);

  // Remove non-existing element
  int num_removed = vector_remove_unordered(vector, 5);
  EXPECT_EQ(num_removed, 0);
  size_t prev_size = vector_len(vector);
  EXPECT_EQ(prev_size, vector_len(vector)) << "Size should not have changed";
}

TEST_F(VectorTest, RemoveDuplicatedElement) {
  // Populate vector
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);
  EXPECT_EQ(vector_len(vector), N_ELEMENTS);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_EQ(vector_at(vector, i), (int)i);
  vector_set(vector, 0, 3);  // Duplicate element

  // Remove (duplicated) elements
  int value_to_remove = 3;
  int num_removed = vector_remove_unordered(vector, value_to_remove);

  EXPECT_EQ(vector_len(vector), N_ELEMENTS - 2);
  EXPECT_EQ(num_removed, 2);
  for (size_t i = 0; i < vector_len(vector); i++)
    EXPECT_NE(vector_at(vector, i), value_to_remove);
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

  for (size_t i = 0; i < N_ELEMENTS; i++)
    EXPECT_EQ(vector_at(small_vector, i), (int)i);

  EXPECT_EQ(vector_len(small_vector), 5UL);
  EXPECT_EQ(vector_get_alloc_size(small_vector), 8UL);

  vector_free(small_vector);
}

TEST_F(VectorTest, MaxSize) {
  const int max_size = 4;

  // Fill the vector until max size is reached
  int *small_vector;
  vector_init(small_vector, 2, max_size);
  for (int i = 0; i < max_size; i++) vector_push(small_vector, i);

  // Try expanding or appending elements should fail
  int rc = vector_ensure_pos(small_vector, max_size);
  EXPECT_EQ(rc, -1);
  rc = vector_push(small_vector, 123);
  EXPECT_EQ(rc, -1);

  vector_free(small_vector);
}

TEST_F(VectorTest, Contains) {
  // No elements
  EXPECT_EQ(vector_contains(vector, 1), false);

  // Push one element
  vector_push(vector, 1);
  EXPECT_EQ(vector_contains(vector, 1), true);

  // Update element
  vector_set(vector, 0, 2);
  EXPECT_EQ(vector_contains(vector, 1), false);
  EXPECT_EQ(vector_contains(vector, 2), true);
}

TEST_F(VectorTest, Remove) {
  // Remove element at invalid position
  int rc = vector_remove_at(vector, 2);
  EXPECT_EQ(rc, -1);  // Failure

  // Push two elements and remove the second one
  vector_push(vector, 1);
  vector_push(vector, 2);
  rc = vector_remove_at(vector, 1);
  EXPECT_EQ(rc, 0);  // Success
  EXPECT_EQ(vector_len(vector), 1);

  // Push another element: it should replace the previous one
  vector_push(vector, 3);
  EXPECT_EQ(vector_len(vector), 2);
  EXPECT_EQ(vector_at(vector, 1), 3);
}

TEST_F(VectorTest, RemoveInTheMiddle) {
  for (size_t i = 0; i < N_ELEMENTS; i++) vector_push(vector, i);

  // Remove element in central position
  int rc = vector_remove_at(vector, 2);
  EXPECT_EQ(rc, 0);  // Success
  EXPECT_EQ(vector_contains(vector, 2), false);
  EXPECT_EQ(vector_len(vector), N_ELEMENTS - 1);

  // Check if elements have been shifted (preserving the order)
  int expected[] = {0, 1, 3, 4};
  for (int i = 0; i < vector_len(vector); i++)
    EXPECT_EQ(vector_at(vector, i), expected[i]);
}

TEST_F(VectorTest, Reset) {
  vector_push(vector, 1);
  vector_push(vector, 2);
  EXPECT_EQ(vector_len(vector), 2);

  vector_reset(vector);
  EXPECT_EQ(vector_len(vector), 0);

  vector_push(vector, 5);
  EXPECT_EQ(vector_len(vector), 1);
  EXPECT_EQ(vector_contains(vector, 5), true);
  EXPECT_EQ(vector_at(vector, 0), 5);
}