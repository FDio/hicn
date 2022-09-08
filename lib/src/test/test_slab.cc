/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

extern "C"
{
#include <hicn/util/slab.h>
}

class SlabTest : public ::testing::Test
{
protected:
  SlabTest () {}
  virtual ~SlabTest () { slab_free (slab); }

  slab_t *slab;
};

typedef struct
{
  int index;
  int val;
} element_t;

TEST_F (SlabTest, SlabCreateAndGetSingleChunk)
{
  slab = slab_create (element_t, 16);
  ASSERT_NE (slab, nullptr);

  element_t *e = slab_get (element_t, slab);
  ASSERT_NE (e, nullptr);
  slab_put (slab, e);
}

TEST_F (SlabTest, SlabGetChunks)
{
  slab = slab_create (element_t, 2);

  // Force creation of multiple blocks (since initial size is only 2)
  for (int i = 0; i < 100; i++)
    {
      element_t *e = slab_get (element_t, slab);
      EXPECT_NE (e, nullptr);
    }
}

TEST_F (SlabTest, SlabGetAndPutChunksNoResize)
{
  constexpr int NUM_ELEMENTS = 64;
  element_t *elements[NUM_ELEMENTS];
  for (int i = 0; i < NUM_ELEMENTS; i++)
    elements[i] = NULL;

  // Initial size=NUM_ELEMENTS, only one block will be created
  slab = slab_create (element_t, NUM_ELEMENTS);

  for (int i = 0; i < NUM_ELEMENTS; i++)
    {
      elements[i] = slab_get (element_t, slab);
      EXPECT_NE (elements[i], nullptr);
    }

  // Release all chunks
  for (int i = 0; i < NUM_ELEMENTS; i++)
    slab_put (slab, elements[i]);
}

TEST_F (SlabTest, SlabGetAndPutChunks)
{
  constexpr int NUM_ELEMENTS = 100;
  element_t *elements[NUM_ELEMENTS];
  for (int i = 0; i < NUM_ELEMENTS; i++)
    elements[i] = NULL;

  // Initial size=2 while NUM_ELEMENTS=100, to force creation of multiple
  // blocks
  slab = slab_create (sizeof (element_t), 2);

  for (int i = 0; i < NUM_ELEMENTS; i++)
    {
      elements[i] = slab_get (element_t, slab);
      EXPECT_NE (elements[i], nullptr);
    }

  // Release all chunks
  for (int i = 0; i < NUM_ELEMENTS; i++)
    slab_put (slab, elements[i]);
}

TEST_F (SlabTest, SlabGetAndPutSomeChunks)
{
  slab = slab_create (element_t, 2);

  constexpr int NUM_ELEMENTS = 100;
  element_t *elements[NUM_ELEMENTS];
  for (int i = 0; i < NUM_ELEMENTS; i++)
    elements[i] = NULL;

  // Get chunks...
  for (int i = 0; i < NUM_ELEMENTS; i++)
    {
      elements[i] = slab_get (element_t, slab);
      EXPECT_NE (elements[i], nullptr);

      // ...and return only some of them
      if (i % 5 == 0)
	slab_put (slab, elements[i]);
    }
}

TEST_F (SlabTest, SlabGetSameChunkTwice)
{
  slab = slab_create (element_t, 1);

  // Get chunk and update it before returning it
  element_t *e = slab_get (element_t, slab);
  ASSERT_NE (e, nullptr);
  element_t *prev = e;
  e->index = 2;
  e->val = 3;
  slab_put (slab, e);

  // Get a chunk again: it should return the previous one
  // without wiping its memory
  e = slab_get (element_t, slab);
  ASSERT_NE (e, nullptr);
  EXPECT_EQ (e, prev);
  EXPECT_EQ (e->index, 2);
  EXPECT_EQ (e->val, 3);

  // Try to get an additional chunk: it should return a new chunk
  // (different from previous one)
  e = slab_get (element_t, slab);
  EXPECT_NE (e, prev);
}