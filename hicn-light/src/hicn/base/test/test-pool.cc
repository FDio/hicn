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
#define WITH_TESTS
#include <hicn/base/pool.h>
}

/*
 * TODO
 * - test max_size
 */

#define DEFAULT_SIZE 10

class PoolTest : public ::testing::Test {
protected:
    PoolTest() { }
    virtual ~PoolTest() { }

    int *pool;
};

TEST_F(PoolTest, PoolAllocation)
{
    int rc;

    pool_init(pool, DEFAULT_SIZE, 0);

    size_t pool_size = next_pow2(DEFAULT_SIZE);

    EXPECT_EQ(pool_get_alloc_size(pool), pool_size);

    /* Check that free indices and bitmaps are correctly initialize */
    off_t * fi = pool_get_free_indices(pool);
    EXPECT_EQ(vector_len(fi), pool_size);
    EXPECT_EQ(fi[0], (long) (pool_size - 1));
    EXPECT_EQ(fi[pool_size - 1], 0);

    /* The allocated size of the underlying vector should be the next power of two */
    EXPECT_EQ(vector_get_alloc_size(fi), pool_size);

    bitmap_t * fb = pool_get_free_bitmap(pool);
    EXPECT_TRUE(bitmap_is_set(fb, 0));
    EXPECT_TRUE(bitmap_is_set(fb, pool_size - 2));
    EXPECT_TRUE(bitmap_is_set(fb, pool_size - 1));
    EXPECT_TRUE(bitmap_is_unset(fb, pool_size));

    /* Getting elements from the pool should correctly update the free indices
     * and bitmap */
    int * elt;

    rc = pool_get(pool, elt);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(vector_len(fi), pool_size - 1);
    EXPECT_TRUE(bitmap_is_unset(fb, 0));

    rc = pool_get(pool, elt);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(vector_len(fi), pool_size - 2);
    EXPECT_TRUE(bitmap_is_unset(fb, 1));

    for (unsigned i = 0; i < pool_size - 4; i++) {
        rc = pool_get(pool, elt);
        EXPECT_GE(rc, 0);
    }

    rc = pool_get(pool, elt);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(vector_len(fi), 1UL);
    EXPECT_TRUE(bitmap_is_unset(fb, pool_size - 2));

    rc = pool_get(pool, elt);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(vector_len(fi), 0UL);
    EXPECT_TRUE(bitmap_is_unset(fb, pool_size - 1));

    /*
     * Getting elements within the allocated range should not have triggered a
     * resize
     */
    EXPECT_EQ(pool_len(pool), pool_size);

    /*
     * Getting elements once the allocated range has been exceeded should
     * trigger a resize
     */
    rc = pool_get(pool, elt);
    EXPECT_GE(rc, 0);

    EXPECT_EQ(pool_get_alloc_size(pool), pool_size * 2);

    EXPECT_EQ(pool_len(pool), pool_size + 1);

    /*
     * Doubling the size, we should have again pool_size elements free, minus 1
     */
    EXPECT_EQ(pool_get_free_indices_size(pool), pool_size - 1);

    /*
     * NOTE: this is wrong as there has been a realloc and the old fi
     * pointer is now invalid
     */
    //EXPECT_EQ(vector_len(fi), pool_size - 1);

    /* And the bitmap should also be correctly modified */
    fb = pool_get_free_bitmap(pool);
    EXPECT_TRUE(bitmap_is_unset(fb, pool_size));

    /* Check that surrounding values are also correct */
    EXPECT_TRUE(bitmap_is_unset(fb, pool_size - 1));
    EXPECT_TRUE(bitmap_is_set(fb, pool_size + 1));

    /* Setting elements after should through */

    /* Check that free indices and bitmaps are correctly updated */

    pool_free(pool);
}

// XXX todo : check state after several get and put
TEST_F(PoolTest, PoolPut)
{
    pool_init(pool, DEFAULT_SIZE, 0);

    int* elt;
    pool_get(pool, elt);
    *elt = 10;
    printf("2\n");
    pool_put(pool, elt);
    printf("3\n");

    pool_free(pool);
}

TEST_F(PoolTest, PoolGetForceBitmapRealloc)
{
    const int N = 64;
    int *elts[N];
    int *elt = NULL;
    pool_init(pool, N, 0);

    for (int i = 0; i < N; i++)
        pool_get(pool, elts[i]);
    pool_get(pool, elt);

    pool_free(pool);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
