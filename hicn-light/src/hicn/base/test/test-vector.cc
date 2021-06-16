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
#include <hicn/base/vector.h>
}

/*
 * TODO
 * - test max_size
 */

#define DEFAULT_SIZE 10

class VectorTest : public ::testing::Test {
protected:
    VectorTest() { }
    virtual ~VectorTest() { }

    int *vector = NULL;
};

/* TEST: Vector allocation and initialization */
TEST_F(VectorTest, VectorAllocate)
{
    vector_init(vector, DEFAULT_SIZE, 0);

    /* Allocated size should be the next power of two */
    EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

    /* Setting elements within the allocated size should not trigger a resize */
    vector_ensure_pos(vector, 15);
    EXPECT_EQ(vector_get_alloc_size(vector), 16UL);

    /* Setting elements after should through */
    vector_ensure_pos(vector, 16);
    EXPECT_EQ(vector_get_alloc_size(vector), 32UL);

    /* Check that free indices and bitmaps are correctly updated */

    vector_free(vector);
}

TEST_F(VectorTest, VectorSize)
{
    vector_init(vector, DEFAULT_SIZE, 0);

    vector_push(vector, 109);
    int size = vector_len(vector);
    EXPECT_EQ(size, 1);
    vector_push(vector, 109);
    size = vector_len(vector);
    EXPECT_EQ(size, 2);
    vector_push(vector, 109);
    size = vector_len(vector);
    EXPECT_EQ(size, 3);

    vector_free(vector);
}

TEST_F(VectorTest, VectorCheckValue)
{
    vector_init(vector, DEFAULT_SIZE, 0);

    vector_push(vector, 109);
    vector_push(vector, 200);
    EXPECT_EQ(vector[0], 109);
    EXPECT_EQ(vector[1], 200);

    vector_free(vector);
}

TEST_F(VectorTest, VectorEnsurePos)
{
    vector_init(vector, DEFAULT_SIZE, 0);

    printf (" %p\n", vector);
    vector_ensure_pos(vector, 1025);
    for (int i = 0; i <1025; i++) {
        //printf("i %d\n", i);
        //printf (" %p\n", vector);
        vector_push(vector, i);
    }
    int size = vector_len(vector);
    EXPECT_EQ(size, 1025);

    vector_free(vector);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
