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
#include <hicn/core/listener_table.h>
}

class ListenerTableTest : public ::testing::Test {
protected:
    ListenerTableTest() {
        listener_table = listener_table_create();
    }
    virtual ~ListenerTableTest() {
        listener_table_free(listener_table);
    }

    listener_table_t *listener_table;
};

TEST_F(ListenerTableTest, Create)
{
    /* Check listener_table allocation */
    EXPECT_NE(listener_table, nullptr);

    /* Check listener_table size */
    size_t listener_table_size = listener_table_len(listener_table);
    EXPECT_EQ(listener_table_size, (size_t) 0);
}

TEST_F(ListenerTableTest, AddListener)
{
    listener_key_t key = {
        .address = _ADDRESS4_LOCALHOST(1),
        .type = FACE_TYPE_UDP
    };
    listener_t *listener;

    listener_table_allocate(listener_table, listener, &key, "listener_name_test");
    size_t listener_table_size = listener_table_len(listener_table);
    EXPECT_EQ(listener_table_size, (size_t) 1);
    EXPECT_NE(listener, nullptr);

    khiter_t k = kh_get_lt_name(listener_table->id_by_name, "listener_name_test");
    EXPECT_NE(k, kh_end(listener_table->id_by_name));
    k = kh_get_lt_key(listener_table->id_by_key, &key);
    EXPECT_NE(k, kh_end(listener_table->id_by_key));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
