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
#include <hicn/core/connection_table.h>
}

class ConnectionTableTest : public ::testing::Test {
protected:
    ConnectionTableTest() {
        conn_table = connection_table_create();
    }
    virtual ~ConnectionTableTest() {
        connection_table_free(conn_table);
    }

    connection_table_t *conn_table;
};

TEST_F(ConnectionTableTest, Create)
{
    /* Check connection_table allocation */
    EXPECT_NE(conn_table, nullptr);

    /* Check connection_table size */
    size_t conn_table_size = connection_table_len(conn_table);
    EXPECT_EQ(conn_table_size, (size_t) 0);
}

TEST_F(ConnectionTableTest, AddConnection)
{
    address_pair_t pair = {
        .local = _ADDRESS4_LOCALHOST(1),
        .remote = _ADDRESS4_LOCALHOST(2)
    };
    connection_t * connection;

    connection_table_allocate(conn_table, connection, &pair, "listener_name_test");
    size_t conn_table_size = connection_table_len(conn_table);
    EXPECT_EQ(conn_table_size, (size_t) 1);
    EXPECT_NE(connection, nullptr);

    khiter_t k = kh_get_ct_name(conn_table->id_by_name, "listener_name_test");
    EXPECT_NE(k, kh_end(conn_table->id_by_name));
    k = kh_get_ct_pair(conn_table->id_by_pair, &pair);
    EXPECT_NE(k, kh_end(conn_table->id_by_pair));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
