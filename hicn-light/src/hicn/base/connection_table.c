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

/**
 * \file connection_table.c
 * \brief Implementation of hICN connection table
 */

#include <hicn/core/connection.h>
#include <hicn/base/connection_table.h>

/* This is only used for first allocation, as the table is resizeable */
#define DEFAULT_CONNECTION_TABLE_SIZE 64

connection_table_t *
connection_table_create(size_t elt_size, size_t max_elts)
{
    connection_table_t * table = malloc(sizeof(connection_table_t));
    if (!table)
        return NULL;

    table->id_by_addresspair = kh_init(address_pair);
    pool_init(table->connections, DEFAULT_CONNECTION_TABLE_SIZE);

    return table;
}

void
connection_table_free(connection_table_t * table)
{
    // XXX TODO
    kh_destroy_address_pair(table->id_by_addresspair);
    pool_free(table->connections);
    free(table);
}

Connection **
connection_table_lookup(connection_table_t * table,
        address_pair_t * pair)
{
  khiter_t k = kh_get_address_pair(table->id_by_addresspair, pair);
  if (k == kh_end(table->id_by_addresspair))
      return NULL;
  return table->connections + kh_val(table->id_by_addresspair, k);
}

void
connection_table_remove_by_id(connection_table_t * table, off_t id)
{
    /*
     * Get the connection addresspair so as to be able to remove it from the
     * hash table index
     */
    Connection * connection = connection_table_at(table, id);
    const address_pair_t * pair = connection_GetAddressPair(connection);
    khiter_t k = kh_get(address_pair, table->id_by_addresspair, pair);
    kh_del(address_pair, table->id_by_addresspair, k);

    pool_put(table->connections, connection);
}

#if 0
unsigned
connection_table_add(connection_table_t * table, Connection * connection)
{
    // XXX missing hash and key storage
    Connection * conn;
    pool_get(table->connections, conn);
    conn = connection;
    unsigned connid = connection_table_get_connection_id(table, conn);
    Connection_SetConnectionId(connection, connid);
    return connid;
}
#endif
