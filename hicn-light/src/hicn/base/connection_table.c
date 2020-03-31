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

#include <hicn/base/connection.h>
#include <hicn/base/connection_table.h>

/* This is only used for first allocation, as the table is resizeable */
#define DEFAULT_CONNECTION_TABLE_SIZE 64

connection_table_t *
connection_table_create(size_t elt_size, size_t max_elts)
{
    connection_table_t * table = malloc(sizeof(connection_table_t));
    if (!table)
        return NULL;

    table->id_by_pair = kh_init_ct_pair();
    table->id_by_name = kh_init_ct_name();
    pool_init(table->connections, DEFAULT_CONNECTION_TABLE_SIZE);

    return table;
}

void
connection_table_free(connection_table_t * table)
{
    kh_destroy_ct_pair(table->id_by_pair);
    kh_destroy_ct_name(table->id_by_name);
    pool_free(table->connections);
    free(table);
}

connection_t *
connection_table_get_by_pair(const connection_table_t * table,
        const address_pair_t * pair)
{
  khiter_t k = kh_get_ct_pair(table->id_by_pair, pair);
  if (k == kh_end(table->id_by_pair))
      return NULL;
  return table->connections + kh_val(table->id_by_pair, k);
}

unsigned
connection_table_get_id_by_name(const connection_table_t * table,
        const char * name)
{
    khiter_t k = kh_get_ct_name(table->id_by_name, name);
    if (k == kh_end(table->id_by_name))
        return CONNECTION_ID_UNDEFINED;
    return kh_val(table->id_by_name, k);
}

connection_t *
connection_table_get_by_name(const connection_table_t * table,
        const char * name)
{
    unsigned conn_id = connection_table_get_id_by_name(table, name);
    if (!connection_id_is_valid(conn_id))
        return NULL;
    return table->connections + conn_id;
}

void
connection_table_remove_by_id(connection_table_t * table, off_t id)
{
    /*
     * Get the connection addresspair & name so as to be able to remove them
     * from the hash table index
     */
    connection_t * connection = connection_table_at(table, id);
    connection_table_deallocate(table, connection);
}
