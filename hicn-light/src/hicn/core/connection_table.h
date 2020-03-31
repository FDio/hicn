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
 * \file connection_table.h
 * \brief hICN connection_table
 */

/* Iterate on connection table : to remove all connections associated to a
 * listener based on listen address */

#ifndef HICN_CONNECTION_TABLE_H
#define HICN_CONNECTION_TABLE_H

//#include <hicn/base/common.h>
#include <hicn/core/address_pair.h>
#include <hicn/core/connection.h>
#include <hicn/base/hash.h>
#include <hicn/base/khash.h>
#include <hicn/base/pool.h>

#include <hicn/common.h>

#define address_pair_hash(pair) (hash32(pair, sizeof(address_pair_t)))
#define address_pair_hash_eq(a, b) (address_pair_hash(b) - address_pair_hash(a))

KHASH_INIT(ct_pair, const address_pair_t *, unsigned, 0, address_pair_hash, address_pair_hash_eq);

KHASH_INIT(ct_name, const char *, unsigned, 0, str_hash, str_hash_eq);

/*
 * The connection table is composed of :
 *  - a connection pool allowing connection access by id in constant time
 *  - a hash table allowing to perform lookups based on address pairs, to get a connection id.
 *
 * For fast lookup by ID, the connection table will point to the beginning of
 * the pool / vector, holding all connections.
 * The header will be prepended
 */

typedef struct {
    kh_ct_pair_t * id_by_pair;
    kh_ct_name_t * id_by_name;

    connection_t * connections; // pool
} connection_table_t;

#define connection_table_allocate(table, conn, pair, name)                      \
do {                                                                            \
    pool_get(table->connections, conn);                                         \
    off_t connection_id = conn - table->connections;                            \
    int res;                                                                    \
    khiter_t k = kh_put_ct_pair(table->id_by_pair, pair, &res);                 \
    kh_value(table->id_by_pair, k) = connection_id;                             \
    if (name) {                                                                 \
        k = kh_put_ct_name(table->id_by_name, name, &res);                      \
        kh_value(table->id_by_name, k) = connection_id;                         \
    }                                                                           \
} while(0)

#define connection_table_deallocate(table, conn)                                \
do {                                                                            \
    const address_pair_t * pair = connection_get_pair(connection);              \
    khiter_t k = kh_get_ct_pair(table->id_by_pair, pair);                       \
    if (k != kh_end(table->id_by_pair))                                         \
        kh_del_ct_pair(table->id_by_pair, k);                                   \
                                                                                \
    const char * name = connection_get_name(connection);                        \
    if (name) {                                                                 \
        k = kh_get_ct_name(table->id_by_name, name);                            \
        if (k != kh_end(table->id_by_name))                                     \
            kh_del_ct_name(table->id_by_name, k);                               \
    }                                                                           \
                                                                                \
    pool_put(table->connections, conn);                                         \
} while(0)                                                                      \

#define connection_table_len(table) (pool_elts(table->connections))

#define connection_table_validate_id(table, id) \
    pool_validate_id((table)->connections, (id))

#define connection_table_at(table, id) ((table)->connections + id)

#define connection_table_get_connection_id(table, conn) \
    (conn - table->connections)

#define connection_table_foreach(table, conn, BODY) \
    pool_foreach(table->connections, (conn), BODY)

#define connection_table_enumerate(table, i, conn, BODY) \
    pool_foreach(table->connections, (i), (conn), BODY)

connection_table_t * connection_table_create();
void connection_table_free(connection_table_t * table);

#define connection_table_get_by_id(table, id)           \
    connection_table_validate_id((table), (id))         \
        ? connection_table_at((table), (id)) : NULL;

connection_t * connection_table_get_by_pair(const connection_table_t * table,
        const address_pair_t * pair);

unsigned connection_table_get_id_by_name(const connection_table_t * table,
        const char * name);

connection_t * connection_table_get_by_name(const connection_table_t * table,
        const char * name);

void connection_table_remove_by_id(connection_table_t * table, off_t id);

//unsigned connection_table_add(connection_table_t * table, Connection * connection);

#endif /* HICN_CONNECTION_TABLE_H */
