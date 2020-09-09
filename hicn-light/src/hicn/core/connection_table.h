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
 *
 * The connection table is composed of :
 *  - a pool of connections allowing access through their id in constant time;
 *  - a set of indices in the form of hash table for efficient index lookups:
 *     . by name
 *     . by address pair
 *
 * For efficient index retrieval, the header will be prepended and the
 * resulting pointer will directly point to the connection pool.
 */

#ifndef HICN_CONNECTION_TABLE_H
#define HICN_CONNECTION_TABLE_H

#include <hicn/core/address_pair.h>
#include <hicn/core/connection.h>
#include <hicn/base/hash.h>
#include <hicn/base/khash.h>
#include <hicn/base/pool.h>

#define _ct_var(x) _ct_var_##x

/* Hash functions for indices. */
#define address_pair_hash(pair) (hash32(pair, sizeof(address_pair_t)))
#define address_pair_hash_eq(a, b) (address_pair_hash(b) - address_pair_hash(a))

/* Hash table types for indices. */
KHASH_INIT(ct_pair, const address_pair_t *, unsigned, 0, address_pair_hash, address_pair_hash_eq);
KHASH_INIT(ct_name, const char *, unsigned, 0, str_hash, str_hash_eq);

typedef struct {
    size_t max_size;

    kh_ct_pair_t * id_by_pair;
    kh_ct_name_t * id_by_name;

    connection_t * connections; // pool
} connection_table_t;

/**
 * @brief Allocate a connection from the connection table.
 *
 * @param[in] table The connection table from which to allocate a connection.
 * @param[out] connection The pointer that will hold the allocated connection.
 * @param[in] pair The address pair associated to the connection (to update index).
 * @param[in] name The name associated to the connection (to update index).
 *
 * NOTE:
 *  - This function updates all indices from the connection table if the
 *  allocation is successful.
 *  - You should always check that the returned connection is not NULL, which
 *  would signal that the pool is exhausted and could not be extended.
 */
#define connection_table_allocate(TABLE, CONN, PAIR, NAME)                      \
do {                                                                            \
    pool_get((TABLE)->connections, CONN);                                       \
    if (!CONN)                                                                  \
        return;                                                                 \
    off_t _ct_var(id) = (CONN) - (TABLE)->connections;                          \
    int _ct_var(res);                                                           \
    khiter_t _ct_var(k);                                                        \
    _ct_var(k) = kh_put_ct_pair((TABLE)->id_by_pair, PAIR, &_ct_var(res));      \
    kh_value((TABLE)->id_by_pair, _ct_var(k)) = _ct_var(id);                    \
    if (NAME) {                                                                 \
        _ct_var(k) = kh_put_ct_name((TABLE)->id_by_name, (NAME), &_ct_var(res));\
        kh_value((TABLE)->id_by_name, _ct_var(k)) = _ct_var(id);                \
    }                                                                           \
} while(0)

/**
 * @brief Deallocate a connection and return it to the connection table pool.
 *
 * @param[in] table The connection table to which the connection is returned.
 * @param[in] conn The connection that is returned to the pool.
 *
 * NOTE:
 *  - Upon returning a connection to the pool, all indices pointing to that
 *  connection are also cleared.
 */
#define connection_table_deallocate(TABLE, CONN)                                \
do {                                                                            \
    const address_pair_t * _ct_var(pair) = connection_get_pair(CONN);           \
    khiter_t _ct_var(k);                                                        \
    _ct_var(k) = kh_get_ct_pair((TABLE)->id_by_pair, _ct_var(pair));            \
    if (_ct_var(k) != kh_end((TABLE)->id_by_pair))                              \
        kh_del_ct_pair((TABLE)->id_by_pair, _ct_var(k));                        \
                                                                                \
    const char * _ct_var(name) = connection_get_name(CONN);                     \
    if (_ct_var(name)) {                                                        \
        _ct_var(k) = kh_get_ct_name((TABLE)->id_by_name, _ct_var(name));        \
        if (_ct_var(k) != kh_end((TABLE)->id_by_name))                          \
            kh_del_ct_name((TABLE)->id_by_name, _ct_var(k));                    \
    }                                                                           \
                                                                                \
    pool_put((TABLE)->connections, CONN);                                       \
} while(0)                                                                      \

/**
 * @brief Returns the length of the connection table, the number of active
 * connections.
 *
 * @param[in] table The connection table for which we retrieve the length.
 *
 * @return size_t The length of the connection table.
 *
 * NOTE:
 *  - The length of the connection table, that is the number of currently active
 *  connections.
 */
#define connection_table_len(table) (pool_len(table->connections))

/**
 * @brief Validate an index in the connection table.
 *
 * @param[in] table The connection table in which to validate an index.
 * @param[in] id The index of the connection to validate.
 *
 * @return bool A flag indicating whether the connection index is valid or not.
 */
#define connection_table_validate_id(table, id) \
    pool_validate_id((table)->connections, (id))

/**
 * @brief Return the connection corresponding to the specified index in the
 * connection table.
 *
 * @param[in] table The connection table for which to retrieve the connection.
 * @param[in] id The index for which to retrieve the connection.
 *
 * @return connection_t * The connection correponding to the specified index in
 * the connection table.
 *
 * @see connection_table_get_by_id
 *
 * NOTE:
 *  - In this function, the index is not validated.
 */
#define connection_table_at(table, id) ((table)->connections + id)

/**
 * @brief Return the connection corresponding to the specified and validated
 * index in the connection table.
 *
 * @param[in] table The connection table for which to retrieve the connection.
 * @param[in] id The index for which to retrieve the connection.
 *
 * @return connection_t * The connection correponding to the specified index in
 * the connection table.
 *
 * @see connection_table_get_by_id
 *
 * NOTE:
 *  - In this function, the index is validated.
 */
#define connection_table_get_by_id(table, id)   \
    connection_table_validate_id(table, id)     \
        ? connection_table_at(table, id) : NULL

/**
 * @brief Returns the index of a given connection in the connection table.
 *
 * @param[in] table The connection table from which to retrieve the index.
 * @param[in] conn The connection for which to retrieve the index.
 *
 * @return off_t The index of the specified connection in the connection table.
 */
#define connection_table_get_connection_id(table, conn) \
    (conn - table->connections)

#define connection_table_foreach(table, conn, BODY) \
    pool_foreach(table->connections, (conn), BODY)

#define connection_table_enumerate(table, i, conn, BODY) \
    pool_enumerate(table->connections, (i), (conn), BODY)

/**
 * @brief Create a new connection table (extended parameters).
 *
 * @param[in] init_size Initially allocated size (hint, 0 = use default value).
 * @param[in] max_size Maximum size (0 = unlimited).
 *
 * @return connection_table_t* The newly created connection table.
 */
connection_table_t * _connection_table_create(size_t init_size, size_t max_size);

/**
 * @brief Create a new connection table (minimal parameters).
 *
 * @return connection_table_t* The newly created connection table.
 */
#define connection_table_create() _connection_table_create(0, 0)

/**
 * @brief Free a connection table
 *
 * @param[in] table Connection table to free
 */
void connection_table_free(connection_table_t * table);

/**
 * @brief Retrieve a connection from the connection table by address pair.
 *
 * @param[in] table The connection table in which to search.
 * @param[in] pair The address pair to search for.
 *
 * @return connection_t * The connection matching the specified address pair, or
 * NULL if not found.
 */
connection_t * connection_table_get_by_pair(const connection_table_t * table,
        const address_pair_t * pair);

/**
 * @brief Return a connection index from the connection table by name.
 *
 * @param[in] table The connection table in which to search.
 * @param[in] name The name to search for.
 *
 * @return off_t The index of the connection matching the name, or
 * CONNECTION_ID_UNDEFINED if not found.
 */
off_t connection_table_get_id_by_name(const connection_table_t * table,
        const char * name);

/**
 * @brief Return a connection from the connection table by name.
 *
 * @param[in] table The connection table in which to search.
 * @param[in] name The name to search for.
 *
 * @return connection_t * The connection matching the name, or NULL if not
 * found.
 */
connection_t * connection_table_get_by_name(const connection_table_t * table,
        const char * name);

/**
 * @brief Remove a connection from the connection table by its index.
 *
 * @param[in] table The connection table from which to delete the connection.
 * @param[in] id The index of the connection to remove.
 */
void connection_table_remove_by_id(connection_table_t * table, off_t id);

#endif /* HICN_CONNECTION_TABLE_H */
