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
 * \file listener_table.h
 * \brief hICN listener table
 *
 * The listener table is composed of:
 *  - a pool of listeners allowing access through their index in constant time;
 *  - a set of indices in the form of hash table for efficient index lookups:
 *     . by name
 *     . by key (listener_type, address)
 *
 * For efficient index retrieval, the header will be prepended and the
 * resulting pointer will directly point to the listener pool.
 */

#ifndef HICNLIGHT_LISTENER_TABLE_H
#define HICNLIGHT_LISTENER_TABLE_H

#include "address.h"
#include "listener.h"
#include "../base/common.h"
#include "../base/hash.h"
#include "../base/khash.h"
#include "../base/pool.h"

#define _lt_var(x) _lt_var_##x

/* Hash functions for indices */
#define key_hash(key) (hash_struct(key))
#define key_hash_eq(a, b) (key_hash(b) == key_hash(a))

/* Hash table types for indices */
KHASH_MAP_INIT_STR(lt_name, unsigned);
KHASH_INIT(lt_key, listener_key_t *, unsigned, 1, key_hash, key_hash_eq);

typedef struct {
    size_t max_size;

    kh_lt_key_t * id_by_key;
    kh_lt_name_t * id_by_name;

    listener_t * listeners; // pool
} listener_table_t;

/**
 * @brief Allocate a listener from the listener table.
 *
 * @param[in] table The listener table from which to allocate a listener.
 * @param[out] listener The pointer that will hold the allocated listener.
 * @param[in] pair The address pair associated to the listener (to update index)
 * @param[in] name The name associated to the listener (to update index)
 *
 * NOTE:
 *  - This function updates all indices from the listener table if the
 *  allocation is successful.
 *  - You should always check that the returned listener is not NULL, which
 *  would signal that the pool is exhausted and could not be extended.
 */
#define listener_table_allocate(TABLE, LISTENER, KEY, NAME)                     \
do {                                                                            \
    pool_get(TABLE->listeners, (LISTENER));                                     \
    if (LISTENER) {                                                             \
        off_t _lt_var(id) = (LISTENER) - (TABLE)->listeners;                    \
        int _lt_var(res);                                                       \
        khiter_t _lt_var(k);							\
        _lt_var(k) = kh_put_lt_name((TABLE)->id_by_name, (NAME), &_lt_var(res));\
        kh_value((TABLE)->id_by_name, _lt_var(k)) = _lt_var(id);                \
                                                                                \
        listener->type = (KEY)->type;						\
        listener->address = (KEY)->address;					\
        listener_key_t * _lt_var(key) = listener_get_key(LISTENER);		\
        _lt_var(k) = kh_put_lt_key((TABLE)->id_by_key, _lt_var(key), &_lt_var(res));\
        kh_value((TABLE)->id_by_key, _lt_var(k)) = _lt_var(id);                 \
    }                                                                           \
} while(0)

/**
 * @brief Deallocate a listener and return it to the listener table pool.
 *
 * @param[in] table The listener table to which the listener is returned.
 * @param[in] conn The listener that is returned to the pool.
 *
 * NOTE:
 *  - Upon returning a listener to the pool, all indices pointing to that
 *  listener are also cleared.
 */
#define listener_table_deallocate(TABLE, LISTENER)                              \
do {                                                                            \
    const address_key_t * _lt_var(key) = listener_get_key(LISTENER);            \
    khiter_t _lt_var(k);							\
    _lt_var(k) = kh_get_ct_key((TABLE)->id_by_key, _lt_var(key));               \
    if (_lt_var(k) != kh_end((TABLE)>id_by_key))                                \
        kh_del_ct_key((TABLE)->id_by_key, _lt_var(k));                          \
                                                                                \
    const char * _lt_var(name) = listener_get_name(LISTENER);                   \
    _lt_var(k) = kh_get_ct_name((TABLE)->id_by_name, _lt_var(name));            \
    if (_lt_var(k) != kh_end((TABLE)->id_by_name))                              \
        kh_del_ct_name((TABLE)->id_by_name, _lt_var(k));                        \
                                                                                \
    pool_put((TABLE)->listeners, LISTENER);                                     \
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
#define listener_table_len(table) (pool_len(table->listeners))

/**
 * @brief Validate an index in the listener table.
 *
 * @param[in] table The listener table in which to validate an index.
 * @param[in] id The index of the listener to validate.
 *
 * @return bool A flag indicating whether the listener index is valid or not.
 */
#define listener_table_validate_id(table, id) \
    pool_validate_id(table->listeners, id)

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
 * @see listener_table_get_by_id
 *
 * NOTE:
 *  - In this function, the index is not validated.
 */
#define listener_table_at(table, id) ((table)->listeners + id)

/**
 * @brief Return the listener corresponding to the specified and validated
 * index in the listener table.
 *
 * @param[in] table The listener table for which to retrieve the listener.
 * @param[in] id The index for which to retrieve the listener.
 *
 * @return listener_t * The listener correponding to the specified index in
 * the listener table.
 *
 * @see listener_table_get_by_id
 *
 * NOTE:
 *  - In this function, the index is validated.
 */
#define listener_table_get_by_id(table, id)   \
    listener_table_validate_id(table, id)     \
        ? listener_table_at(table, id) : NULL

/**
 * @brief Returns the index of a given listener in the listener table.
 *
 * @param[in] table The listener table from which to retrieve the index.
 * @param[in] conn The listener for which to retrieve the index.
 *
 * @return off_t The index of the specified listener in the listener table.
 */
#define listener_table_get_listener_id(table, listener) (listener - table->listeners)

#define listener_table_foreach(table, listener, BODY) \
    pool_foreach(table->listeners, listener, do { BODY } while(0) )

#define listener_table_enumerate(table, i, conn, BODY) \
    pool_enumerate(table->listeners, (i), (conn), BODY)

/**
 * @brief Create a new listener table (extended parameters)
 *
 * @param[in] init_size Initially allocated size (hint, 0 = use default value)
 * @param[in] max_size Maximum size (0 = unlimited)
 *
 * @return listener_table_t* - The newly created listener table
 */
listener_table_t * _listener_table_create(size_t init_size, size_t max_size);

/**
 * @brief Create a new listener table (minimal parameters)
 *
 * @return listener_table_t* - The newly created listener table
 */
#define listener_table_create() _listener_table_create(0, 0)

/**
 * @brief Free a listener table
 *
 * @param[in] table Listener table to free
 */
void listener_table_free(listener_table_t * table);

/**
 * @brief Retrieve a listener from the listener table by address.
 *
 * @param[in] table The listener table in which to search.
 * @param[in] type The face type characterizing the listener to search for.
 * @param[in] address The address to search for.
 *
 * @return listener_t * The listener matching the specified address, or
 * NULL if not found.
 */
listener_t * listener_table_get_by_address(listener_table_t * table,
        face_type_t type, const address_t * address);

/**
 * @brief Return a listener from the listener table by name.
 *
 * @param[in] table The listener table in which to search.
 * @param[in] name The name to search for.
 *
 * @return listener_t * The listener matching the name, or NULL if not
 * found.
 */
listener_t * listener_table_get_by_name(listener_table_t * table,
        const char *name);

/**
 * @brief Remove a listener from the listener table by its index.
 *
 * @param[in] table The listener table from which to delete the listener.
 * @param[in] id The index of the listener to remove.
 */
void listener_table_remove_by_id(listener_table_t * table, off_t id);

unsigned listener_table_add(listener_table_t * table, listener_t * listener);

#endif /* HICNLIGHT_LISTENER_TABLE_H */
