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
 */

#ifndef HICN_LISTENER_TABLE_H
#define HICN_LISTENER_TABLE_H

#include <hicn/core/address.h>
#include <hicn/base/common.h>
#include <hicn/base/hash.h>
#include <hicn/base/khash.h>
#include <hicn/core/listener.h>
#include <hicn/base/pool.h>

#define key_hash(key) (hash(key, sizeof(listener_key_t)))
#define key_hash_eq(a, b) (key_hash(b) - key_hash(a))

KHASH_INIT(lt_name, const char *, unsigned, 0, str_hash, str_hash_eq);
KHASH_INIT(lt_key, listener_key_t *, unsigned, 0, key_hash, key_hash_eq);

typedef struct {
  kh_lt_key_t * id_by_key;
  kh_lt_name_t * id_by_name;
  listener_t * listeners; // pool
} listener_table_t;

#define listener_table_allocate(table, conn, key, name)                         \
do {                                                                            \
    pool_get(table->listeners, conn);                                           \
    off_t listener_id = conn - table->listeners;                                \
    int res;                                                                    \
    khiter_t k = kh_put_lt_name(table->id_by_name, name, &res);                 \
    kh_value(table->id_by_name, k) = listener_id;                               \
    k = kh_put_lt_key(table->id_by_key, key, &res);                             \
    kh_value(table->id_by_key, k) = listener_id;                                \
} while(0)

#define listener_table_deallocate(table, conn)                                  \
do {                                                                            \
    const address_key_t * key = listener_get_key(listener);                     \
    khiter_t k = kh_get_ct_key(table->id_by_key, key);                          \
    if (k != kh_end(table->id_by_key))                                          \
        kh_del_ct_key(table->id_by_key, k);                                     \
                                                                                \
    const char * name = listener_get_name(listener);                            \
    k = kh_get_ct_name(table->id_by_name, name);                                \
    if (k != kh_end(table->id_by_name))                                         \
        kh_del_ct_name(table->id_by_name, k);                                   \
                                                                                \
    pool_put(table->listeners, conn);                                           \
} while(0)                                                                      \


#define listener_table_len(table) (pool_elts(table->listeners))

#define listener_table_validate_id(table, id) pool_validate_id(table->listeners, id)

#define listener_table_at(table, id) ((table)->listeners + id)

#define listener_table_get_by_id(table, id)   \
    listener_table_validate_id(table, id)     \
        ? listener_table_at(table, id) : NULL

#define listener_table_get_listener_id(table, listener) (listener - table->listeners)

#define listener_table_foreach(table, listener, BODY) \
    pool_foreach(table->listeners, listener, do { BODY } while(0) )

listener_table_t * listener_table_create();
void listener_table_free(listener_table_t * table);

listener_t * listener_table_get_by_address(listener_table_t * table,
        face_type_t type, const address_t * address);

listener_t * listener_table_get_by_name(listener_table_t * table,
        const char *name);

void listener_table_remove_by_id(listener_table_t * table, off_t id);

unsigned listener_table_add(listener_table_t * table, listener_t * listener);

#endif /* HICN_LISTENER_TABLE_H */
