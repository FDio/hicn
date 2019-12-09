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

#include <hicn/base/address.h>
#include <hicn/base/common.h>
#include <hicn/base/khash.h>
#include <hicn/base/pool.h>
#include <hicn/io/listener.h>

#define str_hash(str) (hash32(str, strlen(str)))
#define str_hash_eq(a, b) (str_hash(b) - str_hash(a))

typedef struct {
  uint8_t encap_type;
  address_t address;
} listener_key_t;

#define key_hash(key) (hash32(&key, sizeof(listener_key_t)))
#define key_hash_eq(a, b) (key_hash(b) - key_hash(a))

KHASH_INIT(name, const char *, unsigned, 0, str_hash, str_hash_eq);
KHASH_INIT(key, listener_key_t, unsigned, 0, key_hash, key_hash_eq);

typedef struct {
  kh_name_t * id_by_name;
  kh_key_t * id_by_key;
  ListenerOps ** listeners; // pool
} listener_table_t;

#define listener_table_len(table) (pool_elts(table->listeners))

#define listener_table_validate_id(table, id) pool_validate_id(table->listeners, id)

#define listener_table_at(table, id) ((table)->listeners[id])

#define listener_table_get_by_id(table, id)   \
    listener_table_validate_id(table, id)     \
        ? listener_table_at(table, id) : NULL

#define listener_table_get_listener_id(table, listener) (&listener - table->listeners)

#define listener_table_foreach(table, listener, BODY) \
    pool_foreach(table->listeners, listener, do { BODY } while(0) )

listener_table_t * listener_table_create();
void listener_table_free(listener_table_t * table);

ListenerOps * listener_table_lookup(listener_table_t * table,
        uint8_t encap_type, const address_t * address);

ListenerOps * listener_table_get_by_name(listener_table_t * table,
        const char *name);

void listener_table_remove_by_id(listener_table_t * table, off_t id);

unsigned listener_table_add(listener_table_t * table, ListenerOps * listener);

#endif /* HICN_LISTENER_TABLE_H */
