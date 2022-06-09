/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * \file listener_table.c
 * \brief Implementation of hICN listener table
 */

#include <hicn/util/log.h>

#include "listener_table.h"
#include "listener.h"

/* This is only used as a hint for first allocation, as the table is resizeable
 */
#define DEFAULT_LISTENER_TABLE_SIZE 64

listener_table_t *_listener_table_create(size_t init_size, size_t max_size) {
  if (init_size == 0) init_size = DEFAULT_LISTENER_TABLE_SIZE;

  listener_table_t *table = malloc(sizeof(listener_table_t));
  if (!table) return NULL;

  table->max_size = max_size;

  /* Initialize indices */
  table->id_by_name = kh_init_lt_name();
  table->id_by_key = kh_init_lt_key();

  /*
   * We start by allocating a reasonably-sized pool, as this will eventually
   * be resized if needed.
   */
  pool_init(table->listeners, init_size, 0);

  return table;
}

void listener_table_free(listener_table_t *table) {
  const char *k_name;
  const listener_key_t *k_key;
  unsigned v;

  listener_t *listener;
  const char *name;
  kh_foreach(table->id_by_key, k_key, v, {
    listener = listener_table_get_by_id(table, v);
    name = listener_get_name(listener);
    INFO("Removing listner %s [%d]", name, listener->fd);
    listener_finalize(listener);
  });

  (void)v;
  kh_foreach(table->id_by_name, k_name, v, { free((char *)k_name); });
  kh_foreach(table->id_by_key, k_key, v, { free((listener_key_t *)k_key); });

  kh_destroy_lt_name(table->id_by_name);
  kh_destroy_lt_key(table->id_by_key);
  pool_free(table->listeners);
  free(table);
}

listener_t *listener_table_allocate(const listener_table_t *table,
                                    const listener_key_t *key,
                                    const char *name) {
  listener_t *listener = NULL;
  pool_get(table->listeners, listener);
  if (!listener) return NULL;

  off_t id = listener - table->listeners;
  int rc;

  // Add in name hash table
  khiter_t k = kh_put_lt_name(table->id_by_name, strdup(name), &rc);
  assert(rc == KH_ADDED || rc == KH_RESET);
  kh_value(table->id_by_name, k) = (unsigned int)id;

  // Add in key hash table
  listener_key_t *key_copy = (listener_key_t *)malloc(sizeof(listener_key_t));
  memcpy(key_copy, key, sizeof(listener_key_t));

  k = kh_put_lt_key(table->id_by_key, key_copy, &rc);
  assert(rc == KH_ADDED || rc == KH_RESET);
  kh_value(table->id_by_key, k) = (unsigned int)id;

  assert(kh_size(table->id_by_name) == kh_size(table->id_by_key));
  return listener;
}

void listener_table_deallocate(const listener_table_t *table,
                               listener_t *listener) {
  const char *name = listener_get_name(listener);
  listener_key_t *key = listener_get_key(listener);

  // Remove from name hash table
  khiter_t k = kh_get_lt_name(table->id_by_name, name);
  assert(k != kh_end(table->id_by_name));
  free((char *)kh_key(table->id_by_name, k));
  kh_del_lt_name(table->id_by_name, k);

  // Remove from key hash table
  k = kh_get_lt_key(table->id_by_key, key);
  assert(k != kh_end(table->id_by_key));
  free((listener_key_t *)kh_key(table->id_by_key, k));
  kh_del_lt_key(table->id_by_key, k);

  assert(kh_size(table->id_by_name) == kh_size(table->id_by_key));
  pool_put(table->listeners, listener);
}

listener_t *listener_table_get_by_address(listener_table_t *table,
                                          face_type_t type,
                                          const address_t *address) {
  listener_key_t key = listener_key_factory(*address, type);
  khiter_t k = kh_get_lt_key(table->id_by_key, &key);
  if (k == kh_end(table->id_by_key)) return NULL;
  return listener_table_at(table, kh_val(table->id_by_key, k));
}

listener_t *listener_table_get_by_key(listener_table_t *table,
                                      const listener_key_t *key) {
  khiter_t k = kh_get_lt_key(table->id_by_key, key);
  if (k == kh_end(table->id_by_key)) return NULL;
  return listener_table_at(table, kh_val(table->id_by_key, k));
}

void listener_table_remove_by_id(listener_table_t *table, off_t id) {
  listener_t *listener = listener_table_at(table, id);
  INFO("Removing listener %d (%s)", id, listener_get_name(listener));

  listener_table_deallocate(table, listener);
}

off_t listener_table_get_id_by_name(const listener_table_t *table,
                                    const char *name) {
  khiter_t k = kh_get_lt_name(table->id_by_name, name);
  if (k == kh_end(table->id_by_name)) return LISTENER_ID_UNDEFINED;
  return kh_val(table->id_by_name, k);
}

listener_t *listener_table_get_by_name(listener_table_t *table,
                                       const char *name) {
  unsigned listener_id =
      (unsigned int)listener_table_get_id_by_name(table, name);
  if (!listener_id_is_valid(listener_id)) return NULL;
  return listener_table_at(table, listener_id);
}

listener_t *_listener_table_get_by_id(listener_table_t *table, off_t id) {
  return listener_table_get_by_id(table, id);
}

void listener_table_print_by_key(const listener_table_t *table) {
  const listener_key_t *k;
  unsigned v;

  char addr_str[NI_MAXHOST];
  int port;
  listener_t *listener;
  const char *name;

  INFO("*** Listener table ***");
  kh_foreach(table->id_by_key, k, v, {
    address_to_string(&k->address, addr_str, &port);
    listener = listener_table_get_by_id(table, v);
    name = listener_get_name(listener);
    INFO("%s:%d - %s\t\t\t\t(%u, %s)", addr_str, port, face_type_str(k->type),
         v, name);
  })
}

void listener_table_print_by_name(const listener_table_t *table) {
  const char *k;
  unsigned v;

  char addr_str[NI_MAXHOST];
  int port;
  listener_t *listener;
  const listener_key_t *key;

  INFO("*** Listener table ***");
  kh_foreach(table->id_by_name, k, v, {
    listener = listener_table_get_by_id(table, v);
    key = listener_get_key(listener);
    address_to_string(&key->address, addr_str, &port);

    INFO("%s:%d - %s\t\t\t\t(%u, %s)", addr_str, port, face_type_str(key->type),
         v, k);
  })
}