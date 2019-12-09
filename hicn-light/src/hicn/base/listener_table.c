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
 * \file listener_table.c
 * \brief Implementation of hICN listener table
 */

#include <hicn/base/listener_table.h>
#include <hicn/io/listener.h>

/* This is only used for first allocation, as the table is resizeable */
#define DEFAULT_LISTENER_TABLE_SIZE 64

listener_table_t *
listener_table_create(size_t elt_size, size_t max_elts)
{
    listener_table_t * table = malloc(sizeof(listener_table_t));
    if (!table)
        return NULL;

    table->id_by_name = kh_init(name);
    table->id_by_key = kh_init(key);
    pool_init(table->listeners, DEFAULT_LISTENER_TABLE_SIZE);

    return table;
}

void
listener_table_free(listener_table_t * table)
{
    kh_destroy_name(table->id_by_name);
    kh_destroy_key(table->id_by_key);
    pool_free(table->listeners);
    free(table);
}

ListenerOps * listener_table_lookup(listener_table_t * table,
        uint8_t encap_type, const address_t * address)
{
  listener_key_t key = {
    .encap_type = encap_type,
    .address = *address,
  };
  khiter_t k = kh_get_key(table->id_by_key, key);
  if (k == kh_end(table->id_by_key))
      return NULL;
  return listener_table_at(table, kh_val(table->id_by_key, k));
}

void
listener_table_remove_by_id(listener_table_t * table, off_t id)
{
    /*
     * Get the listener address so as to be able to remove it from the
     * hash table index
     */
    ListenerOps * listener = listener_table_at(table, id);
    const char * name = listener->getListenerName(listener);
    listener_key_t key = {
        .encap_type = listener->getEncapType(listener),
        .address = *listener->getListenAddress(listener),
    };
    khiter_t k;
    k = kh_get(name, table->id_by_name, name);
    kh_del(name, table->id_by_name, k);
    k = kh_get(key, table->id_by_key, key);
    kh_del(key, table->id_by_key, k);

    pool_put(table->listeners, listener);
}

ListenerOps *
listener_table_get_by_name(listener_table_t * table, const char * name)
{
    khiter_t k = kh_get_name(table->id_by_name, name);
    if (k == kh_end(table->id_by_name))
        return NULL;
    return listener_table_at(table, kh_val(table->id_by_name, k));
}

#if 0
unsigned
listener_table_add(listener_table_t * table, ListenerOps * listener)
{
    // XXX missing hash and key storage
    ListenerOps * lst;
    pool_get(table->listeners, lst);
    lst = listener;
    unsigned listener_id = lst - table,
    Listener_SetId(listener, listener_id);
    return listener_id;
}
#endif
