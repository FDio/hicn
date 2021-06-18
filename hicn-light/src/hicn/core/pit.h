/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * @file pit.h
 * @brief hICN Pending Interest Table (PIT)
 */

#ifndef HICNLIGHT_PIT_H
#define HICNLIGHT_PIT_H

#include <hicn/base/khash.h>
#include <hicn/core/nexthops.h>
#include <hicn/core/msgbuf.h>
#include <hicn/core/fib.h>
#include <hicn/core/name.h>
#include <hicn/core/ticks.h>

typedef struct  {
  off_t msgbuf_id;
  nexthops_t ingressIdSet;
  nexthops_t egressIdSet;

  fib_entry_t * fib_entry;

  Ticks create_ts;
  Ticks expire_ts;
} pit_entry_t;

typedef enum {
    PIT_VERDICT_FORWARD,
    PIT_VERDICT_AGGREGATE,
    PIT_VERDICT_RETRANSMIT,
} pit_verdict_t;

#define pit_entry_get_ingress(E) (&((E)->ingressIdSet))
#define pit_entry_get_egress(E) (&((E)->egressIdSet))
#define pit_entry_get_fib_entry(E) ((E)->fib_entry)
#define pit_entry_set_fib_entry(E, FIB_ENTRY) ((E)->fib_entry = FIB_ENTRY)
#define pit_entry_get_create_ts(E) ((E)->create_ts)
#define pit_entry_get_expire_ts(E) ((E)->expire_ts)
#define pit_entry_set_expire_ts(E, EXPIRY_TIME) \
    (entry)->expire_ts = EXPIRY_TIME

#define pit_entry_ingress_add(E, NH) \
    nexthops_add(pit_entry_get_ingress(E), (NH))

#define pit_entry_ingress_contains(E, NH) \
    nexthops_contains(pit_entry_get_ingress(E), (NH))

#define pit_entry_egress_add(E, NH) \
    nexthops_add(pit_entry_get_egress(E), (NH))

#define name_hash(name) (name_HashCode(name))
#define name_hash_eq(a, b) (name_hash(b) == name_hash(a))

KHASH_INIT(pit_name, const Name *, unsigned, 1, name_hash, name_hash_eq);

typedef struct {
    size_t max_size;
    pit_entry_t * entries; // pool
    kh_pit_name_t * index_by_name;
} pit_t;

/**
 * @brief Allocate a new PIT data structure (extended parameters)
 *
 * @param init_size Initial size (0 = default)
 * @param max_size Maximum size (0 = unbounded)
 *
 * @return pit_t* Newly allocated PIT data structure
 */
pit_t * _pit_create(size_t init_size, size_t max_size);

/**
 * @brief Allocate a new PIT data structure
 *
 * @return pit_t* Newly allocated PIT data structure
 */
#define pit_create() _pit_create(0, 0)

void pit_free(pit_t * pit);

#define _pit_var(x) _pit_ ## x

#define pit_allocate(pit, entry, msgbuf)                                        \
do {                                                                            \
    pool_get(pit->entries, entry);                                              \
    unsigned _pit_var(id) = entry - pit->entries;                               \
    int _pit_var(res);                                                          \
    khiter_t _pit_var(k) = kh_put(pit_name, pit->index_by_name,                 \
            msgbuf_get_name(msgbuf), &_pit_var(res));                           \
    kh_value(pit->index_by_name, _pit_var(k)) = _pit_var(id);                   \
} while(0)

#define pit_at(pit, i) (pit->entries + i)

pit_verdict_t pit_on_interest(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id);

nexthops_t * pit_on_data(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id);

void pit_remove(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id);

pit_entry_t * pit_lookup(const pit_t * pit, const msgbuf_t * msgbuf);

#endif /* HICNLIGHT_PIT_H */
