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
 * @file pit.h
 * @brief hICN Pending Interest Table (PIT)
 */

#ifndef HICNLIGHT_PIT_H
#define HICNLIGHT_PIT_H

#include <hicn/core/fib.h>

typedef struct {
  nexthops_t ingressIdSet;
  nexthops_t egressIdSet;
  fib_entry_t* fib_entry;
} pit_entry_t;

#define pit_entry_get_ingress(E) (&((E)->ingressIdSet))
#define pit_entry_get_egress(E) (&((E)->egressIdSet))
#define pit_entry_get_fib_entry(E) ((E)->fib_entry)
#define pit_entry_set_fib_entry(E, FIB_ENTRY) ((E)->fib_entry = FIB_ENTRY)

#define pit_entry_ingress_add(E, NH) \
  nexthops_add(pit_entry_get_ingress(E), (NH))

#define pit_entry_ingress_contains(E, NH) \
  nexthops_contains(pit_entry_get_ingress(E), (NH))

#define pit_entry_egress_add(E, NH) nexthops_add(pit_entry_get_egress(E), (NH))

typedef struct {
  // TODO(eloparco): How to handle PIT size?
  size_t max_size;
} pit_t;

#define DEFAULT_INTEREST_LIFETIME 4000000000ULL

Ticks pit_calculate_lifetime(pit_t* pit, const msgbuf_t* msgbuf);

/**
 * @brief Allocate a new PIT data structure (extended parameters)
 *
 * @param init_size Initial size (0 = default)
 * @param max_size Maximum size (0 = unbounded)
 *
 * @return pit_t* Newly allocated PIT data structure
 */
pit_t* _pit_create(size_t init_size, size_t max_size);

/**
 * @brief Allocate a new PIT data structure
 *
 * @return pit_t* Newly allocated PIT data structure
 */
#define pit_create() _pit_create(0, 0)

void pit_free(pit_t* pit);

#endif /* HICNLIGHT_PIT_H */
