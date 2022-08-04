/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file nexthops.h
 * \brief Nexthops
 *
 * An implementation of the nexthop data structure for the FIB entry.
 *
 * Note that the position of nexthops in this structure can be reordered. This
 * is not an issue for the strategy state since the state if bound to the
 * nexthop information, but an external module should not keep any reference to
 * the offset of the nexthop.
 */

#ifndef HICNLIGHT_NEXTHOPS_H
#define HICNLIGHT_NEXTHOPS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <hicn/util/log.h>

#include "connection.h"
#include "strategy_vft.h"

#define _nexthops_var(x) _nexthops_##x

typedef unsigned nexthop_t;
#define NEXTHOP(x) ((nexthop_t)x)

#define INVALID_NEXTHOP NEXTHOP(CONNECTION_ID_UNDEFINED)

/*
 * This allows storage within a single integer
 * 32 or 64 nexthops should be sufficient
 * Eventually replace this with a resizeable vector
 */
#define MAX_NEXTHOPS (sizeof(uint_fast32_t) * 8)

typedef struct nexthops_s {
  unsigned elts[MAX_NEXTHOPS];
  strategy_nexthop_state_t state[MAX_NEXTHOPS];
  size_t num_elts;

  /*
   * flags is used during the processing of nexthops by the policy framework,
   * and its meaning is local to the related functions.
   * It is a mask where a bit set to 1 in position N indicates that the Nth
   * elements in the elts array (elts[N]) is disabled.
   * The number of enabled next hops is reflected in cur_elts, and it is equal
   * to num_elts if no nexthop is disabled. This could be replaced by an
   * efficient function counting the number of 1 bits in flags.
   */
  uint_fast32_t flags;
  size_t cur_elts;
} nexthops_t;

#define NEXTHOPS_EMPTY                                                   \
  (nexthops_t) {                                                         \
    .elts = {0}, .state = {STRATEGY_NEXTHOP_STATE_EMPTY}, .num_elts = 0, \
    .flags = 0, .cur_elts = 0,                                           \
  }

#define nexthops_state(NH, i) ((NH)->state[(i)])

#define nexthops_get_len(NH) ((NH)->num_elts)

#define nexthops_set_len(NH, LEN) \
  do {                            \
    (NH)->num_elts = LEN;         \
    (NH)->cur_elts = LEN;         \
  } while (0)

#define nexthops_get_curlen(NH) ((NH)->cur_elts)

#define nexthops_inc(NH) \
  do {                   \
    (NH)->num_elts++;    \
    (NH)->cur_elts++;    \
  } while (0)

int nexthops_disable(nexthops_t *nexthops, off_t offset);

#define nexthops_disable_if(NH, i, condition) \
  do {                                        \
    if (condition) {                          \
      nexthops_disable((NH), (i));            \
    }                                         \
  } while (0)

#define nexthops_is_disabled(NH, i) ((NH)->flags & (1 << (i)))

void nexthops_reset(nexthops_t *nexthops);

#define nexthops_enumerate(NH, I, X, BODY)             \
  do {                                                 \
    nexthop_t X;                                       \
    (void)X;                                           \
    unsigned I;                                        \
    (void)I;                                           \
    for ((I) = 0; (I) < nexthops_get_len(NH); (I)++) { \
      if (nexthops_is_disabled((NH), (I))) continue;   \
      X = (NH)->elts[(I)];                             \
      do {                                             \
        BODY                                           \
      } while (0);                                     \
    }                                                  \
  } while (0)

#define nexthops_foreach(NH, X, BODY)                      \
  do {                                                     \
    nexthops_enumerate((NH), _nexthops_var(i), X, {BODY}); \
  } while (0)

off_t nexthops_add(nexthops_t *nexthops, nexthop_t nexthop);

off_t nexthops_remove(nexthops_t *nexthops, nexthop_t nexthop);

#define nexthops_clear(NH)   \
  do {                       \
    nexthops_set_len(NH, 0); \
    (NH)->flags = 0;         \
  } while (0)

bool nexthops_contains(nexthops_t *nexthops, unsigned nexthop);

off_t nexthops_find(nexthops_t *nexthops, unsigned nexthop);

unsigned nexthops_get_one(nexthops_t *nexthops);

int nexthops_select(nexthops_t *nexthops, off_t i);

/*
 * This selects the first available element, irrespective of the current state
 * of flags
 */
#define nexthops_select_first(NH) nexthops_select((NH), 0)

#ifdef WITH_POLICY

#define DEFAULT_PRIORITY 0
#define DISABLED_PRIORITY -1

void nexthops_set_priority(nexthops_t *nexthops, nexthop_t nexthop,
                           int priority);

void nexthops_set_priority_by_id(nexthops_t *nexthops, off_t i, int priority);

void nexthops_reset_priority_by_id(nexthops_t *nexthops, off_t i);

void nexthops_reset_priority(nexthops_t *nexthops, nexthop_t nexthop);

void nexthops_reset_priorities(nexthops_t *nexthops);

/*
 * returns true if the list of next hops contained in a is the same of b
 * returns false otherwise
 */
bool nexthops_equal(nexthops_t *a, nexthops_t *b);

void nexthops_copy(nexthops_t *src, nexthops_t *dst);

#endif /* WITH_POLICY */

uint32_t nexthops_get_hash(nexthops_t *nexthops);

#endif /* HICNLIGHT_NEXTHOPS_H */
