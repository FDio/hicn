/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 */

#ifndef HICN_NEXTHOPS_H
#define HICN_NEXTHOPS_H

#include <stdint.h>
#include <stdbool.h>

#include <hicn/base/strategy.h>

#define _nexthops_var(x) _nexthops_##x

/*
 * This allows storage within a single integer
 * 32 or 64 nexthops should be sufficient
 * Eventually replace this with a resizeable vector
 */
#define MAX_NEXTHOPS (sizeof(uint_fast32_t) * 8)

typedef struct {
  unsigned elts[MAX_NEXTHOPS];
  strategy_nexthop_state_t state[MAX_NEXTHOPS];
  size_t num_elts;
  uint_fast32_t flags;
  size_t cur_elts;
} nexthops_t;

#define nexthops_state(nexthops, i) ((nexthops)->state[(i)])

#define nexthops_len(nexthops) ((nexthops)->num_elts)
#define nexthops_curlen(nexthops) ((nexthops)->cur_elts)
#define nexthops_inc(nexthops)                                          \
do {                                                                    \
  (nexthops)->num_elts++;                                               \
  (nexthops)->cur_elts++;                                               \
} while(0)

#define nexthops_disable(nexthops, i)                                   \
do {                                                                    \
  (nexthops)->flags |= (1 << (i));                                      \
  (nexthops)->cur_elts--;                                               \
} while(0)

#define nexthops_disable_if(nexthops, i, condition)                     \
do {                                                                    \
  if (condition)                                                        \
    nexthops_disable((nexthops), (i));                                  \
} while(0)

#define nexthops_is_disabled(nexthops, i) ((nexthops)->flags & (1 << (i)))

#define nexthops_reset(nexthops)                                        \
do {                                                                    \
   (nexthops)->flags = 0;                                               \
   (nexthops)->cur_elts = (nexthops)->num_elts;                         \
} while(0)

#define nexthops_enumerate(nexthops, i, nexthop, BODY)                  \
do {                                                                    \
  for ((i) = 0; (i) < nexthops_len(nexthops); (i)++) {                  \
    if (nexthops_is_disabled((nexthops), (i)))                          \
      continue;                                                         \
    nexthop = (nexthops)->elts[(i)];                                    \
    do { BODY } while(0);                                               \
  }                                                                     \
} while(0)

#define nexthops_foreach(nexthops, nexthop, BODY)                       \
do {                                                                    \
  unsigned _nexthops_var(i);                                            \
  nexthops_enumerate((nexthops), _nexthops_var(i), (nexthop), { BODY });\
} while(0)

#define nexthops_add(nexthops, nexthop)                                 \
do {                                                                    \
  unsigned _nexthops_var(n);                                            \
  bool _nexthops_var(found) = false;                                    \
  nexthops_foreach((nexthops), _nexthops_var(n), {                      \
    if (_nexthops_var(n) == (nexthop)) {                                \
      _nexthops_var(found) = true;                                      \
      break;                                                            \
    }                                                                   \
  });                                                                   \
  if (!_nexthops_var(found)) {                                          \
    (nexthops)->elts[(nexthops)->num_elts++] = (nexthop);               \
    nexthops_reset(nexthops);                                           \
  }                                                                     \
} while(0)

#define nexthops_remove(nexthops, nexthop)                              \
do {                                                                    \
  unsigned _nexthops_var(n);                                            \
  unsigned _nexthops_var(i);                                            \
  nexthops_enumerate((nexthops), _nexthops_var(i), _nexthops_var(n), {  \
    if (_nexthops_var(n) == nexthop) {                                  \
      (nexthops)->elts[_nexthops_var(i)] =                              \
            (nexthops)->elts[(nexthops)->num_elts--];                   \
      nexthops_reset(nexthops);                                         \
    }                                                                   \
  });                                                                   \
} while(0)

static inline
bool
nexthops_contains(nexthops_t * nexthops, unsigned nexthop)
{
  unsigned n;
  nexthops_foreach(nexthops, n, {
    if (n == nexthop)
      return true;
  });
  return false;
}

#define nexthops_select(nexthops, i) ((nexthops)->flags = 1 << (i))
#define nexthops_select_one(nexthops) (nexthops_select((nexthops), 0))

#endif /* HICN_NEXTHOPS_H */
