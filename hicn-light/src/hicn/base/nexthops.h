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

#define NEXTHOPS_EMPTY (nexthops_t) {                   \
    .elts = { 0 },                                      \
    .state = { STRATEGY_NEXTHOP_STATE_EMPTY },          \
    .num_elts = 0,                                      \
    .flags = 0,                                         \
    .cur_elts = 0,                                      \
}

#define nexthops_state(NH, i) ((NH)->state[(i)])

#define nexthops_get_len(NH) ((NH)->num_elts)

#define nexthops_set_len(NH, LEN) \
do {                                                                    \
    (NH)->num_elts = LEN;                                               \
    (NH)->cur_elts = LEN;                                               \
} while(0)

#define nexthops_get_curlen(NH) ((NH)->cur_elts)

#define nexthops_inc(NH)                                                \
do {                                                                    \
  (NH)->num_elts++;                                                     \
  (NH)->cur_elts++;                                                     \
} while(0)

#define nexthops_disable(NH, i)                                         \
do {                                                                    \
  (NH)->flags |= (1 << (i));                                            \
  (NH)->cur_elts--;                                                     \
} while(0)

#define nexthops_disable_if(NH, i, condition)                           \
do {                                                                    \
  if (condition)                                                        \
    nexthops_disable((NH), (i));                                        \
} while(0)

#define nexthops_is_disabled(NH, i) ((NH)->flags & (1 << (i)))

#define nexthops_reset(NH)                                              \
do {                                                                    \
   (NH)->flags = 0;                                                     \
   (NH)->cur_elts = (NH)->num_elts;                                     \
} while(0)

#define nexthops_enumerate(NH, i, X, BODY)                              \
do {                                                                    \
  for ((i) = 0; (i) < nexthops_get_len(NH); (i)++) {                    \
    if (nexthops_is_disabled((NH), (i)))                                \
      continue;                                                         \
    X = (NH)->elts[(i)];                                                \
    do { BODY } while(0);                                               \
  }                                                                     \
} while(0)

#define nexthops_foreach(NH, X, BODY)                                   \
do {                                                                    \
  unsigned _nexthops_var(i);                                            \
  nexthops_enumerate((NH), _nexthops_var(i), (X), { BODY });\
} while(0)

#define nexthops_add(NH, X)                                             \
do {                                                                    \
  unsigned _nexthops_var(n);                                            \
  bool _nexthops_var(found) = false;                                    \
  nexthops_foreach((NH), _nexthops_var(n), {                            \
    if (_nexthops_var(n) == (X)) {                                      \
      _nexthops_var(found) = true;                                      \
      break;                                                            \
    }                                                                   \
  });                                                                   \
  if (!_nexthops_var(found)) {                                          \
    (NH)->elts[(NH)->num_elts++] = (X);                                 \
    nexthops_reset(NH);                                                 \
  }                                                                     \
} while(0)

#define nexthops_remove(NH, X)                                          \
do {                                                                    \
  unsigned _nexthops_var(n);                                            \
  unsigned _nexthops_var(i);                                            \
  nexthops_enumerate((NH), _nexthops_var(i), _nexthops_var(n), {        \
    if (_nexthops_var(n) == X) {                                        \
      (NH)->elts[_nexthops_var(i)] =                                    \
            (NH)->elts[(NH)->num_elts--];                               \
      nexthops_reset(NH);                                               \
    }                                                                   \
  });                                                                   \
} while(0)

#define nexthops_clear(NH) nexthops_set_len(NH, 0);

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
