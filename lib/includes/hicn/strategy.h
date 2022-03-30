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
 * \file strategy.h
 * \brief hICN forwarding strategy
 */
#ifndef HICN_STRATEGY_H
#define HICN_STRATEGY_H

#include <string.h>

#define foreach_strategy_type                                                 \
  _ (UNDEFINED)                                                               \
  _ (LOADBALANCER)                                                            \
  _ (LOW_LATENCY)                                                             \
  _ (RANDOM)                                                                  \
  _ (REPLICATION)                                                             \
  _ (BESTPATH)                                                                \
  _ (N)

typedef enum
{
#define _(x) STRATEGY_TYPE_##x,
  foreach_strategy_type
#undef _
} strategy_type_t;

extern const char *strategy_str[];
#define strategy_str(x) strategy_str[x]

#define IS_VALID_STRATEGY_TYPE(x) IS_VALID_ENUM_TYPE (STRATEGY_TYPE, x)

static inline strategy_type_t
strategy_type_from_str (const char *strategy_str)
{
#define _(x)                                                                  \
  if (strcasecmp (strategy_str, #x) == 0)                                     \
    return STRATEGY_TYPE_##x;                                                 \
  else
  foreach_strategy_type
#undef _
    return STRATEGY_TYPE_UNDEFINED;
}

#define STRATEGY_TYPE_VALID(type)                                             \
  ((type != STRATEGY_TYPE_UNDEFINED) && (type != STRATEGY_TYPE_N))

#define MAX_FWD_STRATEGY_RELATED_PREFIXES 10

#endif /* HICN_STRATEGY_H */
