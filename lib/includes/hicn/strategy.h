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
 * \file strategy.h
 * \brief hICN forwarding strategy
 */
#ifndef HICN_STRATEGY_H
#define HICN_STRATEGY_H

typedef enum {
  STRATEGY_TYPE_UNDEFINED,
  STRATEGY_TYPE_LOADBALANCER,
  STRATEGY_TYPE_LOW_LATENCY,
  STRATEGY_TYPE_RANDOM,
  STRATEGY_TYPE_N
} strategy_type_t;

#define STRATEGY_TYPE_VALID(type) \
    ((type != STRATEGY_TYPE_UNDEFINED) && (type != STRATEGY_TYPE_N))

#define MAX_FWD_STRATEGY_RELATED_PREFIXES 10

#endif /* HICN_STRATEGY_H */
