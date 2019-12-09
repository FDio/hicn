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
 * \file strategy.c
 * \brief Implementation of hICN forwarding strategy
 */

#include <hicn/base/strategy.h>

#include <hicn/strategies/load_balancer.h>
#include <hicn/strategies/random.h>
#include <hicn/strategies/low_latency.h>

extern const strategy_ops_t strategy_load_balancer;
extern const strategy_ops_t strategy_random;
extern const strategy_ops_t strategy_low_latency;

const strategy_ops_t * const strategy_vft[] = {
  [STRATEGY_TYPE_LOADBALANCER] = &strategy_load_balancer,
  [STRATEGY_TYPE_RANDOM] = &strategy_random,
#if 0
  [STRATEGY_TYPE_LOW_LATENCY] = &strategy_low_latency,
#endif
};


