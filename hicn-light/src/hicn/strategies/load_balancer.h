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
 * Forward on the less loaded path
 */

#ifndef HICNLIGHT_STRATEGY_LOAD_BALANCER_H
#define HICNLIGHT_STRATEGY_LOAD_BALANCER_H

typedef struct {
  unsigned int pi;
  double avg_pi;
  double weight;
} strategy_load_balancer_nexthop_state_t;

typedef struct {} strategy_load_balancer_state_t;

typedef struct {} strategy_load_balancer_options_t;

#endif /* HICNLIGHT_STRATEGY_LOAD_BALANCER_H */
