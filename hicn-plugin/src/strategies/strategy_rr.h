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

#ifndef __HICN_STRATEGY_RR_H__
#define __HICN_STRATEGY_RR_H__

#include "../strategy.h"

/**
 * @file strategy_rr.h
 *
 * This file implements the round robin strategy. In this
 * strategy the next hop is choosen in a round robin way.
 */

/**
 * @brief Return the vft for the Round Robin strategy
 */
hicn_strategy_vft_t *hicn_rr_strategy_get_vft (void);

#endif // __HICN_STRATEGY_RR_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
