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

#ifndef __HICN_STRATEGY_RP_H__
#define __HICN_STRATEGY_RP_H__

#include "../strategy.h"

/**
 * @file strategy_rp.h
 *
 * This file implements the replication strategy. In this
 * strategy all the next hops are used to send an intertest.
 */

/**
 * @brief Return the vft for the Replication strategy
 */
hicn_strategy_vft_t *hicn_rp_strategy_get_vft (void);

#endif // __HICN_STRATEGY_RP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
