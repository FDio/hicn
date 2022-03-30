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

#ifndef __IETF_HICN_H__
#define __IETF_HICN_H__

#include "../hicn_light_comm.h"

#define MEM_ALIGN 4096

// Number of locks is equal to number of nodes in hicn-state
// It is a coarse grain approach later can be changed to fine grained
// better to initialize the lock by 0
#define NLOCKS 5
#define LOCK_INIT 0

enum locks_name { lstate, lstrategy, lstrategies, lroute, lface_ip_params };

#define NSTATE_LEAVES 15
#define NSTRATEGY_LEAVES 1
#define NSTRATEGIES_LEAVES 2
#define NROUTE_LEAVES 2
#define NFACE_IP_PARAMS_LEAVES 3

int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription);

#endif /* __IETF_HICN_H__ */