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
 * @file policy.h
 * @brief Policy-related functions
 */

#ifndef HICN_POLICY_H
#define HICN_POLICY_H

#ifdef WITH_POLICY

#include <hicn/policy.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/numberSet.h>

NumberSet * policy_GetAvailableNextHops(const Forwarder * forwarder, NumberSet * nexthops, policy_t * policy, unsigned in_connection);


#endif /* WITH_POLICY */

#endif /* HICN_POLICY_H */
