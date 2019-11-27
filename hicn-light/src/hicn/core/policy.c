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
 * @file policy.c
 * @brief Implementation of policy-related functions
 */

#ifdef WITH_POLICY

/* hICN policy definition from libhicn */
#include <hicn/policy.h>

/* hicn-light policy implementation */
#include <hicn/core/policy.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/numberSet.h>

// All replace and extend fibEntry_GetAvailableNextHops

NumberSet *
policy_FilterNextHops(const Forwarder * forwarder, NumberSet * nexthops, policy_t * policy, unsigned in_connection)
{
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);



}

/* used for consumer prefixes */
NumberSet *
policy_GetAvailableNextHops(const Forwarder * forwarder, NumberSet * nexthops, policy_t * policy, unsigned in_connection)
{
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);



}

/* used for producer prefixes */
NumberSet *
policy_GetAvailableNeighbours(const Forwarder * forwarder, NumberSet * nexthops, policy_t * policy, unsigned in_connection)
{
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);



}
#endif /* WITH_POLICY */
