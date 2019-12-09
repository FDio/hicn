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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hicn/hicn-light/config.h>

#include <hicn/base/nexthops.h>
#include <hicn/strategies/rnd.h>

static
void
strategy_random_initialize(strategy_entry_t * entry)
{
  srand((unsigned int)time(NULL));
}

static
void
strategy_random_finalize(strategy_entry_t * entry)
{
  /* Nothing to do */
}

static
void
strategy_random_add_nexthop(strategy_entry_t * entry,
        unsigned nexthop)
{
  /* Nothing to do */
}

static void strategy_random_remove_nexthop(strategy_entry_t * entry,
        unsigned nexthop)
{
  /* Nothing to do */
}

static
nexthops_t * nexthops
strategy_random_lookup_nexthops(strategy_entry_t * entry,
        const nexthops_t * nexthops,
        const msgbuf_t * msgbuf)
{
  nexthops_select(nexthops, rand() % nexthops_len(nexthops));
  return nexthops;
}

static
void
strategy_random_on_data(strategy_entry_t * entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
  /* Nothing to do */
}

static
void
strategy_random_on_timeout(strategy_entry_t * entry,
        const nexthops_t * nexthops)
{
  /* Nothing to do */
}


DECLARE_STRATEGY(random);
