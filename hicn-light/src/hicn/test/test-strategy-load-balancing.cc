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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/strategy.h>
#include <hicn/strategies/random.h>
}

#define MAX_TESTS 10

#define NEXTHOP_ID NEXTHOP(28)
#define NEXTHOP_ID2 NEXTHOP(29)
#define UNKNOWN_ID1 NEXTHOP(0)
#define UNKNOWN_ID2 NEXTHOP(1)

class StrategyLoadBalancing : public ::testing::Test {
 protected:
  StrategyLoadBalancing() {
    /* Strategy and strategy entry */
    entry = {
        .type = STRATEGY_TYPE_LOADBALANCER,
        .options =
            {
                .random = {},
            },
        .state = {.random = {}},
    };

    strategy_initialize(&entry, nullptr);

    /* Available nexthops */
    available_nexthops_ = NEXTHOPS_EMPTY;
    EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)0);

    /* Message buffer */
    msgbuf_ = NULL;
    ticks_ = ticks_now();
  }
  virtual ~StrategyLoadBalancing() {}

  strategy_entry_t entry;
  nexthops_t available_nexthops_;
  msgbuf_t* msgbuf_;
  Ticks ticks_;
};

TEST_F(StrategyLoadBalancing, SingleNexthop) {
  /* Add a single nexthop */
  off_t id;
  id = nexthops_add(&available_nexthops_, NEXTHOP_ID);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)1);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)1);

  strategy_add_nexthop(&entry, &available_nexthops_, id);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)1);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)1);

  EXPECT_TRUE(nexthops_contains(&available_nexthops_, NEXTHOP_ID));
  EXPECT_FALSE(nexthops_contains(&available_nexthops_, UNKNOWN_ID1));
  EXPECT_FALSE(nexthops_contains(&available_nexthops_, UNKNOWN_ID2));

  /* Lookup */
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry, &available_nexthops_, msgbuf_);

  EXPECT_EQ(nexthops_get_len(nexthops), (size_t)1);
  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)1);

  EXPECT_TRUE(nexthops_contains(nexthops, NEXTHOP_ID));
  EXPECT_FALSE(nexthops_contains(nexthops, UNKNOWN_ID1));
  EXPECT_FALSE(nexthops_contains(nexthops, UNKNOWN_ID2));

  /* Retrieve candidate */

  unsigned nexthop;
  for (unsigned i = 0; i < MAX_TESTS; i++) {
    nexthop = nexthops_get_one(nexthops);
    EXPECT_EQ(nexthop, NEXTHOP_ID);
  }

  /* Disable (move to nexthop unit tests) */
  nexthops_disable(nexthops, 0);

  EXPECT_EQ(nexthops_get_len(nexthops), (size_t)1);
  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)0);

  nexthop = nexthops_get_one(nexthops);
  EXPECT_EQ(nexthop, INVALID_NEXTHOP);
}

TEST_F(StrategyLoadBalancing, MultipleNexthops) {
  off_t id, id2;
  /* Add a single nexthop */
  id = nexthops_add(&available_nexthops_, NEXTHOP_ID);
  id2 = nexthops_add(&available_nexthops_, NEXTHOP_ID2);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)2);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)2);

  strategy_add_nexthop(&entry, &available_nexthops_, id);
  strategy_add_nexthop(&entry, &available_nexthops_, id2);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)2);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)2);

  EXPECT_TRUE(nexthops_contains(&available_nexthops_, NEXTHOP_ID));
  EXPECT_TRUE(nexthops_contains(&available_nexthops_, NEXTHOP_ID2));
  EXPECT_FALSE(nexthops_contains(&available_nexthops_, UNKNOWN_ID1));
  EXPECT_FALSE(nexthops_contains(&available_nexthops_, UNKNOWN_ID2));

  /* Lookup */
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry, &available_nexthops_, msgbuf_);

  EXPECT_EQ(nexthops_get_len(nexthops), (size_t)2);
  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)1);

  EXPECT_TRUE((nexthops_contains(nexthops, NEXTHOP_ID)) ||
              (nexthops_contains(nexthops, NEXTHOP_ID2)));
  EXPECT_FALSE(nexthops_contains(nexthops, UNKNOWN_ID1));
  EXPECT_FALSE(nexthops_contains(nexthops, UNKNOWN_ID2));

  /* Retrieve candidate */

  unsigned nexthop;
  for (unsigned i = 0; i < MAX_TESTS; i++) {
    nexthop = nexthops_get_one(nexthops);
    EXPECT_TRUE((nexthop == NEXTHOP_ID) || (nexthop == NEXTHOP_ID2));
  }
}
