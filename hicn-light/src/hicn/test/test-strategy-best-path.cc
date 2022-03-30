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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/strategy.h>
#include <hicn/strategies/best_path.h>
}

#define MAX_TESTS 10

#define NEXTHOP_ID1 NEXTHOP(28)
#define NEXTHOP_ID2 NEXTHOP(29)
#define UNKNOWN_ID1 NEXTHOP(0)
#define UNKNOWN_ID2 NEXTHOP(1)

class StrategyBestpathTest : public ::testing::Test {
 protected:
  StrategyBestpathTest() {
    /* Strategy and strategy entry */
    entry = {
        .type = STRATEGY_TYPE_BESTPATH,
        .options =
            {
                .bestpath = {},
            },
        .state = {.bestpath = {}},
    };

    strategy_initialize(&entry, nullptr);

    // test init
    EXPECT_EQ(entry.forwarder, nullptr);
    EXPECT_EQ(entry.state.bestpath.best_nexthop, (unsigned)~0);
    EXPECT_EQ(entry.state.bestpath.probing_state, PROBING_OFF);

    /* Available nexthops */
    available_nexthops_ = NEXTHOPS_EMPTY;
    EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)0);

    /* Message buffer */
    msgbuf_ = NULL;
    ticks_ = ticks_now();
  }

  virtual ~StrategyBestpathTest() {}

  strategy_entry_t entry;
  nexthops_t available_nexthops_;
  msgbuf_t *msgbuf_;
  Ticks ticks_;
};

TEST_F(StrategyBestpathTest, emptyNexthop) {
  nexthops_t *nexthops;
  nexthops = strategy_lookup_nexthops(&entry, &available_nexthops_, msgbuf_);
  EXPECT_EQ(nexthops_get_len(nexthops), (size_t)0);
}

TEST_F(StrategyBestpathTest, faceExists) {
  nexthops_t *nexthops;

  nexthops_add(&available_nexthops_, NEXTHOP_ID1);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)1);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)1);

  nexthops_add(&available_nexthops_, NEXTHOP_ID2);
  EXPECT_EQ(nexthops_get_len(&available_nexthops_), (size_t)2);
  EXPECT_EQ(nexthops_get_curlen(&available_nexthops_), (size_t)2);

  entry.state.bestpath.probing_state = PROBING_OFF;
  entry.state.bestpath.best_nexthop = NEXTHOP_ID2;

  nexthops = strategy_lookup_nexthops(&entry, &available_nexthops_, msgbuf_);

  EXPECT_EQ(nexthops_get_len(nexthops), (size_t)2);
  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)1);

  EXPECT_TRUE(nexthops_contains(nexthops, NEXTHOP_ID2));
  EXPECT_FALSE(nexthops_contains(nexthops, NEXTHOP_ID1));

  EXPECT_TRUE(entry.state.bestpath.probing_state == PROBING_OFF);
  EXPECT_EQ(entry.state.bestpath.best_nexthop, NEXTHOP_ID2);
}
