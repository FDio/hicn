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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/nexthops.h>
#include <hicn/core/strategy.h>
}

#define NEXTHOP1 50
#define NEXTHOP2 51
#define NEXTHOP3 52

class NexthopsTest : public ::testing::Test {
 protected:
  NexthopsTest() {}

  virtual ~NexthopsTest() {}

  nexthops_t nexthops;
};

TEST_F(NexthopsTest, NexthopsAdd) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);

  EXPECT_TRUE(nexthops_get_len(&nexthops) == 1);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));

  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));
}

TEST_F(NexthopsTest, NexthopsRemove) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_remove(&nexthops, NEXTHOP2);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 2);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_remove(&nexthops, NEXTHOP3);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 1);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_remove(&nexthops, NEXTHOP3);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 1);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_remove(&nexthops, NEXTHOP1);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 0);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));
}

TEST_F(NexthopsTest, NexthopsClear) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_clear(&nexthops);

  EXPECT_TRUE(nexthops_get_len(&nexthops) == 0);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));
}

TEST_F(NexthopsTest, NexthopsGetOne) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  unsigned nexthop = nexthops_get_one(&nexthops);

  EXPECT_TRUE(nexthops_contains(&nexthops, nexthop));
}

TEST_F(NexthopsTest, NexthopsSelect) {
  int ret;
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  ret = nexthops_select(&nexthops, 2);

  EXPECT_TRUE(ret == 0);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 1);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  ret = nexthops_select(&nexthops, 0);

  EXPECT_TRUE(ret == 0);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 1);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));

  nexthops_reset(&nexthops);

  EXPECT_TRUE(ret == 0);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  ret = nexthops_select(&nexthops, 4);

  EXPECT_TRUE(ret == -1);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  ret = nexthops_select(&nexthops, 3);

  EXPECT_TRUE(ret == -1);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 3);
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));
}

TEST_F(NexthopsTest, NexthopsDisable) {
  int ret;
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);

  ret = nexthops_disable(&nexthops, 0);

  EXPECT_TRUE(ret == 0);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 2);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  ret = nexthops_disable(&nexthops, 2);

  EXPECT_TRUE(ret == 0);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 1);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));

  ret = nexthops_disable(&nexthops, 3);
  EXPECT_TRUE(ret == -1);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 3);
  EXPECT_TRUE(nexthops_get_curlen(&nexthops) == 1);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP3));
}

TEST_F(NexthopsTest, NexthopsState) {
  strategy_nexthop_state_t state;
  nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP2);
  nexthops_add(&nexthops, NEXTHOP3);
  nexthops.state[0].load_balancer.pi = 100;
  nexthops.state[1].load_balancer.pi = 200;
  nexthops.state[2].load_balancer.pi = 300;

  state = nexthops_state(&nexthops, 0);
  EXPECT_TRUE(state.load_balancer.pi == 100);

  state = nexthops_state(&nexthops, 1);
  EXPECT_TRUE(state.load_balancer.pi == 200);

  state = nexthops_state(&nexthops, 2);
  EXPECT_TRUE(state.load_balancer.pi == 300);

  nexthops_remove(&nexthops, NEXTHOP1);
  EXPECT_TRUE(nexthops_get_len(&nexthops) == 2);
  EXPECT_FALSE(nexthops_contains(&nexthops, NEXTHOP1));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP2));
  EXPECT_TRUE(nexthops_contains(&nexthops, NEXTHOP3));

  state = nexthops_state(&nexthops, 0);
  EXPECT_TRUE(state.load_balancer.pi == 300);

  state = nexthops_state(&nexthops, 1);
  EXPECT_TRUE(state.load_balancer.pi == 200);
}

TEST_F(NexthopsTest, NexthopsEqual) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_t nexthops_eq = NEXTHOPS_EMPTY;
  nexthops_t nexthops_not_eq = NEXTHOPS_EMPTY;

  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP3);
  nexthops_add(&nexthops_eq, NEXTHOP1);
  nexthops_add(&nexthops_eq, NEXTHOP3);
  nexthops_add(&nexthops_not_eq, NEXTHOP2);

  bool ret = nexthops_equal(&nexthops, &nexthops_eq);
  EXPECT_TRUE(ret);

  ret = nexthops_equal(&nexthops, &nexthops_not_eq);
  EXPECT_FALSE(ret);
}

TEST_F(NexthopsTest, NexthopsCopy) {
  nexthops = NEXTHOPS_EMPTY;
  nexthops_t nexthops_eq = NEXTHOPS_EMPTY;

  nexthops_add(&nexthops, NEXTHOP1);
  nexthops_add(&nexthops, NEXTHOP3);
  nexthops_copy(&nexthops, &nexthops_eq);

  bool ret = nexthops_equal(&nexthops, &nexthops_eq);
  EXPECT_TRUE(ret);
}
