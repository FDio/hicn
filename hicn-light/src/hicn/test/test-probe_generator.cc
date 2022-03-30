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
#include <arpa/inet.h>

extern "C" {
#define WITH_TESTS
#include <hicn/strategies/probe_generator.h>
}

class ProbeGeneratorTest : public ::testing::Test {
 protected:
  ProbeGeneratorTest() {}

  virtual ~ProbeGeneratorTest() {}
};

TEST_F(ProbeGeneratorTest, ProbeGeneratorRegisterProbe) {
  probe_generator_t *pg = create_probe_generator();
  EXPECT_FALSE(pg == nullptr);

  register_probe(pg, 1);
  register_probe(pg, 2);
  register_probe(pg, 3);
  register_probe(pg, 4);

  Ticks t = get_probe_send_time(pg, 1);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 2);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 3);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 4);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 5);
  EXPECT_FALSE(t != 0);

  destroy_probe_generator(pg);
}

TEST_F(ProbeGeneratorTest, ProbeGeneratorTime) {
  probe_generator_t *pg = create_probe_generator();
  EXPECT_FALSE(pg == nullptr);

  Ticks t1 = register_probe(pg, 1);
  Ticks t2 = get_probe_send_time(pg, 1);

  EXPECT_TRUE(t2 != 0);
  EXPECT_TRUE(t1 == t2);

  destroy_probe_generator(pg);
}

TEST_F(ProbeGeneratorTest, ProbeGeneratorDeleteProbe) {
  probe_generator_t *pg = create_probe_generator();
  EXPECT_FALSE(pg == nullptr);

  register_probe(pg, 1);
  register_probe(pg, 2);
  register_probe(pg, 3);
  register_probe(pg, 4);

  Ticks t = get_probe_send_time(pg, 1);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 2);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 3);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 4);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 5);
  EXPECT_FALSE(t != 0);

  delete_probe(pg, 1);
  delete_probe(pg, 3);

  t = get_probe_send_time(pg, 1);
  EXPECT_FALSE(t != 0);

  t = get_probe_send_time(pg, 3);
  EXPECT_FALSE(t != 0);

  destroy_probe_generator(pg);
}

TEST_F(ProbeGeneratorTest, ProbeGeneratorDeleteAll) {
  probe_generator_t *pg = create_probe_generator();
  EXPECT_FALSE(pg == nullptr);

  register_probe(pg, 1);
  register_probe(pg, 2);
  register_probe(pg, 3);
  register_probe(pg, 4);

  Ticks t = get_probe_send_time(pg, 1);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 2);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 3);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 4);
  EXPECT_TRUE(t != 0);

  t = get_probe_send_time(pg, 5);
  EXPECT_FALSE(t != 0);

  delete_all_probes(pg);

  t = get_probe_send_time(pg, 1);
  EXPECT_FALSE(t != 0);

  t = get_probe_send_time(pg, 2);
  EXPECT_FALSE(t != 0);

  t = get_probe_send_time(pg, 3);
  EXPECT_FALSE(t != 0);

  t = get_probe_send_time(pg, 4);
  EXPECT_FALSE(t != 0);

  destroy_probe_generator(pg);
}
