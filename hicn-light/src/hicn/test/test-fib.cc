/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#define WITH_TESTS
#include <hicn/util/ip_address.h>
#include <hicn/config/configuration.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/fib.h>
}

/*
 * TODO
 * - test max_size
 */

#define DEFAULT_SIZE 10
#define ARRAY_SIZE(a) ((sizeof(a) / sizeof(*(a))))

class FibTest : public ::testing::Test {
 protected:
  FibTest() { fib = fib_create(NULL); }
  virtual ~FibTest() { fib_free(fib); }

  configuration_t *configuration;
  forwarder_t *forwarder;
  fib_t *fib;
};

void _fib_add_prefix(fib_t *fib, const hicn_prefix_t *prefix) {
  fib_entry_t *entry =
      fib_entry_create(prefix, STRATEGY_TYPE_UNDEFINED, NULL, NULL);
  fib_add(fib, entry);
}

static const hicn_prefix_t p0010 = (hicn_prefix_t){
    .name = {.v6 = {.as_u64 = {0x1122334455667788, 0x9900aabbccddeeff}}},
    .len = 4};

/* TEST: Fib allocation and initialization */
TEST_F(FibTest, FibAddOne) {
  /* Empty fib should be valid */

  const hicn_prefix_t *empty_prefix_array[] = {};
  bool empty_used_array[] = {};
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, empty_prefix_array, empty_used_array));

  const hicn_prefix_t *prefix_array[] = {&p0010};
  bool used_array[] = {true};

  for (unsigned i = 0; i < ARRAY_SIZE(prefix_array); i++) {
    if (!used_array[i]) continue;
    _fib_add_prefix(fib, prefix_array[i]);
  }

  fib_dump(fib);

  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array, used_array));

  /* Check that free indices and bitmaps are correctly updated */
}
