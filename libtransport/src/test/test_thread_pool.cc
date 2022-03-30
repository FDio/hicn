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
#include <hicn/transport/utils/thread_pool.h>

namespace utils {

class ThreadPoolTest : public ::testing::Test {
 protected:
  ThreadPoolTest() : thread_pool_() {
    // You can do set-up work for each test here.
  }

  virtual ~ThreadPoolTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  ::utils::ThreadPool thread_pool_;
};

TEST_F(ThreadPoolTest, DefaultConstructor) {
  // EXPECT_EQ(thread_pool_.GetNumThreads(), 0);
  // EXPECT_EQ(thread_pool_.GetNumIdleThreads(), 0);
  // EXPECT_EQ(thread_pool_.GetNumBusyThreads(), 0);
}

TEST_F(ThreadPoolTest, GetNThreads) {
  auto n_threads = thread_pool_.getNThreads();
  EXPECT_GT(n_threads, std::size_t(0));
  EXPECT_EQ(n_threads, std::thread::hardware_concurrency());

  ::utils::ThreadPool pool(64);
  n_threads = pool.getNThreads();
  EXPECT_GT(n_threads, std::size_t(0));
  EXPECT_NE(n_threads, std::thread::hardware_concurrency());
  EXPECT_EQ(n_threads, std::size_t(64));

  // EXPECT_EQ(thread_pool_.GetNumThreads(), 0);
  // EXPECT_EQ(thread_pool_.GetNumIdleThreads(), 0);
  // EXPECT_EQ(thread_pool_.GetNumBusyThreads(), 0);
}

}  // namespace utils