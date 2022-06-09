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

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hicn/transport/portability/cache.h>

#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace utils {

class LoopTest : public ::testing::Test {
 protected:
  static inline const std::size_t size = 256;

  LoopTest() = default;

  ~LoopTest() override = default;

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  void SetUp() override {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  void TearDown() override {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }
};

// 1 cache line struct (64 bytes)
struct Data {
  std::array<uint64_t, 8> data;
};

TEST_F(LoopTest, QuadLoopTest) {
  // Create 2 arrays of 256 elements
  std::vector<std::unique_ptr<Data>> _from;
  std::vector<std::unique_ptr<Data>> _to_next;
  _from.reserve(size);
  _to_next.reserve(size);

  int n_left_from = size;
  int n_left_to_next = size;

  // Initialize the arrays
  for (std::size_t i = 0; i < size; i++) {
    _from.push_back(std::make_unique<Data>());
    _to_next.push_back(std::make_unique<Data>());

    for (int j = 0; j < 8; j++) {
      _from[i]->data[j] = j;
      _to_next[i]->data[j] = 0;
    }
  }

  const std::unique_ptr<Data> *from = &_from[0];
  const std::unique_ptr<Data> *to_next = &_to_next[0];

  clock_t start;
  clock_t end;
  double clocks;

  start = clock();
  // Create a quad loop
  while (n_left_from > 0) {
    while (n_left_from >= 4 && n_left_to_next >= 4) {
      {
        using namespace transport::portability::cache;
        Data *d2;
        Data *d3;

        d2 = from[2].get();
        d3 = from[3].get();

        prefetch<Data, READ>(d2, sizeof(Data));
        prefetch<Data, READ>(d3, sizeof(Data));

        d2 = to_next[2].get();
        d3 = to_next[3].get();

        prefetch<Data, WRITE>(d2, sizeof(Data));
        prefetch<Data, WRITE>(d3, sizeof(Data));
      }

      // Do 4 iterations
      std::memcpy(to_next[0].get()->data.data(), from[0].get()->data.data(),
                  sizeof(Data));
      std::memcpy(to_next[1].get()->data.data(), from[1].get()->data.data(),
                  sizeof(Data));
      n_left_from -= 2;
      n_left_to_next -= 2;
      from += 2;
      to_next += 2;
    }

    while (n_left_from > 0 && n_left_to_next > 0) {
      std::memcpy(to_next[0].get()->data.data(), from[0].get()->data.data(),
                  sizeof(Data));
      n_left_from -= 1;
      n_left_to_next -= 1;
      from += 1;
      to_next += 1;
    }
  }
  end = clock();
  clocks = (double)(end - start);

  LOG(INFO) << "Time with quad loop: " << clocks << std::endl;
}

TEST_F(LoopTest, NormalLoopTest) {
  // Create 2 arrays of 256 elements
  std::vector<std::unique_ptr<Data>> _from;
  std::vector<std::unique_ptr<Data>> _to_next;
  _from.reserve(size);
  _to_next.reserve(size);

  int n_left_from = size;
  int n_left_to_next = size;

  // Initialize the arrays
  for (std::size_t i = 0; i < size; i++) {
    _from.push_back(std::make_unique<Data>());
    _to_next.push_back(std::make_unique<Data>());

    for (int j = 0; j < 8; j++) {
      _from[i]->data[j] = j;
      _to_next[i]->data[j] = 0;
    }
  }

  const std::unique_ptr<Data> *from = &_from[0];
  const std::unique_ptr<Data> *to_next = &_to_next[0];

  clock_t start;
  clock_t end;
  double clocks;

  start = clock();
  while (n_left_from > 0) {
    while (n_left_from > 0 && n_left_to_next > 0) {
      std::memcpy(to_next[0].get()->data.data(), from[0].get()->data.data(),
                  sizeof(Data));
      n_left_from -= 1;
      n_left_to_next -= 1;
      from += 1;
      to_next += 1;
    }
  }
  end = clock();
  clocks = ((double)(end - start));

  LOG(INFO) << "Time with normal loop: " << clocks << std::endl;
}

}  // namespace utils