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
#include <hicn/transport/utils/event_thread.h>

#include <cmath>

namespace utils {

namespace {

class EventThreadTest : public ::testing::Test {
 protected:
  EventThreadTest() : event_thread_() {
    // You can do set-up work for each test here.
  }

  virtual ~EventThreadTest() {
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

  utils::EventThread event_thread_;
};

double average(const unsigned long samples[], int size) {
  double sum = 0;

  for (int i = 0; i < size; i++) {
    sum += samples[i];
  }

  return sum / size;
}

double stdDeviation(const unsigned long samples[], int size) {
  double avg = average(samples, size);
  double var = 0;

  for (int i = 0; i < size; i++) {
    var += (samples[i] - avg) * (samples[i] - avg);
  }

  return sqrt(var / size);
}

}  // namespace

TEST_F(EventThreadTest, DISABLED_SchedulingDelay) {
  using namespace std::chrono;
  const size_t size = 1000000;
  std::vector<unsigned long> samples(size);

  for (unsigned int i = 0; i < size; i++) {
    auto t0 = steady_clock::now();
    event_thread_.add([t0, &samples, i]() {
      auto t1 = steady_clock::now();
      samples[i] = duration_cast<nanoseconds>(t1 - t0).count();
    });
  }

  event_thread_.stop();

  auto avg = average(&samples[0], size);
  auto sd = stdDeviation(&samples[0], size);
  (void)sd;

  // Expect average to be less that 1 ms
  EXPECT_LT(avg, 1000000);
}

}  // namespace utils
