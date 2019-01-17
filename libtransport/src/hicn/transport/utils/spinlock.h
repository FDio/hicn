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

#pragma once

#include <atomic>

namespace utils {

class SpinLock : private std::atomic_flag {
 public:
  class Acquire {
   public:
    Acquire(SpinLock& spin_lock) : spin_lock_(spin_lock) { spin_lock_.lock(); }

    ~Acquire() { spin_lock_.unlock(); }

    // No copies
    Acquire& operator=(const Acquire&) = delete;
    Acquire(const Acquire&) = delete;

   private:
    SpinLock& spin_lock_;
  };

  SpinLock() : std::atomic_flag(false) {}

  void lock() {
    // busy-wait
    while (std::atomic_flag::test_and_set(std::memory_order_acquire))
      ;
  }

  void unlock() { clear(std::memory_order_release); }

  bool tryLock() {
    return std::atomic_flag::test_and_set(std::memory_order_acquire);
  }
};

}  // namespace utils