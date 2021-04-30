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

#pragma once

#include <atomic>
#include <mutex>

namespace transport {

namespace core {

template <typename T = uint64_t>
class GlobalCounter {
 public:
  static GlobalCounter& getInstance() {
    std::lock_guard<std::mutex> lock(global_mutex_);

    if (!instance_) {
      instance_.reset(new GlobalCounter());
    }

    return *instance_;
  }

  T getNext() { return counter_++; }

 private:
  GlobalCounter() : counter_(0) {}
  static std::unique_ptr<GlobalCounter<T>> instance_;
  static std::mutex global_mutex_;
  std::atomic<T> counter_;
};

template <typename T>
std::unique_ptr<GlobalCounter<T>> GlobalCounter<T>::instance_ = nullptr;

template <typename T>
std::mutex GlobalCounter<T>::global_mutex_;

}  // namespace core
}  // namespace transport