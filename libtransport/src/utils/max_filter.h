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
 * limitations under the License.sudo make instamake install
 */

#pragma once

#include <deque>
#include <iostream>
#include <set>
#include <type_traits>
#include <vector>

namespace utils {

template <typename T>
class MaxFilter {
 public:
  MaxFilter(std::size_t size) : size_(size) {}

  std::size_t size() const { return by_arrival_.size(); }

  template <typename R>
  void pushBack(R&& value) {
    if (by_arrival_.size() >= size_) {
      by_order_.erase(by_arrival_.back());
      by_arrival_.pop_back();
    }

    by_arrival_.push_front(by_order_.insert(std::forward<R>(value)));
  }

  void clear() {
    by_arrival_.clear();
    by_order_.clear();
  }

  const T& begin() const { return *by_order_.crbegin(); }

  const T& rBegin() const { return *by_order_.rbegin(); }

 private:
  std::multiset<T> by_order_;
  std::deque<typename std::multiset<T>::const_iterator> by_arrival_;
  std::size_t size_;
};

}  // namespace utils
