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
#include <cstddef>

namespace utils {

/**
 * NOTE: Single consumer single producer ring buffer
 */
template <typename Element, std::size_t Size>
class CircularFifo {
 public:
  enum { Capacity = Size + 1 };

  CircularFifo() : tail_(0), head_(0), size_(0) {}
  virtual ~CircularFifo() {}

  bool push(const Element& item);
  bool push(Element&& item);
  bool pop(Element& item);

  bool wasEmpty() const;
  bool wasFull() const;
  bool isLockFree() const;
  std::size_t size() const;

 private:
  std::size_t increment(std::size_t idx) const;
  std::atomic<std::size_t> tail_;  // tail(input) index
  Element array_[Capacity];
  std::atomic<std::size_t> head_;  // head(output) index
  std::atomic<std::size_t> size_;
};

template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::push(const Element& item) {
  const auto current_tail = tail_.load(std::memory_order_relaxed);
  const auto next_tail = increment(current_tail);
  if (next_tail != head_.load(std::memory_order_acquire)) {
    array_[current_tail] = item;
    tail_.store(next_tail, std::memory_order_release);
    size_++;
    return true;
  }

  // full queue
  return false;
}

/**
 * Push by move
 */
template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::push(Element&& item) {
  const auto current_tail = tail_.load(std::memory_order_relaxed);
  const auto next_tail = increment(current_tail);
  if (next_tail != head_.load(std::memory_order_acquire)) {
    array_[current_tail] = std::move(item);
    tail_.store(next_tail, std::memory_order_release);
    size_++;
    return true;
  }

  // full queue
  return false;
}

// Pop by Consumer can only update the head
// (load with relaxed, store with release)
// the tail must be accessed with at least acquire
template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::pop(Element& item) {
  const size_t current_head = head_.load(std::memory_order_relaxed);
  if (current_head == tail_.load(std::memory_order_acquire)) {
    return false;  // empty queue
  }

  item = std::move(array_[current_head]);
  head_.store(increment(current_head), std::memory_order_release);
  size_--;
  return true;
}

template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::wasEmpty() const {
  // snapshot with acceptance of that this comparison operation is not atomic
  return (head_.load() == tail_.load());
}

// snapshot with acceptance that this comparison is not atomic
template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::wasFull() const {
  const auto next_tail =
      increment(tail_.load());  // acquire, we dont know who call
  return (next_tail == head_.load());
}

template <typename Element, std::size_t Size>
bool CircularFifo<Element, Size>::isLockFree() const {
  return (tail_.is_lock_free() && head_.is_lock_free());
}

template <typename Element, std::size_t Size>
std::size_t CircularFifo<Element, Size>::increment(std::size_t idx) const {
  return (idx + 1) % Capacity;
}

template <typename Element, std::size_t Size>
std::size_t CircularFifo<Element, Size>::size() const {
  return size_.load(std::memory_order_relaxed);
}

}  // namespace utils