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

#include <hicn/transport/portability/portability.h>

#include <cstddef>

namespace utils {

template <typename T = uint8_t>
class Array {
 public:
  explicit Array(const T *array, size_t size) : array_(array), size_(size) {
    this->array_ = array;
    this->size_ = size;
  }

  Array() : array_(nullptr), size_(0) {
    this->array_ = nullptr;
    this->size_ = 0;
  }

  TRANSPORT_ALWAYS_INLINE const T *data() const { return array_; }

  TRANSPORT_ALWAYS_INLINE T *writableData() const {
    return const_cast<T *>(array_);
  }

  TRANSPORT_ALWAYS_INLINE std::size_t length() const { return size_; }

  TRANSPORT_ALWAYS_INLINE Array &setData(const T *data) {
    array_ = data;
    return *this;
  }

  TRANSPORT_ALWAYS_INLINE Array &setSize(std::size_t size) {
    size_ = size;
    return *this;
  }

  TRANSPORT_ALWAYS_INLINE bool empty() { return !size_; }

 private:
  const T *array_;
  std::size_t size_;
};

}  // namespace utils
