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

#include <hicn/transport/errors/not_implemented_exception.h>

namespace transport {
namespace protocol {

namespace fec {

template <typename T>
struct FecInfo {
  static bool isFec() { throw errors::NotImplementedException(); }
  static uint32_t nextSymbol(uint32_t index) {
    throw errors::NotImplementedException();
  }
  static uint32_t nextSource(uint32_t index) {
    throw errors::NotImplementedException();
  }
};

template <uint32_t K, uint32_t N>
struct Code {};

template <uint32_t K, uint32_t N>
struct FecInfo<Code<K, N>> {
  static bool isFec(uint32_t index) { return (index % N) >= K; }

  static uint32_t nextSymbol(uint32_t index) {
    if (isFec(index)) {
      return index;
    }

    return index + (K - (index % N));
  }

  static uint32_t nextSource(uint32_t index) {
    if (!isFec(index)) {
      return index;
    }

    return index + (N - (index % N));
  }
};

}  // namespace fec
}  // namespace protocol
}  // namespace transport