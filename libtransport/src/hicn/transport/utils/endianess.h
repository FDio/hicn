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

#ifndef _WIN32
#include <arp/inet.h>
#else
#include <hicn/transport/portability/win_portability.h>
#endif

#include <cstring>

namespace utils {

namespace {

template <size_t Size>
struct uint_types_by_size;

#define GENERATOR(sz, fn)                                                    \
  static TRANSPORT_ALWAYS_INLINE uint##sz##_t byteswap_gen(uint##sz##_t v) { \
    return fn(v);                                                            \
  }                                                                          \
  template <>                                                                \
  struct uint_types_by_size<sz / 8> {                                        \
    using type = uint##sz##_t;                                               \
  };

GENERATOR(8, uint8_t)
#ifdef _MSC_VER
GENERATOR(64, _byteswap_uint64)
GENERATOR(32, _byteswap_ulong)
GENERATOR(16, _byteswap_ushort)
#else
GENERATOR(64, __builtin_bswap64)
GENERATOR(32, __builtin_bswap32)
GENERATOR(16, __builtin_bswap16)
#endif

template <typename T>
struct EndianInt {
  static_assert(
      (std::is_integral<T>::value && !std::is_same<T, bool>::value) ||
          std::is_floating_point<T>::value,
      "template type parameter must be non-bool integral or floating point");

  static T swap(T x) {
    // we implement this with memcpy because that is defined behavior in C++
    // we rely on compilers to optimize away the memcpy calls
    constexpr auto s = sizeof(T);
    using B = typename uint_types_by_size<s>::type;
    B b;
    std::memcpy(&b, &x, s);
    b = byteswap_gen(b);
    std::memcpy(&x, &b, s);
    return x;
  }
  static T big(T x) {
    return portability::little_endian_arch ? EndianInt::swap(x) : x;
  }
  static T little(T x) {
    return portability::big_endian_arch ? EndianInt::swap(x) : x;
  }
};

}  // namespace

// big* convert between native and big-endian representations
// little* convert between native and little-endian representations
// swap* convert between big-endian and little-endian representations
//
// ntohs, htons == big16
// ntohl, htonl == big32
#define GENERATOR1(fn, t, sz) \
  static t fn##sz(t x) { return fn<t>(x); }

#define GENERATOR2(t, sz) \
  GENERATOR1(swap, t, sz) \
  GENERATOR1(big, t, sz)  \
  GENERATOR1(little, t, sz)

#define GENERATOR3(sz)         \
  GENERATOR2(uint##sz##_t, sz) \
  GENERATOR2(int##sz##_t, sz)

class Endian {
 public:
  enum class Order : uint8_t { LITTLE, BIG };

  static constexpr Order order =
      portability::little_endian_arch ? Order::LITTLE : Order::BIG;

  template <typename T>
  static T swap(T x) {
    return EndianInt<T>::swap(x);
  }

  template <typename T>
  static T big(T x) {
    return EndianInt<T>::big(x);
  }

  template <typename T>
  static T little(T x) {
    return EndianInt<T>::little(x);
  }

#if !defined(__ANDROID__)
  GENERATOR3(64)
  GENERATOR3(32)
  GENERATOR3(16)
  GENERATOR3(8)
#endif
};

template <typename T>
static TRANSPORT_ALWAYS_INLINE T ntoh(T x) {
  return Endian::order == Endian::Order::LITTLE ? Endian::little(x) : x;
}

template <typename T>
static TRANSPORT_ALWAYS_INLINE T hton(T x) {
  return Endian::order == Endian::Order::LITTLE ? Endian::big(x) : x;
}

}  // namespace utils