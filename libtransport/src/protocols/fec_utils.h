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

#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <protocols/fec/rs.h>

#if ENABLE_RELY
#include <protocols/fec/rely.h>
#endif

#include <functional>

namespace transport {
namespace protocol {

namespace fec {

#if ENABLE_RELY
#define foreach_fec_type foreach_rs_fec_type foreach_rely_fec_type
#else
#define foreach_fec_type foreach_rs_fec_type
#endif

#define ENUM_FROM_MACRO(name, k, n) name##_K##k##_N##n
#define ENUM_FROM_MACRO_STR(name, k, n) #name "_K" #k "_N" #n

enum class FECType : uint8_t {
#define _(name, k, n) ENUM_FROM_MACRO(name, k, n),
  foreach_fec_type
#undef _
      UNKNOWN
};

#define ENUM_FROM_MACRO2(name, k, n) FECType::ENUM_FROM_MACRO(name, k, n)

class FECUtils {
 public:
  static FECType fecTypeFromString(const char *fec_type) {
#define _(name, k, n)                                            \
  do {                                                           \
    if (strncmp(fec_type, ENUM_FROM_MACRO_STR(name, k, n),       \
                strlen(ENUM_FROM_MACRO_STR(name, k, n))) == 0) { \
      return ENUM_FROM_MACRO2(name, k, n);                       \
    }                                                            \
  } while (0);
    foreach_fec_type
#undef _

        return FECType::UNKNOWN;
  }

  static bool isFec(FECType fec_type, uint32_t index, uint32_t seq_offset = 0) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return FecInfo<Code<k, n>>::isFec(index - (seq_offset % n));

      foreach_fec_type
#undef _
          default : return false;
    }
  }

  static uint32_t nextSource(FECType fec_type, uint32_t index,
                             uint32_t seq_offset = 0) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return FecInfo<Code<k, n>>::nextSource(index) + (seq_offset % n);

      foreach_fec_type
#undef _
          default : throw std::runtime_error("Unknown fec type");
    }
  }

  static uint32_t getSourceSymbols(FECType fec_type) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return k;
      foreach_fec_type
#undef _
          default : throw std::runtime_error("Unknown fec type");
    }
  }

  static uint32_t getBlockSymbols(FECType fec_type) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return n;
      foreach_fec_type
#undef _
          default : throw std::runtime_error("Unknown fec type");
    }
  }

  static std::unique_ptr<ProducerFEC> getEncoder(FECType fec_type,
                                                 uint32_t seq_offset = 0) {
    return factoryEncoder(fec_type, seq_offset);
  }

  static std::unique_ptr<ConsumerFEC> getDecoder(FECType fec_type,
                                                 uint32_t seq_offset = 0) {
    return factoryDencoder(fec_type, seq_offset);
  }

 private:
  static std::unique_ptr<ProducerFEC> factoryEncoder(FECType fec_type,
                                                     uint32_t seq_offset) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return std::make_unique<name##Encoder>(k, n, seq_offset);

      foreach_fec_type
#undef _
          default : throw std::runtime_error("Unknown fec type");
    }
  }

  static std::unique_ptr<ConsumerFEC> factoryDencoder(FECType fec_type,
                                                      uint32_t seq_offset) {
    switch (fec_type) {
#define _(name, k, n)                \
  case ENUM_FROM_MACRO2(name, k, n): \
    return std::make_unique<name##Decoder>(k, n, seq_offset);

      foreach_fec_type
#undef _
          default : throw std::runtime_error("Unknown fec type");
    }
  }
};  // namespace fec

}  // namespace fec
}  // namespace protocol
}  // namespace transport
