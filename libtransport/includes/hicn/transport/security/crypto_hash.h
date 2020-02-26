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

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/security/crypto_hash_type.h>
#include <hicn/transport/utils/array.h>

extern "C" {
#include <parc/security/parc_CryptoHash.h>
};

#include <cstring>
#include <unordered_map>

namespace utils {

class CryptoHasher;

struct EnumClassHash {
  template <typename T>
  std::size_t operator()(T t) const {
    return static_cast<std::size_t>(t);
  }
};

static std::unordered_map<CryptoHashType, std::size_t, EnumClassHash>
    hash_size_map = {{CryptoHashType::SHA_256, 32},
                     {CryptoHashType::CRC32C, 4},
                     {CryptoHashType::SHA_512, 64}};

class Signer;
class Verifier;

class CryptoHash {
  friend class CryptoHasher;
  friend class Signer;
  friend class Verifier;

 public:
  CryptoHash() : hash_(nullptr) {}

  CryptoHash(const CryptoHash& other) {
    if (other.hash_) {
      hash_ = parcCryptoHash_Acquire(other.hash_);
    }
  }

  CryptoHash(CryptoHash&& other) {
    if (other.hash_) {
      hash_ = parcCryptoHash_Acquire(other.hash_);
    }
  }

  template <typename T>
  CryptoHash(const T* buffer, std::size_t length, CryptoHashType hash_type) {
    hash_ = parcCryptoHash_CreateFromArray(
        static_cast<PARCCryptoHashType>(hash_type), buffer, length);
  }

  ~CryptoHash() {
    if (hash_) {
      parcCryptoHash_Release(&hash_);
    }
  }

  CryptoHash& operator=(const CryptoHash& other) {
    if (other.hash_) {
      hash_ = parcCryptoHash_Acquire(other.hash_);
    }

    return *this;
  }

  template <typename T>
  utils::Array<T> getDigest() const {
    return utils::Array<T>(
        static_cast<T*>(parcBuffer_Overlay(parcCryptoHash_GetDigest(hash_), 0)),
        parcBuffer_Remaining(parcCryptoHash_GetDigest(hash_)));
  }

  CryptoHashType getType() {
    return static_cast<CryptoHashType>(parcCryptoHash_GetDigestType(hash_));
  }

  template <typename T>
  static bool compareBinaryDigest(const T* digest1, const T* digest2,
                                  CryptoHashType hash_type) {
    if (hash_size_map.find(hash_type) == hash_size_map.end()) {
      return false;
    }

    return !static_cast<bool>(
        std::memcmp(digest1, digest2, hash_size_map[hash_type]));
  }

  TRANSPORT_ALWAYS_INLINE void display() {
    parcBuffer_Display(parcCryptoHash_GetDigest(hash_), 2);
  }

 private:
  PARCCryptoHash* hash_;
};

}  // namespace utils