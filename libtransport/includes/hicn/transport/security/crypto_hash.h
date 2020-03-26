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
#include <blake3/blake3.h>
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
                     {CryptoHashType::SHA_512, 64},
                     {CryptoHashType::BLAKE3, BLAKE3_OUT_LEN}};

class Signer;
class Verifier;

class CryptoHash {
  friend class CryptoHasher;
  friend class Signer;
  friend class Verifier;

 public:
  CryptoHash() { crypto_hash_.type = CryptoHashType::NULL_HASH; }

  CryptoHash(const CryptoHash& other) {
    crypto_hash_.type = other.crypto_hash_.type;

    if (crypto_hash_.type == CryptoHashType::BLAKE3) {
      memcpy(crypto_hash_.blake3, other.crypto_hash_.blake3, BLAKE3_OUT_LEN);
    } else {
      crypto_hash_.parc = parcCryptoHash_Acquire(other.crypto_hash_.parc);
    }
  }

  CryptoHash(CryptoHash&& other) {
    crypto_hash_.type = other.crypto_hash_.type;

    if (crypto_hash_.type == CryptoHashType::BLAKE3) {
      memcpy(crypto_hash_.blake3, other.crypto_hash_.blake3, BLAKE3_OUT_LEN);
    } else {
      crypto_hash_.parc = parcCryptoHash_Acquire(other.crypto_hash_.parc);
    }
  }

  template <typename T>
  CryptoHash(const T* buffer, std::size_t length, CryptoHashType hash_type) {
    crypto_hash_.type = hash_type;

    if (hash_type == CryptoHashType::BLAKE3) {
      memcpy(crypto_hash_.blake3, static_cast<uint8_t*>(buffer),
             BLAKE3_OUT_LEN);
    } else {
      crypto_hash_.parc = parcCryptoHash_CreateFromArray(
          static_cast<PARCCryptoHashType>(hash_type), buffer, length);
    }
  }

  ~CryptoHash() {
    if (crypto_hash_.type != CryptoHashType::BLAKE3) {
      if (crypto_hash_.parc) {
        parcCryptoHash_Release(&crypto_hash_.parc);
      }
    }
  }

  CryptoHash& operator=(const CryptoHash& other) {
    crypto_hash_.type = other.crypto_hash_.type;

    if (crypto_hash_.type == CryptoHashType::BLAKE3) {
      memcpy(crypto_hash_.blake3, other.crypto_hash_.blake3, BLAKE3_OUT_LEN);
    } else {
      crypto_hash_.parc = parcCryptoHash_Acquire(other.crypto_hash_.parc);
    }

    return *this;
  }

  template <typename T>
  utils::Array<T> getDigest() const {
    if (crypto_hash_.type == CryptoHashType::BLAKE3) {
      return utils::Array<T>(const_cast<T*>(crypto_hash_.blake3),
                             BLAKE3_OUT_LEN);
    } else {
      return utils::Array<T>(
          static_cast<T*>(parcBuffer_Overlay(
              parcCryptoHash_GetDigest(crypto_hash_.parc), 0)),
          parcBuffer_Remaining(parcCryptoHash_GetDigest(crypto_hash_.parc)));
    }
  }

  CryptoHashType getType() { return crypto_hash_.type; }

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
    if (crypto_hash_.type == CryptoHashType::BLAKE3) {
      for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        printf("%02x", crypto_hash_.blake3[i]);
      }
      printf("\n");
    } else {
      parcBuffer_Display(parcCryptoHash_GetDigest(crypto_hash_.parc), 0);
    }
  }

 private:
  typedef struct {
    CryptoHashType type;
    union {
      uint8_t blake3[BLAKE3_OUT_LEN];
      PARCCryptoHash* parc;
    };
  } crypto_hash_t;

  crypto_hash_t crypto_hash_;
};

}  // namespace utils
