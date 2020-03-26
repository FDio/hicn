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

#include <hicn/transport/security/crypto_hash.h>

extern "C" {
#include <blake3/blake3.h>
#include <parc/security/parc_CryptoHasher.h>
};

namespace utils {

class CryptoHasher {
 public:
  CryptoHasher(CryptoHashType hash_type) : managed_(true) {
    crypto_hasher_.type = hash_type;

    if (hash_type != CryptoHashType::BLAKE3) {
      crypto_hasher_.parc =
          parcCryptoHasher_Create(static_cast<PARCCryptoHashType>(hash_type));
    }
  }

  CryptoHasher(PARCCryptoHasher* parc_hasher) : managed_(false) {
    crypto_hasher_.type = CryptoHashType::NULL_HASH;
    crypto_hasher_.parc = parc_hasher;
  }

  ~CryptoHasher() {
    if (crypto_hasher_.type != CryptoHashType::BLAKE3) {
      if (managed_) {
        parcCryptoHasher_Release(&crypto_hasher_.parc);
      }
    }
  }

  CryptoHasher& init() {
    if (crypto_hasher_.type == CryptoHashType::BLAKE3) {
      blake3_hasher_init(&crypto_hasher_.blake3);
    } else {
      if (parcCryptoHasher_Init(crypto_hasher_.parc) == -1) {
        throw errors::RuntimeException("Cryptohash init failed.");
      }
    }

    return *this;
  }

  template <typename T>
  CryptoHasher& updateBytes(const T* buffer, std::size_t length) {
    if (crypto_hasher_.type == CryptoHashType::BLAKE3) {
      blake3_hasher_update(&crypto_hasher_.blake3, buffer, length);
    } else {
      if (parcCryptoHasher_UpdateBytes(crypto_hasher_.parc, buffer, length) ==
          -1) {
        throw errors::RuntimeException("Cryptohash updateBytes failed.");
      }
    }
    return *this;
  }

  CryptoHash finalize() {
    CryptoHash crypto_hash;

    crypto_hash.crypto_hash_.type = crypto_hasher_.type;

    if (crypto_hasher_.type == CryptoHashType::BLAKE3) {
      blake3_hasher_finalize(&crypto_hasher_.blake3,
                             crypto_hash.crypto_hash_.blake3, BLAKE3_OUT_LEN);
    } else {
      crypto_hash.crypto_hash_.parc =
          parcCryptoHasher_Finalize(crypto_hasher_.parc);
    }

    return crypto_hash;
  }

 private:
  typedef struct {
    CryptoHashType type;
    union {
      PARCCryptoHasher* parc;
      blake3_hasher blake3;
    };
  } crypto_hasher_t;

  bool managed_;
  crypto_hasher_t crypto_hasher_;
};

}  // namespace utils
