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
#include <parc/security/parc_CryptoHasher.h>
};

namespace utils {

class CryptoHasher {
 public:
  CryptoHasher(CryptoHashType hash_type)
      : hasher_(parcCryptoHasher_Create(
            static_cast<PARCCryptoHashType>(hash_type))),
        managed_(true) {}

  CryptoHasher(PARCCryptoHasher* hasher) : hasher_(hasher), managed_(false) {}

  ~CryptoHasher() {
    if (managed_) {
      parcCryptoHasher_Release(&hasher_);
    }
  }

  CryptoHasher& init() {
    if (parcCryptoHasher_Init(hasher_) == -1) {
      throw errors::RuntimeException("Cryptohash init failed.");
    }

    return *this;
  }

  template <typename T>
  CryptoHasher& updateBytes(const T* buffer, std::size_t length) {
    if (parcCryptoHasher_UpdateBytes(hasher_, buffer, length) == -1) {
      throw errors::RuntimeException("Cryptohash updateBytes failed.");
    }
    return *this;
  }

  CryptoHash finalize() {
    CryptoHash hash;
    hash.hash_ = parcCryptoHasher_Finalize(hasher_);
    return hash;
  }

 private:
  PARCCryptoHasher* hasher_;
  bool managed_;
};

}  // namespace utils