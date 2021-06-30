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

#include <hicn/transport/auth/crypto_hash.h>

extern "C" {
#include <openssl/obj_mac.h>
}

namespace transport {
namespace auth {

enum class CryptoSuite : uint8_t {
  UNKNOWN,
  ECDSA_BLAKE2B512,
  ECDSA_BLAKE2S256,
  ECDSA_SHA256,
  ECDSA_SHA512,
  RSA_BLAKE2B512,
  RSA_BLAKE2S256,
  RSA_SHA256,
  RSA_SHA512,
  HMAC_BLAKE2B512,
  HMAC_BLAKE2S256,
  HMAC_SHA256,
  HMAC_SHA512,
  DSA_BLAKE2B512,
  DSA_BLAKE2S256,
  DSA_SHA256,
  DSA_SHA512,
};

// Return the suite associated to the given NID
CryptoSuite getSuite(int nid);

// Return the hash type associated to the given suite
CryptoHashType getHashType(CryptoSuite suite);

}  // namespace auth
}  // namespace transport
