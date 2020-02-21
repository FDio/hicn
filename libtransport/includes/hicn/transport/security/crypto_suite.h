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

extern "C" {
#include <parc/security/parc_CryptoSuite.h>
};

#include <cstdint>

namespace utils {

enum class CryptoSuite : uint8_t {
  RSA_SHA256 = PARCCryptoSuite_RSA_SHA256,
  DSA_SHA256 = PARCCryptoSuite_DSA_SHA256,
  RSA_SHA512 = PARCCryptoSuite_RSA_SHA512,
  HMAC_SHA256 = PARCCryptoSuite_HMAC_SHA256,
  HMAC_SHA512 = PARCCryptoSuite_HMAC_SHA512,
  NULL_CRC32C = PARCCryptoSuite_NULL_CRC32C,
  ECDSA_256K1 = PARCCryptoSuite_ECDSA_SHA256,
  UNKNOWN = PARCCryptoSuite_UNKNOWN
};
}
