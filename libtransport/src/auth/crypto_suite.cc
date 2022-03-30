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

#include <hicn/transport/auth/crypto_suite.h>

namespace transport {
namespace auth {

CryptoSuite getSuite(int nid) {
  switch (nid) {
    case NID_ecdsa_with_SHA256:
      return CryptoSuite::ECDSA_SHA256;
    case NID_ecdsa_with_SHA512:
      return CryptoSuite::ECDSA_SHA512;
    case NID_sha256WithRSAEncryption:
      return CryptoSuite::RSA_SHA256;
    case NID_sha512WithRSAEncryption:
      return CryptoSuite::RSA_SHA512;
    case NID_hmacWithSHA256:
      return CryptoSuite::HMAC_SHA256;
    case NID_hmacWithSHA512:
      return CryptoSuite::HMAC_SHA512;
    case NID_dsa_with_SHA256:
      return CryptoSuite::DSA_SHA256;
    case NID_dsa_with_SHA512:
      return CryptoSuite::DSA_SHA512;
    default:
      return CryptoSuite::UNKNOWN;
  }
}

std::string getStringSuite(CryptoSuite suite) {
  switch (suite) {
    case CryptoSuite::ECDSA_BLAKE2B512:
      return "ECDSA_BLAKE2B512";
    case CryptoSuite::ECDSA_BLAKE2S256:
      return "ECDSA_BLAKE2S256";
    case CryptoSuite::ECDSA_SHA256:
      return "ECDSA_SHA256";
    case CryptoSuite::ECDSA_SHA512:
      return "ECDSA_SHA512";
    case CryptoSuite::RSA_BLAKE2B512:
      return "RSA_BLAKE2B512";
    case CryptoSuite::RSA_BLAKE2S256:
      return "RSA_BLAKE2S256";
    case CryptoSuite::RSA_SHA256:
      return "RSA_SHA256";
    case CryptoSuite::RSA_SHA512:
      return "RSA_SHA512";
    case CryptoSuite::HMAC_BLAKE2B512:
      return "HMAC_BLAKE2B512";
    case CryptoSuite::HMAC_BLAKE2S256:
      return "HMAC_BLAKE2S256";
    case CryptoSuite::HMAC_SHA256:
      return "HMAC_SHA256";
    case CryptoSuite::HMAC_SHA512:
      return "HMAC_SHA512";
    case CryptoSuite::DSA_BLAKE2B512:
      return "DSA_BLAKE2B512";
    case CryptoSuite::DSA_BLAKE2S256:
      return "DSA_BLAKE2S256";
    case CryptoSuite::DSA_SHA256:
      return "DSA_SHA256";
    case CryptoSuite::DSA_SHA512:
      return "DSA_SHA512";
    default:
      return "UNKNOWN";
  }
}

CryptoHashType getHashType(CryptoSuite suite) {
  switch (suite) {
    case CryptoSuite::ECDSA_BLAKE2B512:
    case CryptoSuite::RSA_BLAKE2B512:
    case CryptoSuite::HMAC_BLAKE2B512:
    case CryptoSuite::DSA_BLAKE2B512:
      return CryptoHashType::BLAKE2B512;
    case CryptoSuite::ECDSA_BLAKE2S256:
    case CryptoSuite::RSA_BLAKE2S256:
    case CryptoSuite::HMAC_BLAKE2S256:
    case CryptoSuite::DSA_BLAKE2S256:
      return CryptoHashType::BLAKE2S256;
    case CryptoSuite::ECDSA_SHA256:
    case CryptoSuite::RSA_SHA256:
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::DSA_SHA256:
      return CryptoHashType::SHA256;
    case CryptoSuite::ECDSA_SHA512:
    case CryptoSuite::RSA_SHA512:
    case CryptoSuite::HMAC_SHA512:
    case CryptoSuite::DSA_SHA512:
      return CryptoHashType::SHA512;
    default:
      return CryptoHashType::UNKNOWN;
  }
}

}  // namespace auth
}  // namespace transport
