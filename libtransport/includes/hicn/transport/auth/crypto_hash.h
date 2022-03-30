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

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/utils/membuf.h>

#include <iomanip>

extern "C" {
#include <openssl/evp.h>
}

namespace transport {
namespace auth {

typedef const EVP_MD *(*CryptoHashEVP)(void);

enum class CryptoHashType : uint8_t {
  UNKNOWN,
  SHA256,
  SHA512,
  BLAKE2B512,
  BLAKE2S256,
};

class CryptoHash {
 public:
  // Constructors
  CryptoHash();
  CryptoHash(const CryptoHash &other);
  CryptoHash(CryptoHash &&other);
  CryptoHash(CryptoHashType hash_type);
  CryptoHash(const uint8_t *hash, std::size_t size, CryptoHashType hash_type);
  CryptoHash(const std::vector<uint8_t> &hash, CryptoHashType hash_type);

  // Destructor
  ~CryptoHash() = default;

  // Operators
  CryptoHash &operator=(const CryptoHash &other);
  bool operator==(const CryptoHash &other) const;

  // Compute the hash of given buffer
  void computeDigest(const uint8_t *buffer, std::size_t len);
  void computeDigest(const std::vector<uint8_t> &buffer);

  // Compute the hash of given membuf
  void computeDigest(const utils::MemBuf *buffer);

  // Return the computed hash
  std::vector<uint8_t> getDigest() const;

  // Return the computed hash as a string
  std::string getStringDigest() const;

  // Return hash type
  CryptoHashType getType() const;

  // Return hash size
  std::size_t getSize() const;

  // Change hash type
  void setType(CryptoHashType hash_type);

  // Print hash to stdout
  void display();

  // Reset hash
  void reset();

  // Return OpenSSL EVP function associated to a given hash type
  static CryptoHashEVP getEVP(CryptoHashType hash_type);

  // Return hash size
  static std::size_t getSize(CryptoHashType hash_type);

  // Compare two raw buffers
  static bool compareDigest(const uint8_t *digest1, const uint8_t *digest2,
                            CryptoHashType hash_type);

 private:
  CryptoHashType digest_type_;
  std::vector<uint8_t> digest_;
  std::size_t digest_size_;
};

}  // namespace auth
}  // namespace transport
