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

#include <hicn/transport/auth/crypto_hash.h>

using namespace std;

namespace transport {
namespace auth {

CryptoHash::CryptoHash() : CryptoHash(CryptoHashType::UNKNOWN) {}

CryptoHash::CryptoHash(const CryptoHash &other)
    : digest_type_(other.digest_type_),
      digest_(other.digest_),
      digest_size_(other.digest_size_) {}

CryptoHash::CryptoHash(CryptoHash &&other)
    : digest_type_(move(other.digest_type_)),
      digest_(other.digest_),
      digest_size_(other.digest_size_) {
  other.reset();
}

CryptoHash::CryptoHash(CryptoHashType hash_type) { setType(hash_type); }

CryptoHash::CryptoHash(const uint8_t *hash, size_t size,
                       CryptoHashType hash_type)
    : digest_type_(hash_type), digest_size_(size) {
  digest_.resize(size);
  memcpy(digest_.data(), hash, size);
}

CryptoHash::CryptoHash(const vector<uint8_t> &hash, CryptoHashType hash_type)
    : CryptoHash(hash.data(), hash.size(), hash_type) {}

CryptoHash &CryptoHash::operator=(const CryptoHash &other) {
  digest_type_ = other.digest_type_;
  digest_ = other.digest_;
  digest_size_ = other.digest_size_;
  return *this;
}

bool CryptoHash::operator==(const CryptoHash &other) const {
  return (digest_type_ == other.digest_type_ && digest_ == other.digest_);
}

void CryptoHash::computeDigest(const uint8_t *buffer, size_t len) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(digest_type_);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  EVP_Digest(buffer, len, digest_.data(), (unsigned int *)&digest_size_,
             (*hash_evp)(), nullptr);
}

void CryptoHash::computeDigest(const vector<uint8_t> &buffer) {
  computeDigest(buffer.data(), buffer.size());
}

void CryptoHash::computeDigest(const utils::MemBuf *buffer) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(digest_type_);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  EVP_MD_CTX *mcdtx = EVP_MD_CTX_new();
  const utils::MemBuf *p = buffer;

  if (EVP_DigestInit_ex(mcdtx, (*hash_evp)(), nullptr) == 0) {
    throw errors::RuntimeException("Digest initialization failed");
  }

  do {
    if (EVP_DigestUpdate(mcdtx, p->data(), p->length()) != 1) {
      throw errors::RuntimeException("Digest update failed");
    }

    p = p->next();
  } while (p != buffer);

  if (EVP_DigestFinal_ex(mcdtx, digest_.data(),
                         (unsigned int *)&digest_size_) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  EVP_MD_CTX_free(mcdtx);
}

vector<uint8_t> CryptoHash::getDigest() const { return digest_; }

string CryptoHash::getStringDigest() const {
  stringstream string_digest;

  string_digest << hex << setfill('0');

  for (auto byte : digest_) {
    string_digest << hex << setw(2) << static_cast<int>(byte);
  }

  return string_digest.str();
}

CryptoHashType CryptoHash::getType() const { return digest_type_; }

size_t CryptoHash::getSize() const { return digest_size_; }

void CryptoHash::setType(CryptoHashType hash_type) {
  reset();
  digest_type_ = hash_type;
  digest_size_ = CryptoHash::getSize(hash_type);
  digest_.resize(digest_size_);
}

void CryptoHash::display() {
  switch (digest_type_) {
    case CryptoHashType::SHA256:
      cout << "SHA256";
      break;
    case CryptoHashType::SHA512:
      cout << "SHA512";
      break;
    case CryptoHashType::BLAKE2S256:
      cout << "BLAKE2s256";
      break;
    case CryptoHashType::BLAKE2B512:
      cout << "BLAKE2b512";
      break;
    default:
      cout << "UNKNOWN";
      break;
  }

  cout << ": " << getStringDigest() << endl;
}

void CryptoHash::reset() {
  digest_type_ = CryptoHashType::UNKNOWN;
  digest_.clear();
  digest_size_ = 0;
}

CryptoHashEVP CryptoHash::getEVP(CryptoHashType hash_type) {
  switch (hash_type) {
    case CryptoHashType::SHA256:
      return &EVP_sha256;
      break;
    case CryptoHashType::SHA512:
      return &EVP_sha512;
      break;
    case CryptoHashType::BLAKE2S256:
      return &EVP_blake2s256;
      break;
    case CryptoHashType::BLAKE2B512:
      return &EVP_blake2b512;
      break;
    default:
      return nullptr;
      break;
  }
}

size_t CryptoHash::getSize(CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    return 0;
  }

  return EVP_MD_size((*hash_evp)());
}

bool CryptoHash::compareDigest(const uint8_t *digest1, const uint8_t *digest2,
                               CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    return false;
  }

  return !static_cast<bool>(
      memcmp(digest1, digest2, CryptoHash::getSize(hash_type)));
}

}  // namespace auth
}  // namespace transport
