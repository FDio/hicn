/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <glog/logging.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/core/global_object_pool.h>

namespace transport {
namespace auth {

CryptoHash::CryptoHash() : CryptoHash(CryptoHashType::UNKNOWN) {}

CryptoHash::CryptoHash(const CryptoHash &other)
    : digest_type_(other.digest_type_),
      digest_(other.digest_),
      digest_size_(other.digest_size_) {}

CryptoHash::CryptoHash(CryptoHash &&other) noexcept
    : digest_type_(std::move(other.digest_type_)),
      digest_(std::move(other.digest_)),
      digest_size_(other.digest_size_) {}

CryptoHash::CryptoHash(CryptoHashType hash_type)
    : digest_(core::PacketManager<>::getInstance().getMemBuf()) {
  setType(hash_type);
}

CryptoHash::CryptoHash(const uint8_t *hash, size_t size,
                       CryptoHashType hash_type)
    : digest_type_(hash_type), digest_size_(size) {
  digest_ = core::PacketManager<>::getInstance().getMemBuf();
  digest_->append(size);
  memcpy(digest_->writableData(), hash, size);
}

CryptoHash::CryptoHash(const std::vector<uint8_t> &hash,
                       CryptoHashType hash_type)
    : CryptoHash(hash.data(), hash.size(), hash_type) {}

CryptoHash &CryptoHash::operator=(const CryptoHash &other) {
  if (this != &other) {
    digest_type_ = other.digest_type_;
    digest_ = other.digest_;
    digest_size_ = other.digest_size_;
  }
  return *this;
}

bool CryptoHash::operator==(const CryptoHash &other) const {
  return (digest_type_ == other.digest_type_ && *digest_ == *other.digest_);
}

void CryptoHash::computeDigest(const uint8_t *buffer, size_t len) {
  const EVP_MD *hash_md = CryptoHash::getMD(digest_type_);
  if (hash_md == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  if (EVP_Digest(buffer, len, digest_->writableData(),
                 reinterpret_cast<unsigned int *>(&digest_size_), hash_md,
                 nullptr) != 1) {
    throw errors::RuntimeException("Digest computation failed.");
  };
}

void CryptoHash::computeDigest(const std::vector<uint8_t> &buffer) {
  computeDigest(buffer.data(), buffer.size());
}

void CryptoHash::computeDigest(const utils::MemBuf *buffer) {
  if (buffer->isChained()) {
    throw errors::RuntimeException(
        "Digest of chained membuf is not supported.");
  }

  computeDigest(buffer->data(), buffer->length());
}

const utils::MemBuf::Ptr &CryptoHash::getDigest() const { return digest_; }

std::string CryptoHash::getStringDigest() const {
  std::stringstream string_digest;

  string_digest << std::hex << std::setfill('0');

  for (size_t i = 0; i < digest_size_; ++i) {
    string_digest << std::hex << std::setw(2)
                  << static_cast<int>(digest_->data()[i]);
  }

  return string_digest.str();
}

CryptoHashType CryptoHash::getType() const { return digest_type_; }

size_t CryptoHash::getSize() const { return digest_size_; }

void CryptoHash::setType(CryptoHashType hash_type) {
  digest_type_ = hash_type;
  digest_size_ = CryptoHash::getSize(hash_type);
  DCHECK(digest_size_ <= digest_->tailroom());
  digest_->setLength(digest_size_);
}

void CryptoHash::display() {
  switch (digest_type_) {
    case CryptoHashType::SHA256:
      LOG(INFO) << "SHA256: " << getStringDigest();
      break;
    case CryptoHashType::SHA512:
      LOG(INFO) << "SHA512: " << getStringDigest();
      break;
    case CryptoHashType::BLAKE2S256:
      LOG(INFO) << "BLAKE2s256: " << getStringDigest();
      break;
    case CryptoHashType::BLAKE2B512:
      LOG(INFO) << "BLAKE2b512: " << getStringDigest();
      break;
    default:
      LOG(INFO) << "UNKNOWN: " << getStringDigest();
      break;
  }
}

void CryptoHash::reset() {
  digest_type_ = CryptoHashType::UNKNOWN;
  digest_size_ = 0;
  digest_->setLength(0);
}

const EVP_MD *CryptoHash::getMD(CryptoHashType hash_type) {
  switch (hash_type) {
    case CryptoHashType::SHA256:
      return EVP_sha256();
    case CryptoHashType::SHA512:
      return EVP_sha512();
    case CryptoHashType::BLAKE2S256:
      return EVP_blake2s256();
    case CryptoHashType::BLAKE2B512:
      return EVP_blake2b512();
    default:
      return nullptr;
  }
}

size_t CryptoHash::getSize(CryptoHashType hash_type) {
  const EVP_MD *hash_md = CryptoHash::getMD(hash_type);
  return hash_md == nullptr ? 0 : EVP_MD_size(hash_md);
}

bool CryptoHash::compareDigest(const uint8_t *digest1, const uint8_t *digest2,
                               CryptoHashType hash_type) {
  const EVP_MD *hash_md = CryptoHash::getMD(hash_type);
  return hash_md == nullptr
             ? false
             : !static_cast<bool>(
                   memcmp(digest1, digest2, CryptoHash::getSize(hash_type)));
}

}  // namespace auth
}  // namespace transport
