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
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/utils/chrono_typedefs.h>

#include "hicn/transport/core/global_object_pool.h"

namespace transport {
namespace auth {

// ---------------------------------------------------------
// Base Signer
// ---------------------------------------------------------
Signer::Signer()
    : suite_(CryptoSuite::UNKNOWN),
      signature_(core::PacketManager<>::getInstance().getMemBuf()),
      signature_len_(0),
      key_(nullptr) {}

Signer::~Signer() {}

void Signer::signPacket(PacketPtr packet) {
  DCHECK(key_ != nullptr);
  if (!packet->hasAH()) {
    throw errors::MalformedAHPacketException();
  }

  // Set signature size
  size_t signature_field_len = getSignatureFieldSize();
  packet->setSignatureFieldSize(signature_field_len);
  packet->updateLength();  // update IP payload length

  // Copy IP+TCP / ICMP header before zeroing them
  u8 header_copy[HICN_HDRLEN_MAX];
  size_t header_len;
  packet->saveHeader(header_copy, &header_len);

  // Copy bitmap from interest manifest
  uint32_t request_bitmap[BITMAP_SIZE] = {0};
  if (packet->isInterest()) {
    core::Interest *interest = dynamic_cast<core::Interest *>(packet);
    if (interest->hasManifest())
      memcpy(request_bitmap, interest->getRequestBitmap(),
             BITMAP_SIZE * sizeof(uint32_t));
  }

  // Fill in the hICN AH header
  auto now = utils::SteadyTime::nowMs().count();
  packet->setSignatureTimestamp(now);
  packet->setValidationAlgorithm(suite_);

  // Set key ID
  const utils::MemBuf::Ptr &key_id = key_id_.getDigest();
  packet->setKeyId({key_id->writableData(), key_id->length()});

  // Reset fields to compute the packet hash
  packet->resetForHash();

  // Compute the signature and put it in the packet
  signBuffer(packet);
  packet->setSignature(signature_);
  packet->setSignatureSize(signature_len_);

  // Restore header
  packet->loadHeader(header_copy, header_len);

  // Restore bitmap in interest manifest
  if (packet->isInterest()) {
    core::Interest *interest = dynamic_cast<core::Interest *>(packet);
    interest->setRequestBitmap(request_bitmap);
  }
}

void Signer::signBuffer(const uint8_t *buffer, std::size_t len) {
  const EVP_MD *hash_md = getMD(suite_);

  std::shared_ptr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (md_ctx == nullptr) {
    throw errors::RuntimeException("Signature context allocation failed");
  }

  if (EVP_DigestSignInit(md_ctx.get(), nullptr, hash_md, nullptr, key_.get()) !=
      1) {
    throw errors::RuntimeException("Signature initialization failed");
  }

  if (EVP_DigestSign(md_ctx.get(), nullptr, &signature_len_, buffer, len) !=
      1) {
    throw errors::RuntimeException("Signature length computation failed");
  };

  DCHECK(signature_len_ <= signature_->tailroom());
  signature_->setLength(signature_len_);

  if (EVP_DigestSign(md_ctx.get(), signature_->writableData(), &signature_len_,
                     buffer, len) != 1) {
    throw errors::RuntimeException("Signature computation failed");
  };

  DCHECK(signature_len_ <= signature_->tailroom());
  signature_->setLength(signature_len_);
}

void Signer::signBuffer(const std::vector<uint8_t> &buffer) {
  signBuffer(buffer.data(), buffer.size());
}

void Signer::signBuffer(const utils::MemBuf *buffer) {
  if (buffer->isChained()) {
    throw errors::RuntimeException(
        "Signature of chained membuf is not supported.");
  }

  signBuffer(buffer->data(), buffer->length());
}

const utils::MemBuf::Ptr &Signer::getSignature() const { return signature_; }

std::string Signer::getStringSignature() const {
  std::stringstream string_sig;
  string_sig << std::hex << std::setfill('0');

  for (size_t i = 0; i < signature_len_; ++i) {
    string_sig << std::hex << std::setw(2)
               << static_cast<int>(signature_->data()[i]);
  }

  return string_sig.str();
}

size_t Signer::getSignatureSize() const { return signature_len_; }

size_t Signer::getSignatureFieldSize() const {
  if (signature_len_ % 4 == 0) {
    return signature_len_;
  }

  return (signature_len_ + 4) - (signature_len_ % 4);
}

CryptoSuite Signer::getSuite() const { return suite_; }

CryptoHashType Signer::getHashType() const {
  return ::transport::auth::getHashType(suite_);
}

void Signer::display() {
  LOG(INFO) << getStringSuite(suite_) << ": " << getStringSignature();
}

// ---------------------------------------------------------
// Void Signer
// ---------------------------------------------------------
void VoidSigner::signPacket(PacketPtr packet) {}

void VoidSigner::signBuffer(const uint8_t *buffer, std::size_t len) {}

void VoidSigner::signBuffer(const std::vector<uint8_t> &buffer) {}

void VoidSigner::signBuffer(const utils::MemBuf *buffer) {}

// ---------------------------------------------------------
// Asymmetric Signer
// ---------------------------------------------------------
AsymmetricSigner::AsymmetricSigner(CryptoSuite suite,
                                   std::shared_ptr<EVP_PKEY> key,
                                   std::shared_ptr<EVP_PKEY> pub_key)
    : Signer() {
  setKey(suite, key, pub_key);
}

AsymmetricSigner::AsymmetricSigner(std::string keystore_path,
                                   std::string password)
    : Signer() {
  FILE *p12file = fopen(keystore_path.c_str(), "r");

  if (p12file == nullptr) {
    throw errors::RuntimeException("failed to read keystore");
  }

  std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
      d2i_PKCS12_fp(p12file, nullptr), &PKCS12_free);
  X509 *cert_raw;
  EVP_PKEY *key_raw;

  if (PKCS12_parse(p12.get(), password.c_str(), &key_raw, &cert_raw, nullptr) !=
      1) {
    fclose(p12file);
    throw errors::RuntimeException("failed to parse keystore");
  }

  std::shared_ptr<EVP_PKEY> key(key_raw, EVP_PKEY_free);
  std::shared_ptr<EVP_PKEY> pub_key(X509_get_pubkey(cert_raw), EVP_PKEY_free);

  setKey(transport::auth::getSuite(X509_get_signature_nid(cert_raw)), key,
         pub_key);

  fclose(p12file);
}

void AsymmetricSigner::setKey(CryptoSuite suite, std::shared_ptr<EVP_PKEY> key,
                              std::shared_ptr<EVP_PKEY> pub_key) {
  suite_ = suite;
  key_ = key;

  signature_len_ = EVP_PKEY_size(key_.get());
  DCHECK(signature_len_ <= signature_->tailroom());
  signature_->setLength(signature_len_);

  // Key ID is not supported yet.
  uint8_t id[8] = {0};
  key_id_ = CryptoHash(getHashType());
  key_id_.computeDigest(id, 8);
}

size_t AsymmetricSigner::getSignatureFieldSize() const {
  size_t field_size = EVP_PKEY_size(key_.get());

  if (field_size % 4 == 0) {
    return field_size;
  }

  return (field_size + 4) - (field_size % 4);
}

// ---------------------------------------------------------
// Symmetric Signer
// ---------------------------------------------------------
SymmetricSigner::SymmetricSigner(CryptoSuite suite,
                                 const std::string &passphrase)
    : Signer() {
  suite_ = suite;
  key_ = std::shared_ptr<EVP_PKEY>(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                   (const unsigned char *)passphrase.c_str(),
                                   passphrase.size()),
      EVP_PKEY_free);

  const EVP_MD *hash_md = getMD(suite_);
  if (hash_md == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  signature_len_ = EVP_MD_size(hash_md);
  DCHECK(signature_len_ <= signature_->tailroom());
  signature_->setLength(signature_len_);

  // Key ID is not supported yet.
  uint8_t id[8] = {0};
  key_id_ = CryptoHash(getHashType());
  key_id_.computeDigest(id, 8);
}

}  // namespace auth
}  // namespace transport
