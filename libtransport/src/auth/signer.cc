/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

#include <hicn/transport/auth/signer.h>

using namespace std;

namespace transport {
namespace auth {

// ---------------------------------------------------------
// Base Signer
// ---------------------------------------------------------
Signer::Signer()
    : suite_(CryptoSuite::UNKNOWN), signature_len_(0), key_(nullptr) {}

void Signer::signPacket(PacketPtr packet) {
  assert(key_ != nullptr);
  core::Packet::Format format = packet->getFormat();

  if (!packet->authenticationHeader()) {
    throw errors::MalformedAHPacketException();
  }

  // Set signature size
  size_t signature_field_len = getSignatureFieldSize();
  packet->setSignatureSize(signature_field_len);
  packet->setSignatureSizeGap(0u);

  // Copy IP+TCP / ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, packet->packet_start_, &header_copy, false);

  // Fill in the hICN AH header
  auto now = chrono::duration_cast<chrono::milliseconds>(
                 chrono::system_clock::now().time_since_epoch())
                 .count();
  packet->setSignatureTimestamp(now);
  packet->setValidationAlgorithm(suite_);

  // Set key ID
  vector<uint8_t> key_id = key_id_.getDigest();
  packet->setKeyId({key_id.data(), key_id.size()});

  // Reset fields to compute the packet hash
  packet->resetForHash();

  // Compute the signature and put it in the packet
  signBuffer(packet);
  hicn_packet_copy_header(format, &header_copy, packet->packet_start_, false);

  // Set the gap between the signature field size and the signature real size.
  packet->setSignatureSizeGap(signature_field_len - signature_len_);
  memcpy(packet->getSignature(), signature_.data(), signature_len_);
}

void Signer::signBuffer(const std::vector<uint8_t> &buffer) {
  assert(key_ != nullptr);
  CryptoHashEVP hash_evp = CryptoHash::getEVP(getHashType());

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

  if (mdctx == nullptr) {
    throw errors::RuntimeException("Digest context allocation failed");
  }

  if (EVP_DigestSignInit(mdctx.get(), nullptr, (*hash_evp)(), nullptr,
                         key_.get()) != 1) {
    throw errors::RuntimeException("Digest initialization failed");
  }

  if (EVP_DigestSignUpdate(mdctx.get(), buffer.data(), buffer.size()) != 1) {
    throw errors::RuntimeException("Digest update failed");
  }

  if (EVP_DigestSignFinal(mdctx.get(), nullptr, &signature_len_) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  signature_.resize(signature_len_);

  if (EVP_DigestSignFinal(mdctx.get(), signature_.data(), &signature_len_) !=
      1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  signature_.resize(signature_len_);
}

void Signer::signBuffer(const utils::MemBuf *buffer) {
  assert(key_ != nullptr);
  CryptoHashEVP hash_evp = CryptoHash::getEVP(getHashType());

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

  if (mdctx == nullptr) {
    throw errors::RuntimeException("Digest context allocation failed");
  }

  if (EVP_DigestSignInit(mdctx.get(), nullptr, (*hash_evp)(), nullptr,
                         key_.get()) != 1) {
    throw errors::RuntimeException("Digest initialization failed");
  }

  do {
    if (EVP_DigestSignUpdate(mdctx.get(), p->data(), p->length()) != 1) {
      throw errors::RuntimeException("Digest update failed");
    }

    p = p->next();
  } while (p != buffer);

  if (EVP_DigestSignFinal(mdctx.get(), nullptr, &signature_len_) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  signature_.resize(signature_len_);

  if (EVP_DigestSignFinal(mdctx.get(), signature_.data(), &signature_len_) !=
      1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  signature_.resize(signature_len_);
}

vector<uint8_t> Signer::getSignature() const { return signature_; }

size_t Signer::getSignatureSize() const { return signature_len_; }

size_t Signer::getSignatureFieldSize() const {
  if (signature_len_ % 4 == 0) {
    return signature_len_;
  }

  return (signature_len_ + 4) - (signature_len_ % 4);
}

CryptoHashType Signer::getHashType() const {
  return ::transport::auth::getHashType(suite_);
}

CryptoSuite Signer::getSuite() const { return suite_; }

// ---------------------------------------------------------
// Void Signer
// ---------------------------------------------------------
void VoidSigner::signPacket(PacketPtr packet){};

void VoidSigner::signBuffer(const std::vector<uint8_t> &buffer){};

void VoidSigner::signBuffer(const utils::MemBuf *buffer){};

// ---------------------------------------------------------
// Asymmetric Signer
// ---------------------------------------------------------
AsymmetricSigner::AsymmetricSigner(CryptoSuite suite, shared_ptr<EVP_PKEY> key,
                                   shared_ptr<EVP_PKEY> pub_key) {
  suite_ = suite;
  key_ = key;
  key_id_ = CryptoHash(getHashType());

  vector<uint8_t> pbk(i2d_PublicKey(pub_key.get(), nullptr));
  uint8_t *pbk_ptr = pbk.data();
  int len = i2d_PublicKey(pub_key.get(), &pbk_ptr);

  signature_len_ = EVP_PKEY_size(key.get());
  signature_.resize(signature_len_);
  key_id_.computeDigest(pbk_ptr, len);
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
SymmetricSigner::SymmetricSigner(CryptoSuite suite, const string &passphrase) {
  suite_ = suite;
  key_ = shared_ptr<EVP_PKEY>(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                   (const unsigned char *)passphrase.c_str(),
                                   passphrase.size()),
      EVP_PKEY_free);
  key_id_ = CryptoHash(getHashType());

  CryptoHashEVP hash_evp = CryptoHash::getEVP(getHashType());

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  signature_len_ = EVP_MD_size((*hash_evp)());
  signature_.resize(signature_len_);
  key_id_.computeDigest((uint8_t *)passphrase.c_str(), passphrase.size());
}

}  // namespace auth
}  // namespace transport
