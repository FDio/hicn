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

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
}

#include <chrono>

#define ALLOW_UNALIGNED_READS 1

using namespace std;

namespace transport {
namespace auth {

Signer::Signer() : signer_(nullptr), key_id_(nullptr) { parcSecurity_Init(); }

Signer::Signer(PARCSigner *signer) : Signer() { setSigner(signer); }

Signer::~Signer() {
  if (signer_) parcSigner_Release(&signer_);
  if (key_id_) parcKeyId_Release(&key_id_);
  parcSecurity_Fini();
}

void Signer::signPacket(PacketPtr packet) {
  parcAssertNotNull(signer_, "Expected non-null signer");

  const utils::MemBuf &header_chain = *packet;
  core::Packet::Format format = packet->getFormat();
  auto suite = getCryptoSuite();
  size_t signature_len = getSignatureSize();

  if (!packet->authenticationHeader()) {
    throw errors::MalformedAHPacketException();
  }

  packet->setSignatureSize(signature_len);

  // Copy IP+TCP / ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, packet->packet_start_, &header_copy, false);
  packet->resetForHash();

  // Fill in the HICN_AH header
  auto now = chrono::duration_cast<chrono::milliseconds>(
                 chrono::system_clock::now().time_since_epoch())
                 .count();
  packet->setSignatureTimestamp(now);
  packet->setValidationAlgorithm(suite);

  // Set the key ID
  KeyId key_id;
  key_id.first = static_cast<uint8_t *>(
      parcBuffer_Overlay((PARCBuffer *)parcKeyId_GetKeyId(key_id_), 0));
  packet->setKeyId(key_id);

  // Calculate hash
  CryptoHasher hasher(parcSigner_GetCryptoHasher(signer_));
  const utils::MemBuf *current = &header_chain;

  hasher.init();

  do {
    hasher.updateBytes(current->data(), current->length());
    current = current->next();
  } while (current != &header_chain);

  CryptoHash hash = hasher.finalize();

  // Compute signature
  PARCSignature *signature = parcSigner_SignDigestNoAlloc(
      signer_, hash.hash_, packet->getSignature(), (uint32_t)signature_len);
  PARCBuffer *buffer = parcSignature_GetSignature(signature);
  size_t bytes_len = parcBuffer_Remaining(buffer);

  if (bytes_len > signature_len) {
    throw errors::MalformedAHPacketException();
  }

  // Put signature in AH header
  hicn_packet_copy_header(format, &header_copy, packet->packet_start_, false);

  // Release allocated objects
  parcSignature_Release(&signature);
}

void Signer::setSigner(PARCSigner *signer) {
  parcAssertNotNull(signer, "Expected non-null signer");

  if (signer_) parcSigner_Release(&signer_);
  if (key_id_) parcKeyId_Release(&key_id_);

  signer_ = parcSigner_Acquire(signer);
  key_id_ = parcSigner_CreateKeyId(signer_);
}

size_t Signer::getSignatureSize() const {
  parcAssertNotNull(signer_, "Expected non-null signer");
  return parcSigner_GetSignatureSize(signer_);
}

CryptoSuite Signer::getCryptoSuite() const {
  parcAssertNotNull(signer_, "Expected non-null signer");
  return static_cast<CryptoSuite>(parcSigner_GetCryptoSuite(signer_));
}

CryptoHashType Signer::getCryptoHashType() const {
  parcAssertNotNull(signer_, "Expected non-null signer");
  return static_cast<CryptoHashType>(parcSigner_GetCryptoHashType(signer_));
}

PARCSigner *Signer::getParcSigner() const { return signer_; }

PARCKeyStore *Signer::getParcKeyStore() const {
  parcAssertNotNull(signer_, "Expected non-null signer");
  return parcSigner_GetKeyStore(signer_);
}

AsymmetricSigner::AsymmetricSigner(CryptoSuite suite, PARCKeyStore *key_store) {
  parcAssertNotNull(key_store, "Expected non-null key_store");

  auto crypto_suite = static_cast<PARCCryptoSuite>(suite);

  switch (suite) {
    case CryptoSuite::DSA_SHA256:
    case CryptoSuite::RSA_SHA256:
    case CryptoSuite::RSA_SHA512:
    case CryptoSuite::ECDSA_256K1:
      break;
    default:
      throw errors::RuntimeException(
          "Invalid crypto suite for asymmetric signer");
  }

  setSigner(
      parcSigner_Create(parcPublicKeySigner_Create(key_store, crypto_suite),
                        PARCPublicKeySignerAsSigner));
}

SymmetricSigner::SymmetricSigner(CryptoSuite suite, PARCKeyStore *key_store) {
  parcAssertNotNull(key_store, "Expected non-null key_store");

  auto crypto_suite = static_cast<PARCCryptoSuite>(suite);

  switch (suite) {
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512:
      break;
    default:
      throw errors::RuntimeException(
          "Invalid crypto suite for symmetric signer");
  }

  setSigner(parcSigner_Create(parcSymmetricKeySigner_Create(
                                  (PARCSymmetricKeyStore *)key_store,
                                  parcCryptoSuite_GetCryptoHash(crypto_suite)),
                              PARCSymmetricKeySignerAsSigner));
}

SymmetricSigner::SymmetricSigner(CryptoSuite suite, const string &passphrase) {
  auto crypto_suite = static_cast<PARCCryptoSuite>(suite);

  switch (suite) {
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512:
      break;
    default:
      throw errors::RuntimeException(
          "Invalid crypto suite for symmetric signer");
  }

  PARCBufferComposer *composer = parcBufferComposer_Create();
  parcBufferComposer_PutString(composer, passphrase.c_str());
  PARCBuffer *key_buf = parcBufferComposer_ProduceBuffer(composer);
  parcBufferComposer_Release(&composer);

  PARCSymmetricKeyStore *key_store = parcSymmetricKeyStore_Create(key_buf);
  PARCSymmetricKeySigner *key_signer = parcSymmetricKeySigner_Create(
      key_store, parcCryptoSuite_GetCryptoHash(crypto_suite));

  setSigner(parcSigner_Create(key_signer, PARCSymmetricKeySignerAsSigner));

  parcSymmetricKeySigner_Release(&key_signer);
  parcSymmetricKeyStore_Release(&key_store);
  parcBuffer_Release(&key_buf);
}

}  // namespace auth
}  // namespace transport
