/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Copyright 2017 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hicn/transport/errors/malformed_ahpacket_exception.h>
#include <hicn/transport/security/key_id.h>
#include <hicn/transport/security/signer.h>
#include <hicn/transport/utils/membuf.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
#include <parc/security/parc_PublicKeySigner.h>
#include <parc/security/parc_Security.h>
#include <parc/security/parc_SymmetricKeySigner.h>
}

#include <chrono>

#define ALLOW_UNALIGNED_READS 1

namespace utils {

uint8_t Signer::zeros[200] = {0};

/*One signer_ per Private Key*/
Signer::Signer(PARCKeyStore *keyStore, CryptoSuite suite) {
  parcSecurity_Init();

  switch (suite) {
    case CryptoSuite::DSA_SHA256:
    case CryptoSuite::RSA_SHA256:
    case CryptoSuite::RSA_SHA512:
    case CryptoSuite::ECDSA_256K1: {
      this->signer_ =
          parcSigner_Create(parcPublicKeySigner_Create(
                                keyStore, static_cast<PARCCryptoSuite>(suite)),
                            PARCPublicKeySignerAsSigner);
      break;
    }
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512: {
      this->signer_ =
          parcSigner_Create(parcSymmetricKeySigner_Create(
                                (PARCSymmetricKeyStore *)keyStore,
                                parcCryptoSuite_GetCryptoHash(
                                    static_cast<PARCCryptoSuite>(suite))),
                            PARCSymmetricKeySignerAsSigner);
      break;
    }
    default: { return; }
  }

  suite_ = suite;
  key_id_ = parcSigner_CreateKeyId(this->signer_);
  signature_length_ = parcSigner_GetSignatureSize(this->signer_);
}

Signer::Signer(const std::string &passphrase, CryptoSuite suite) {
  parcSecurity_Init();

  switch (suite) {
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512: {
      composer_ = parcBufferComposer_Create();
      parcBufferComposer_PutString(composer_, passphrase.c_str());
      key_buffer_ = parcBufferComposer_ProduceBuffer(composer_);
      symmetricKeyStore_ = parcSymmetricKeyStore_Create(key_buffer_);
      this->signer_ = parcSigner_Create(
          parcSymmetricKeySigner_Create(
              symmetricKeyStore_, parcCryptoSuite_GetCryptoHash(
                                      static_cast<PARCCryptoSuite>(suite))),
          PARCSymmetricKeySignerAsSigner);
      break;
    }
    default: { return; }
  }

  suite_ = suite;
  key_id_ = parcSigner_CreateKeyId(this->signer_);
  signature_length_ = parcSigner_GetSignatureSize(this->signer_);
}

Signer::Signer(const PARCSigner *signer, CryptoSuite suite)
    : signer_(parcSigner_Acquire(signer)),
      key_id_(parcSigner_CreateKeyId(this->signer_)),
      suite_(suite),
      signature_length_(parcSigner_GetSignatureSize(this->signer_)) {
  parcSecurity_Init();
}

Signer::Signer(const PARCSigner *signer)
    : Signer(signer, CryptoSuite::UNKNOWN) {}

Signer::~Signer() {
  if (signature_) parcSignature_Release(&signature_);
  if (symmetricKeyStore_) parcSymmetricKeyStore_Release(&symmetricKeyStore_);
  if (key_buffer_) parcBuffer_Release(&key_buffer_);
  if (composer_) parcBufferComposer_Release(&composer_);
  if (signer_) parcSigner_Release(&signer_);
  if (key_id_) parcKeyId_Release(&key_id_);
  parcSecurity_Fini();
}

void Signer::sign(Packet &packet) {
  // header chain points to the IP + TCP hicn header + AH Header
  MemBuf *header_chain = packet.header_head_;
  MemBuf *payload_chain = packet.payload_head_;
  uint8_t *hicn_packet = (uint8_t *)header_chain->writableData();
  Packet::Format format = packet.getFormat();

  if (!(format & HFO_AH)) {
    throw errors::MalformedAHPacketException();
  }

  packet.setSignatureSize(signature_length_);

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, (const hicn_header_t *)packet.packet_start_,
                          &header_copy, false);

  std::size_t header_len = Packet::getHeaderSizeFromFormat(format);

  packet.resetForHash();

  /* Fill the hicn_ah header */
  using namespace std::chrono;
  auto now = duration_cast<milliseconds>(system_clock::now().time_since_epoch())
                 .count();
  packet.setSignatureTimestamp(now);
  packet.setValidationAlgorithm(suite_);

  KeyId key_id;
  key_id.first = (uint8_t *)parcBuffer_Overlay(
      (PARCBuffer *)parcKeyId_GetKeyId(this->key_id_), 0);
  packet.setKeyId(key_id);

  // Calculate hash
  CryptoHasher hasher(parcSigner_GetCryptoHasher(signer_));
  hasher.init();
  hasher.updateBytes(hicn_packet, header_len + signature_length_);

  for (MemBuf *current = payload_chain; current != header_chain;
       current = current->next()) {
    hasher.updateBytes(current->data(), current->length());
  }

  CryptoHash hash = hasher.finalize();
  signature_ = parcSigner_SignDigestNoAlloc(this->signer_, hash.hash_,
                                            packet.getSignature(),
                                            (uint32_t)signature_length_);
  PARCBuffer *buffer = parcSignature_GetSignature(signature_);
  size_t bytes_len = parcBuffer_Remaining(buffer);

  if (bytes_len > signature_length_) {
    throw errors::MalformedAHPacketException();
  }

  hicn_packet_copy_header(format, &header_copy,
                          (hicn_header_t *)packet.packet_start_, false);

  parcSignature_Release(&signature_);
}

size_t Signer::getSignatureLength() { return signature_length_; }

PARCKeyStore *Signer::getKeyStore() {
  return parcSigner_GetKeyStore(this->signer_);
}

}  // namespace utils
