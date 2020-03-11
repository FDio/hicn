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

#include <hicn/transport/core/packet.h>
#include <hicn/transport/errors/malformed_ahpacket_exception.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/security/key_id.h>
#include <hicn/transport/security/verifier.h>
#include <hicn/transport/utils/log.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
}

#include <sys/stat.h>

namespace utils {

TRANSPORT_ALWAYS_INLINE bool file_exists(const std::string &name) {
  struct stat buffer;
  return (stat(name.c_str(), &buffer) == 0);
}

uint8_t Verifier::zeros[200] = {0};

Verifier::Verifier() {
  parcSecurity_Init();
  PARCInMemoryVerifier *in_memory_verifier = parcInMemoryVerifier_Create();
  this->verifier_ =
      parcVerifier_Create(in_memory_verifier, PARCInMemoryVerifierAsVerifier);
}

Verifier::~Verifier() {
  if (key_) parcKey_Release(&key_);
  if (keyId_) parcKeyId_Release(&keyId_);
  if (signer_) parcSigner_Release(&signer_);
  if (symmetricKeyStore_) parcSymmetricKeyStore_Release(&symmetricKeyStore_);
  if (key_buffer_) parcBuffer_Release(&key_buffer_);
  if (composer_) parcBufferComposer_Release(&composer_);
  if (certificate_) parcCertificate_Release(&certificate_);
  if (factory_) parcCertificateFactory_Release(&factory_);
  if (verifier_) parcVerifier_Release(&verifier_);
  parcSecurity_Fini();
}

/*
 * TODO: Unsupported in libparc
 */
bool Verifier::hasKey(PARCKeyId *keyId) { return false; }

/*
 * TODO: signal errors without trap.
 */
bool Verifier::addKey(PARCKey *key) {
  parcVerifier_AddKey(this->verifier_, key);
  return true;
}

PARCKeyId *Verifier::addKeyFromPassphrase(const std::string &passphrase,
                                          CryptoSuite suite) {
  composer_ = parcBufferComposer_Create();
  parcBufferComposer_PutString(composer_, passphrase.c_str());
  key_buffer_ = parcBufferComposer_ProduceBuffer(composer_);

  symmetricKeyStore_ = parcSymmetricKeyStore_Create(key_buffer_);
  signer_ = parcSigner_Create(
      parcSymmetricKeySigner_Create(
          symmetricKeyStore_,
          parcCryptoSuite_GetCryptoHash(static_cast<PARCCryptoSuite>(suite))),
      PARCSymmetricKeySignerAsSigner);
  keyId_ = parcSigner_CreateKeyId(signer_);
  key_ = parcKey_CreateFromSymmetricKey(
      keyId_, parcSigner_GetSigningAlgorithm(signer_), key_buffer_);

  addKey(key_);
  return keyId_;
}

PARCKeyId *Verifier::addKeyFromCertificate(const std::string &file_name) {
  factory_ = parcCertificateFactory_Create(PARCCertificateType_X509,
                                           PARCContainerEncoding_PEM);
  parcAssertNotNull(factory_, "Expected non-NULL factory");

  if (!file_exists(file_name)) {
    TRANSPORT_LOGW("Warning! The certificate %s file does not exist",
                   file_name.c_str());
    return nullptr;
  }

  certificate_ = parcCertificateFactory_CreateCertificateFromFile(
      factory_, (char *)file_name.c_str(), NULL);
  PARCBuffer *derEncodedVersion =
      parcCertificate_GetDEREncodedPublicKey(certificate_);
  PARCCryptoHash *keyDigest = parcCertificate_GetPublicKeyDigest(certificate_);
  keyId_ = parcKeyId_Create(parcCryptoHash_GetDigest(keyDigest));
  key_ = parcKey_CreateFromDerEncodedPublicKey(keyId_, PARCSigningAlgorithm_RSA,
                                               derEncodedVersion);

  addKey(key_);
  return keyId_;
}

int Verifier::verify(const Packet &packet) {
  // Initialize packet.payload_head_
  const_cast<Packet *>(&packet)->separateHeaderPayload();
  Packet::Format format = packet.getFormat();
  bool valid = false;

  if (!(packet.format_ & HFO_AH)) {
    throw errors::MalformedAHPacketException();
  }

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, (const hicn_header_t *)packet.packet_start_,
                          &header_copy, false);

  PARCCryptoSuite suite =
      static_cast<PARCCryptoSuite>(packet.getValidationAlgorithm());
  PARCCryptoHashType hashtype = parcCryptoSuite_GetCryptoHash(suite);
  KeyId _key_id = packet.getKeyId();
  PARCBuffer *buffer =
      parcBuffer_Wrap(_key_id.first, _key_id.second, 0, _key_id.second);
  PARCKeyId *key_id = parcKeyId_Create(buffer);
  parcBuffer_Release(&buffer);

  int ah_payload_len = (int)packet.getSignatureSize();
  uint8_t *_signature = packet.getSignature();
  uint8_t *signature = new uint8_t[ah_payload_len];
  std::shared_ptr<CryptoHasher> hasher;

  // TODO Remove signature copy at this point, by not setting to zero
  // the validation payload.
  std::memcpy(signature, _signature, ah_payload_len);

  switch (CryptoSuite(suite)) {
    case CryptoSuite::DSA_SHA256:
    case CryptoSuite::RSA_SHA256:
    case CryptoSuite::RSA_SHA512:
    case CryptoSuite::ECDSA_256K1: {
      hasher = std::make_shared<CryptoHasher>(
          parcVerifier_GetCryptoHasher(verifier_, key_id, hashtype));
      break;
    }
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512: {
      if (!signer_) return false;
      hasher =
          std::make_shared<CryptoHasher>(parcSigner_GetCryptoHasher(signer_));
      break;
    }
    default: { return false; }
  }
  CryptoHash hash_computed_locally = getPacketHash(packet, hasher);

  PARCBuffer *bits =
      parcBuffer_Wrap(signature, ah_payload_len, 0, ah_payload_len);
  parcBuffer_Rewind(bits);

  /* If the signature algo is ECDSA, the signature might be shorter than the
   * signature field */
  PARCSigningAlgorithm algo = parcCryptoSuite_GetSigningAlgorithm(suite);
  while (algo == PARCSigningAlgorithm_ECDSA && parcBuffer_HasRemaining(bits) &&
         parcBuffer_GetUint8(bits) == 0)
    ;

  if (algo == PARCSigningAlgorithm_ECDSA) {
    parcBuffer_SetPosition(bits, parcBuffer_Position(bits) - 1);
  }

  if (!parcBuffer_HasRemaining(bits)) {
    parcKeyId_Release(&key_id);
    parcBuffer_Release(&bits);
    return valid;
  }

  PARCSignature *signatureToVerify = parcSignature_Create(
      parcCryptoSuite_GetSigningAlgorithm(suite), hashtype, bits);

  if (algo == PARCSigningAlgorithm_RSA) {
    parcBuffer_SetPosition(bits, 0);
  }

  valid = parcVerifier_VerifyDigestSignature(
      verifier_, key_id, hash_computed_locally.hash_, suite, signatureToVerify);

  /* Restore the resetted fields */
  hicn_packet_copy_header(format, &header_copy,
                          (hicn_header_t *)packet.packet_start_, false);

  delete[] signature;
  parcKeyId_Release(&key_id);
  parcBuffer_Release(&bits);
  parcSignature_Release(&signatureToVerify);

  return valid;
}

CryptoHash Verifier::getPacketHash(const Packet &packet,
                                   std::shared_ptr<CryptoHasher> hasher) {
  MemBuf *header_chain = packet.header_head_;
  MemBuf *payload_chain = packet.payload_head_;
  Packet::Format format = packet.getFormat();
  int ah_payload_len = (int)packet.getSignatureSize();
  uint8_t *hicn_packet = header_chain->writableData();
  std::size_t header_len = Packet::getHeaderSizeFromFormat(format);

  // Reset fields that should not appear in the signature
  const_cast<Packet &>(packet).resetForHash();
  hasher->init().updateBytes(hicn_packet, header_len + ah_payload_len);

  for (MemBuf *current = payload_chain; current != header_chain;
       current = current->next()) {
    hasher->updateBytes(current->data(), current->length());
  }

  return hasher->finalize();
}

}  // namespace utils
