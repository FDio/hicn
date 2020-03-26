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

Verifier::Verifier() {
  parcSecurity_Init();
  PARCInMemoryVerifier *in_memory_verifier = parcInMemoryVerifier_Create();
  this->verifier_ =
      parcVerifier_Create(in_memory_verifier, PARCInMemoryVerifierAsVerifier);
}

Verifier::~Verifier() {
  if (signer_) parcSigner_Release(&signer_);
  if (verifier_) parcVerifier_Release(&verifier_);
  parcSecurity_Fini();
}

/*
 * TODO: Unsupported in libparc
 */
bool Verifier::hasKey(PARCKeyId *key_id) { return false; }

/*
 * TODO: Signal errors without trap.
 */
bool Verifier::addKey(PARCKey *key) {
  parcVerifier_AddKey(this->verifier_, key);
  return true;
}

PARCKeyId *Verifier::addKeyFromPassphrase(const std::string &passphrase,
                                          CryptoSuite suite) {
  PARCBufferComposer *composer = parcBufferComposer_Create();
  parcBufferComposer_PutString(composer, passphrase.c_str());
  PARCBuffer *key_buffer = parcBufferComposer_ProduceBuffer(composer);

  PARCSymmetricKeyStore *symmetricKeyStore =
      parcSymmetricKeyStore_Create(key_buffer);
  signer_ = parcSigner_Create(
      parcSymmetricKeySigner_Create(
          symmetricKeyStore,
          parcCryptoSuite_GetCryptoHash(static_cast<PARCCryptoSuite>(suite))),
      PARCSymmetricKeySignerAsSigner);

  PARCKeyId *key_id = parcSigner_CreateKeyId(signer_);
  PARCKey *key = parcKey_CreateFromSymmetricKey(
      key_id, parcSigner_GetSigningAlgorithm(signer_), key_buffer);

  addKey(key);

  parcKey_Release(&key);
  parcSymmetricKeyStore_Release(&symmetricKeyStore);
  parcBuffer_Release(&key_buffer);
  parcBufferComposer_Release(&composer);

  return key_id;
}

PARCKeyId *Verifier::addKeyFromCertificate(const std::string &file_name) {
  PARCCertificateFactory *factory = parcCertificateFactory_Create(
      PARCCertificateType_X509, PARCContainerEncoding_PEM);
  parcAssertNotNull(factory, "Expected non-NULL factory");

  if (!file_exists(file_name)) {
    TRANSPORT_LOGW("Warning! The certificate %s file does not exist",
                   file_name.c_str());
    return nullptr;
  }

  PARCCertificate *certificate =
      parcCertificateFactory_CreateCertificateFromFile(
          factory, (char *)file_name.c_str(), NULL);
  PARCBuffer *derEncodedVersion =
      parcCertificate_GetDEREncodedPublicKey(certificate);
  PARCCryptoHash *keyDigest = parcCertificate_GetPublicKeyDigest(certificate);

  PARCKeyId *key_id = parcKeyId_Create(parcCryptoHash_GetDigest(keyDigest));
  PARCKey *key = parcKey_CreateFromDerEncodedPublicKey(
      key_id, PARCSigningAlgorithm_RSA, derEncodedVersion);

  addKey(key);

  parcKey_Release(&key);
  parcCertificate_Release(&certificate);
  parcCertificateFactory_Release(&factory);

  return key_id;
}

int Verifier::verify(const Packet &packet) {
  /* Initialize packet.payload_head_ */
  const_cast<Packet *>(&packet)->separateHeaderPayload();

  bool valid = false;
  Packet::Format format = packet.getFormat();

  if (!(format & HFO_AH)) {
    throw errors::MalformedAHPacketException();
  }

  /* Copy IP+TCP/ICMP header before zeroing them */
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, (const hicn_header_t *)packet.packet_start_,
                          &header_copy, false);

  /* Get crypto suite */
  PARCCryptoSuite suite =
      static_cast<PARCCryptoSuite>(packet.getValidationAlgorithm());
  PARCCryptoHashType hashtype = parcCryptoSuite_GetCryptoHash(suite);

  /* Fetch the key that we will use to verify the signature */
  KeyId _key_id = packet.getKeyId();
  PARCBuffer *buffer =
      parcBuffer_Wrap(_key_id.first, _key_id.second, 0, _key_id.second);
  PARCKeyId *key_id = parcKeyId_Create(buffer);
  parcBuffer_Release(&buffer);

  /* Fetch signature */
  int ah_payload_len = (int)packet.getSignatureSize();
  uint8_t *_signature = packet.getSignature();
  uint8_t *signature = new uint8_t[ah_payload_len];
  /* TODO Remove signature copy at this point, by not setting to zero */
  /* the validation payload. */
  std::memcpy(signature, _signature, ah_payload_len);

  /* Prepare local computation of the signature based on the crypto suite */
  PARCCryptoHasher *hasher_ptr = nullptr;
  switch (CryptoSuite(suite)) {
    case CryptoSuite::DSA_SHA256:
    case CryptoSuite::RSA_SHA256:
    case CryptoSuite::RSA_SHA512:
    case CryptoSuite::ECDSA_256K1: {
      hasher_ptr = parcVerifier_GetCryptoHasher(verifier_, key_id, hashtype);
      break;
    }
    case CryptoSuite::HMAC_SHA256:
    case CryptoSuite::HMAC_SHA512: {
      if (!signer_) return false;
      hasher_ptr = parcSigner_GetCryptoHasher(signer_);
      break;
    }
    default: { return false; }
  }

  /* Compute the packet signature locally */
  CryptoHasher crypto_hasher(hasher_ptr);
  CryptoHash hash_computed_locally = getPacketHash(packet, crypto_hasher);

  /* Create a signature object from the raw packet signature */
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
    delete[] signature;
    parcKeyId_Release(&key_id);
    parcBuffer_Release(&bits);
    return valid;
  }

  PARCSignature *signatureToVerify = parcSignature_Create(
      parcCryptoSuite_GetSigningAlgorithm(suite), hashtype, bits);

  if (algo == PARCSigningAlgorithm_RSA) {
    parcBuffer_SetPosition(bits, 0);
  }

  /* Compare the packet signature to the locally computed one */
  valid = parcVerifier_VerifyDigestSignature(
      verifier_, key_id, hash_computed_locally.crypto_hash_.parc, suite,
      signatureToVerify);

  /* Restore the fields that were reset */
  hicn_packet_copy_header(format, &header_copy,
                          (hicn_header_t *)packet.packet_start_, false);

  delete[] signature;
  parcKeyId_Release(&key_id);
  parcBuffer_Release(&bits);
  parcSignature_Release(&signatureToVerify);

  return valid;
}

CryptoHash Verifier::getPacketHash(const Packet &packet,
                                   CryptoHasher &crypto_hasher) {
  MemBuf *header_chain = packet.header_head_;
  MemBuf *payload_chain = packet.payload_head_;
  Packet::Format format = packet.getFormat();
  int ah_payload_len = (int)packet.getSignatureSize();
  uint8_t *hicn_packet = header_chain->writableData();
  std::size_t header_len = Packet::getHeaderSizeFromFormat(format);

  /* Reset fields that should not appear in the signature */
  const_cast<Packet &>(packet).resetForHash();
  crypto_hasher.init().updateBytes(hicn_packet, header_len + ah_payload_len);

  for (MemBuf *current = payload_chain; current != header_chain;
       current = current->next()) {
    crypto_hasher.updateBytes(current->data(), current->length());
  }

  return crypto_hasher.finalize();
}

}  // namespace utils
