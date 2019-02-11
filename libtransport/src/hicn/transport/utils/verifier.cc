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
#include <hicn/transport/utils/key_id.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/verifier.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
#include <parc/security/parc_CertificateFactory.h>
#include <parc/security/parc_InMemoryVerifier.h>
#include <parc/security/parc_Security.h>
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
  parcInMemoryVerifier_Release(&in_memory_verifier);
}

Verifier::~Verifier() {
  parcVerifier_Release(&verifier_);
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

  PARCKey *key = parcCertificate_GetPublicKey(certificate);
  addKey(key);

  PARCKeyId *ret = parcKeyId_Acquire(parcKey_GetKeyId(key));

  //  parcKey_Release(&key);
  //  parcCertificate_Release(&certificate);
  //  parcCertificateFactory_Release(&factory);

  return ret;
}

int Verifier::verify(const Packet &packet) {
  bool valid = false;

  // header chain points to the IP + TCP hicn header
  utils::MemBuf *header_chain = packet.header_head_;
  utils::MemBuf *payload_chain = packet.payload_head_;
  uint8_t *hicn_packet = header_chain->writableData();
  Packet::Format format = packet.getFormat();

  if (!(packet.format_ & HFO_AH)) {
    throw errors::MalformedAHPacketException();
  }

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;
  if (format == HF_INET_TCP) {
    memcpy(&header_copy, hicn_packet, HICN_V4_TCP_HDRLEN);
  } else if (format == HF_INET6_TCP) {
    memcpy(&header_copy, hicn_packet, HICN_V6_TCP_HDRLEN);
  } else {
    throw errors::RuntimeException("Verifier::verify -- Packet format not expected.");
  }

  std::size_t header_len = Packet::getHeaderSizeFromFormat(format);

  PARCCryptoSuite suite =
      static_cast<PARCCryptoSuite>(packet.getValidationAlgorithm());
  KeyId _key_id = packet.getKeyId();
  PARCBuffer *buffer =
      parcBuffer_Wrap(_key_id.first, _key_id.second, 0, _key_id.second);
  PARCKeyId *key_id = parcKeyId_Create(buffer);
  parcBuffer_Release(&buffer);

  int ah_payload_len = packet.getSignatureSize();
  uint8_t *_signature = packet.getSignature();
  uint8_t signature[ah_payload_len];

  // TODO Remove signature copy at this point, by not setting to zero
  // the validation payload.
  std::memcpy(signature, _signature, ah_payload_len);

  // Reset fields that should not appear in the signature
  const_cast<Packet &>(packet).resetForHash();

  PARCCryptoHashType hashtype = parcCryptoSuite_GetCryptoHash(suite);
  utils::CryptoHasher hasher(
      parcVerifier_GetCryptoHasher(verifier_, key_id, hashtype));

  hasher.init().updateBytes(hicn_packet, header_len + ah_payload_len);

  for (utils::MemBuf *current = payload_chain; current != header_chain;
       current = current->next()) {
    hasher.updateBytes(current->data(), current->length());
  }

  utils::CryptoHash hash = hasher.finalize();
  PARCCryptoHash *hash_computed_locally = hash.hash_;

  parcBuffer_Display(parcCryptoHash_GetDigest(hash_computed_locally), 2);

  PARCBuffer *bits =
      parcBuffer_Wrap(signature, ah_payload_len, 0, ah_payload_len);
  parcBuffer_Rewind(bits);

  /* IF the signature algo is ECDSA, the signature might be shorter than the
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

  parcBuffer_Display(parcSignature_GetSignature(signatureToVerify), 2);

  valid = parcVerifier_VerifyDigestSignature(
      verifier_, key_id, hash_computed_locally, suite, signatureToVerify);

  /* Restore the resetted fields */
  if (format & HFO_INET) {
    memcpy(hicn_packet, &header_copy, HICN_V4_TCP_HDRLEN);
  } else if (format & HFO_INET6) {
    memcpy(hicn_packet, &header_copy, HICN_V6_TCP_HDRLEN);
  }

  parcKeyId_Release(&key_id);

  parcBuffer_Release(&bits);
  parcSignature_Release(&signatureToVerify);

  return valid;
}
}  // namespace utils
