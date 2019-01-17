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
#include <hicn/transport/utils/endianess.h>
#include <hicn/transport/utils/membuf.h>
#include <hicn/transport/utils/signer.h>
#include <hicn/transport/utils/key_id.h>


extern "C" {
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
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
Signer::Signer(PARCKeyStore *keyStore, PARCCryptoSuite suite) {
  switch (suite) {
    case PARCCryptoSuite_NULL_CRC32C:
      break;
    case PARCCryptoSuite_ECDSA_SHA256:
    case PARCCryptoSuite_RSA_SHA256:
    case PARCCryptoSuite_DSA_SHA256:
    case PARCCryptoSuite_RSA_SHA512:
      this->signer_ =
          parcSigner_Create(parcPublicKeySigner_Create(keyStore, suite),
                            PARCPublicKeySignerAsSigner);
      this->key_id_ = parcSigner_CreateKeyId(this->signer_);
      break;

    case PARCCryptoSuite_HMAC_SHA512:
    case PARCCryptoSuite_HMAC_SHA256:
    default:
      this->signer_ = parcSigner_Create(
          parcSymmetricKeySigner_Create((PARCSymmetricKeyStore *)keyStore,
                                        parcCryptoSuite_GetCryptoHash(suite)),
          PARCSymmetricKeySignerAsSigner);
      this->key_id_ = parcSigner_CreateKeyId(this->signer_);
      break;
  }
}

Signer::Signer(const PARCSigner *signer)
    : signer_(parcSigner_Acquire(signer)),
      key_id_(parcSigner_CreateKeyId(this->signer_)) {}

Signer::~Signer() {
  parcSigner_Release(&signer_);
  parcKeyId_Release(&key_id_);
}

void Signer::sign(Packet &packet) {
  // header chain points to the IP + TCP hicn header
  utils::MemBuf *header_chain = packet.header_head_;
  utils::MemBuf * payload_chain = packet.payload_head_;
  uint8_t *hicn_packet = header_chain->writableData();
  Packet::Format format = packet.getFormat();
  std::size_t sign_len_bytes = parcSigner_GetSignatureSize(signer_);

  if (!(format & HFO_AH)) {
    throw errors::MalformedAHPacketException();
  }

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;
  if (format & HFO_INET) {
    memcpy(&header_copy, hicn_packet, sizeof(hicn_v4_hdr_t));
  } else if (format & HFO_INET6) {
    memcpy(&header_copy, hicn_packet, sizeof(hicn_v6_hdr_t));
  }

  std::size_t header_len = Packet::getHeaderSizeFromFormat(format);

  packet.resetForHash();
  packet.setSignatureSize(sign_len_bytes);

  /* Fill the hicn_ah header */
  using namespace std::chrono;
  auto now = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  packet.setSignatureTimestamp(now);
  // *reinterpret_cast<uint64_t*>(ah->signTime) = utils::hton<uint64_t>(now);
  // // std::memcpy(&ah->hicn_ah.signTime, &sign_time, sizeof(ah->hicn_ah.signTime));

  packet.setValidationAlgorithm(CryptoSuite(parcSigner_GetCryptoSuite(this->signer_)));
  // ah->validationAlgorithm = parcSigner_GetCryptoSuite(this->signer_);

  KeyId key_id;
  key_id.first = (uint8_t *)parcBuffer_Overlay((PARCBuffer *) parcKeyId_GetKeyId(this->key_id_), 0);
  packet.setKeyId(key_id);

  // memcpy(ah->keyId,
  //        parcBuffer_Overlay((PARCBuffer *) parcKeyId_GetKeyId(this->key_id_), 0),
  //        sizeof(_ah_header_t::keyId));

  // Calculate hash
  utils::CryptoHasher hasher(parcSigner_GetCryptoHasher(signer_));
  hasher.init();
  hasher.updateBytes(hicn_packet, header_len);
  hasher.updateBytes(zeros, sign_len_bytes);
  
  for (utils::MemBuf *current = payload_chain; current != header_chain; current = current->next()) {
    hasher.updateBytes(current->data(), current->length());
  }

  utils::CryptoHash hash = hasher.finalize();
  
  PARCSignature *signature = parcSigner_SignDigest(this->signer_, hash.hash_);
  PARCBuffer *buffer = parcSignature_GetSignature(signature);

  PARCByteArray * byte_array = parcBuffer_Array(buffer);
  uint8_t * bytes = parcByteArray_Array(byte_array);
  size_t bytes_len = parcBuffer_Remaining(buffer);

  if (bytes_len > sign_len_bytes) {
    throw errors::MalformedAHPacketException();
  }

    /* Restore the resetted fields */
  if (format & HFO_INET) {
    memcpy(hicn_packet, &header_copy, sizeof(hicn_v4_hdr_t));
  } else if (format & HFO_INET6) {
    memcpy(hicn_packet, &header_copy, sizeof(hicn_v6_hdr_t));
  }

  int offset = sign_len_bytes - bytes_len;

  std::unique_ptr<utils::MemBuf> signature_buffer;
  std::unique_ptr<utils::MemBuf> tmp_buf = utils::MemBuf::takeOwnership(
    bytes,
    bytes_len,
    bytes_len,
    [](void* buf, void* userData){ parcSignature_Release((PARCSignature **)&userData); },
    signature,
    true);

  if (offset) {
    signature_buffer = utils::MemBuf::create(offset);
    memset(signature_buffer->writableData(), 0, offset);
    signature_buffer->append(offset);
    signature_buffer->appendChain(std::move(tmp_buf));
  } else {
    signature_buffer = std::move(tmp_buf);
  }

  packet.setSignature(std::move(signature_buffer));
}

}  // namespace utils
