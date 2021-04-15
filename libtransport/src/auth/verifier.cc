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

#include <hicn/transport/auth/verifier.h>
#include <protocols/errors.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
}

#include <sys/stat.h>

using namespace std;

namespace transport {
namespace auth {

const std::vector<VerificationPolicy> Verifier::DEFAULT_FAILED_POLICIES = {
    VerificationPolicy::DROP,
    VerificationPolicy::ABORT,
};

Verifier::Verifier()
    : hasher_(nullptr),
      verifier_(nullptr),
      verification_failed_cb_(interface::VOID_HANDLER),
      failed_policies_(DEFAULT_FAILED_POLICIES) {
  parcSecurity_Init();
  PARCInMemoryVerifier *in_memory_verifier = parcInMemoryVerifier_Create();
  verifier_ =
      parcVerifier_Create(in_memory_verifier, PARCInMemoryVerifierAsVerifier);
  parcInMemoryVerifier_Release(&in_memory_verifier);
}

Verifier::~Verifier() {
  if (hasher_) parcCryptoHasher_Release(&hasher_);
  if (verifier_) parcVerifier_Release(&verifier_);
  parcSecurity_Fini();
}

bool Verifier::verifyPacket(PacketPtr packet) {
  bool valid_packet = false;
  core::Packet::Format format = packet->getFormat();

  if (!packet->authenticationHeader()) {
    throw errors::MalformedAHPacketException();
  }

  // Get crypto suite and hash type
  auto suite = static_cast<PARCCryptoSuite>(packet->getValidationAlgorithm());
  PARCCryptoHashType hash_type = parcCryptoSuite_GetCryptoHash(suite);

  // Copy IP+TCP / ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, packet->packet_start_, &header_copy, false);

  // Fetch packet signature
  uint8_t *packet_signature = packet->getSignature();
  size_t signature_len = Verifier::getSignatureSize(packet);
  vector<uint8_t> signature_raw(packet_signature,
                                packet_signature + signature_len);

  // Create a signature buffer from the raw packet signature
  PARCBuffer *bits =
      parcBuffer_Wrap(signature_raw.data(), signature_len, 0, signature_len);
  parcBuffer_Rewind(bits);

  // If the signature algo is ECDSA, the signature might be shorter than the
  // signature field
  PARCSigningAlgorithm algo = parcCryptoSuite_GetSigningAlgorithm(suite);
  if (algo == PARCSigningAlgorithm_ECDSA) {
    while (parcBuffer_HasRemaining(bits) && parcBuffer_GetUint8(bits) == 0)
      ;
    parcBuffer_SetPosition(bits, parcBuffer_Position(bits) - 1);
  }

  if (!parcBuffer_HasRemaining(bits)) {
    parcBuffer_Release(&bits);
    return false;
  }

  // Create a signature object from the signature buffer
  PARCSignature *signature = parcSignature_Create(
      parcCryptoSuite_GetSigningAlgorithm(suite), hash_type, bits);

  // Fetch the key to verify the signature
  KeyId key_buffer = packet->getKeyId();
  PARCBuffer *buffer = parcBuffer_Wrap(key_buffer.first, key_buffer.second, 0,
                                       key_buffer.second);
  PARCKeyId *key_id = parcKeyId_Create(buffer);

  // Reset fields that are not used to compute signature
  packet->resetForHash();

  // Compute the packet hash
  if (!hasher_)
    setHasher(parcVerifier_GetCryptoHasher(verifier_, key_id, hash_type));
  CryptoHash local_hash = computeHash(packet);

  // Compare the packet signature to the locally computed one
  valid_packet = parcVerifier_VerifyDigestSignature(
      verifier_, key_id, local_hash.hash_, suite, signature);

  // Restore the fields that were reset
  hicn_packet_copy_header(format, &header_copy, packet->packet_start_, false);

  // Release allocated objects
  parcBuffer_Release(&buffer);
  parcKeyId_Release(&key_id);
  parcSignature_Release(&signature);
  parcBuffer_Release(&bits);

  return valid_packet;
}

vector<VerificationPolicy> Verifier::verifyPackets(
    const vector<PacketPtr> &packets) {
  vector<VerificationPolicy> policies(packets.size(), VerificationPolicy::DROP);

  for (unsigned int i = 0; i < packets.size(); ++i) {
    if (verifyPacket(packets[i])) {
      policies[i] = VerificationPolicy::ACCEPT;
    }

    callVerificationFailedCallback(packets[i], policies[i]);
  }

  return policies;
}

vector<VerificationPolicy> Verifier::verifyPackets(
    const vector<PacketPtr> &packets,
    const unordered_map<Suffix, HashEntry> &suffix_map) {
  vector<VerificationPolicy> policies(packets.size(),
                                      VerificationPolicy::UNKNOWN);

  for (unsigned int i = 0; i < packets.size(); ++i) {
    uint32_t suffix = packets[i]->getName().getSuffix();
    auto manifest_hash = suffix_map.find(suffix);

    if (manifest_hash != suffix_map.end()) {
      CryptoHashType hash_type = manifest_hash->second.first;
      CryptoHash packet_hash = packets[i]->computeDigest(hash_type);

      if (!CryptoHash::compareBinaryDigest(
              packet_hash.getDigest<uint8_t>().data(),
              manifest_hash->second.second.data(), hash_type)) {
        policies[i] = VerificationPolicy::ABORT;
      } else {
        policies[i] = VerificationPolicy::ACCEPT;
      }
    }

    callVerificationFailedCallback(packets[i], policies[i]);
  }

  return policies;
}

void Verifier::addKey(PARCKey *key) { parcVerifier_AddKey(verifier_, key); }

void Verifier::setHasher(PARCCryptoHasher *hasher) {
  parcAssertNotNull(hasher, "Expected non-null hasher");
  if (hasher_) parcCryptoHasher_Release(&hasher_);
  hasher_ = parcCryptoHasher_Acquire(hasher);
}

void Verifier::setVerificationFailedCallback(
    VerificationFailedCallback verfication_failed_cb,
    const vector<VerificationPolicy> &failed_policies) {
  verification_failed_cb_ = verfication_failed_cb;
  failed_policies_ = failed_policies;
}

void Verifier::getVerificationFailedCallback(
    VerificationFailedCallback **verfication_failed_cb) {
  *verfication_failed_cb = &verification_failed_cb_;
}

size_t Verifier::getSignatureSize(const PacketPtr packet) {
  return packet->getSignatureSize();
}

CryptoHash Verifier::computeHash(PacketPtr packet) {
  parcAssertNotNull(hasher_, "Expected non-null hasher");

  CryptoHasher crypto_hasher(hasher_);
  const utils::MemBuf &header_chain = *packet;
  const utils::MemBuf *current = &header_chain;

  crypto_hasher.init();

  do {
    crypto_hasher.updateBytes(current->data(), current->length());
    current = current->next();
  } while (current != &header_chain);

  return crypto_hasher.finalize();
}

void Verifier::callVerificationFailedCallback(PacketPtr packet,
                                              VerificationPolicy &policy) {
  if (verification_failed_cb_ == interface::VOID_HANDLER) {
    return;
  }

  if (find(failed_policies_.begin(), failed_policies_.end(), policy) !=
      failed_policies_.end()) {
    policy = verification_failed_cb_(
        static_cast<const core::ContentObject &>(*packet),
        make_error_code(
            protocol::protocol_error::signature_verification_failed));
  }
}

bool VoidVerifier::verifyPacket(PacketPtr packet) { return true; }

vector<VerificationPolicy> VoidVerifier::verifyPackets(
    const vector<PacketPtr> &packets) {
  return vector<VerificationPolicy>(packets.size(), VerificationPolicy::ACCEPT);
}

vector<VerificationPolicy> VoidVerifier::verifyPackets(
    const vector<PacketPtr> &packets,
    const unordered_map<Suffix, HashEntry> &suffix_map) {
  return vector<VerificationPolicy>(packets.size(), VerificationPolicy::ACCEPT);
}

AsymmetricVerifier::AsymmetricVerifier(PARCKey *pub_key) { addKey(pub_key); }

AsymmetricVerifier::AsymmetricVerifier(const string &cert_path) {
  setCertificate(cert_path);
}

void AsymmetricVerifier::setCertificate(const string &cert_path) {
  PARCCertificateFactory *factory = parcCertificateFactory_Create(
      PARCCertificateType_X509, PARCContainerEncoding_PEM);

  struct stat buffer;
  if (stat(cert_path.c_str(), &buffer) != 0) {
    throw errors::RuntimeException("Certificate does not exist");
  }

  PARCCertificate *certificate =
      parcCertificateFactory_CreateCertificateFromFile(factory,
                                                       cert_path.c_str(), NULL);
  PARCKey *key = parcCertificate_GetPublicKey(certificate);

  addKey(key);

  parcKey_Release(&key);
  parcCertificateFactory_Release(&factory);
}

SymmetricVerifier::SymmetricVerifier(const string &passphrase)
    : passphrase_(nullptr), signer_(nullptr) {
  setPassphrase(passphrase);
}

SymmetricVerifier::~SymmetricVerifier() {
  if (passphrase_) parcBuffer_Release(&passphrase_);
  if (signer_) parcSigner_Release(&signer_);
}

void SymmetricVerifier::setPassphrase(const string &passphrase) {
  if (passphrase_) parcBuffer_Release(&passphrase_);

  PARCBufferComposer *composer = parcBufferComposer_Create();
  parcBufferComposer_PutString(composer, passphrase.c_str());
  passphrase_ = parcBufferComposer_ProduceBuffer(composer);
  parcBufferComposer_Release(&composer);
}

void SymmetricVerifier::setSigner(const PARCCryptoSuite &suite) {
  parcAssertNotNull(passphrase_, "Expected non-null passphrase");

  if (signer_) parcSigner_Release(&signer_);

  PARCSymmetricKeyStore *key_store = parcSymmetricKeyStore_Create(passphrase_);
  PARCSymmetricKeySigner *key_signer = parcSymmetricKeySigner_Create(
      key_store, parcCryptoSuite_GetCryptoHash(suite));
  signer_ = parcSigner_Create(key_signer, PARCSymmetricKeySignerAsSigner);

  PARCKeyId *key_id = parcSigner_CreateKeyId(signer_);
  PARCKey *key = parcKey_CreateFromSymmetricKey(
      key_id, parcSigner_GetSigningAlgorithm(signer_), passphrase_);

  addKey(key);
  setHasher(parcSigner_GetCryptoHasher(signer_));

  parcSymmetricKeyStore_Release(&key_store);
  parcSymmetricKeySigner_Release(&key_signer);
  parcKeyId_Release(&key_id);
  parcKey_Release(&key);
}

vector<VerificationPolicy> SymmetricVerifier::verifyPackets(
    const vector<PacketPtr> &packets) {
  vector<VerificationPolicy> policies(packets.size(), VerificationPolicy::DROP);

  for (unsigned int i = 0; i < packets.size(); ++i) {
    auto suite =
        static_cast<PARCCryptoSuite>(packets[i]->getValidationAlgorithm());

    if (!signer_ || suite != parcSigner_GetCryptoSuite(signer_)) {
      setSigner(suite);
    }

    if (verifyPacket(packets[i])) {
      policies[i] = VerificationPolicy::ACCEPT;
    }

    callVerificationFailedCallback(packets[i], policies[i]);
  }

  return policies;
}

}  // namespace auth
}  // namespace transport
