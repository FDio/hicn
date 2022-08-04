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

#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/core/interest.h>
#include <protocols/errors.h>

#include "glog/logging.h"

namespace transport {
namespace auth {

const std::vector<VerificationPolicy> Verifier::DEFAULT_FAILED_POLICIES = {
    VerificationPolicy::DROP,
    VerificationPolicy::ABORT,
};

// ---------------------------------------------------------
// Base Verifier
// ---------------------------------------------------------
Verifier::Verifier()
    : verification_failed_cb_(interface::VOID_HANDLER),
      failed_policies_(DEFAULT_FAILED_POLICIES) {}

Verifier::~Verifier() {}

bool Verifier::verifyPacket(PacketPtr packet) {
  if (!packet->hasAH()) {
    throw errors::MalformedAHPacketException();
  }

  // Get crypto suite, hash type, signature length
  CryptoSuite suite = packet->getValidationAlgorithm();
  CryptoHashType hash_type = getHashType(suite);

  // Copy IP+TCP / ICMP header before zeroing them
  u8 header_copy[HICN_HDRLEN_MAX];
  size_t header_len;
  packet->saveHeader(header_copy, &header_len);

  // Copy bitmap from interest manifest
  uint32_t request_bitmap[BITMAP_SIZE] = {0};
  if (packet->isInterest()) {
    core::Interest *interest = dynamic_cast<core::Interest *>(packet);
    memcpy(request_bitmap, interest->getRequestBitmap(),
           BITMAP_SIZE * sizeof(uint32_t));
  }

  // Retrieve packet signature
  utils::MemBuf::Ptr signature_raw = packet->getSignature();
  std::size_t signature_len = packet->getSignatureSize();
  DCHECK(signature_len <= signature_raw->tailroom());
  signature_raw->setLength(signature_len);

  // Reset fields that are not used to compute signature
  packet->resetForHash();

  // Check signatures
  bool valid_packet = verifyBuffer(static_cast<utils::MemBuf *>(packet),
                                   signature_raw, hash_type);

  // Restore header
  packet->loadHeader(header_copy, header_len);
  packet->setSignature(signature_raw);
  packet->setSignatureSize(signature_raw->length());

  // Restore bitmap in interest manifest
  if (packet->isInterest()) {
    core::Interest *interest = dynamic_cast<core::Interest *>(packet);
    interest->setRequestBitmap(request_bitmap);
  }

  return valid_packet;
}

Verifier::PolicyMap Verifier::verifyPackets(
    const std::vector<PacketPtr> &packets) {
  PolicyMap policies;

  for (const auto &packet : packets) {
    Suffix suffix = packet->getName().getSuffix();
    VerificationPolicy policy = VerificationPolicy::ABORT;

    if (verifyPacket(packet)) {
      policy = VerificationPolicy::ACCEPT;
    }

    callVerificationFailedCallback(suffix, policy);
    policies[suffix] = policy;
  }

  return policies;
}

Verifier::PolicyMap Verifier::verifyHashes(const SuffixMap &packet_map,
                                           const SuffixMap &suffix_map) {
  PolicyMap policies;

  for (const auto &packet_hash : packet_map) {
    VerificationPolicy policy = VerificationPolicy::UNKNOWN;
    auto manifest_hash = suffix_map.find(packet_hash.first);

    if (manifest_hash != suffix_map.end()) {
      policy = VerificationPolicy::ABORT;

      if (packet_hash.second == manifest_hash->second) {
        policy = VerificationPolicy::ACCEPT;
      }
    }

    callVerificationFailedCallback(packet_hash.first, policy);
    policies[packet_hash.first] = policy;
  }

  return policies;
}

Verifier::PolicyMap Verifier::verifyPackets(
    const std::vector<PacketPtr> &packets, const SuffixMap &suffix_map) {
  PolicyMap policies;

  for (const auto &packet : packets) {
    Suffix suffix = packet->getName().getSuffix();
    VerificationPolicy policy = VerificationPolicy::UNKNOWN;
    auto manifest_hash = suffix_map.find(suffix);

    if (manifest_hash != suffix_map.end()) {
      policy = VerificationPolicy::ABORT;
      CryptoHashType hash_type = manifest_hash->second.getType();
      CryptoHash packet_hash = packet->computeDigest(hash_type);

      if (packet_hash == manifest_hash->second) {
        policy = VerificationPolicy::ACCEPT;
      }
    }

    callVerificationFailedCallback(suffix, policy);
    policies[suffix] = policy;
  }

  return policies;
}

void Verifier::setVerificationFailedCallback(
    VerificationFailedCallback verfication_failed_cb,
    const std::vector<VerificationPolicy> &failed_policies) {
  verification_failed_cb_ = verfication_failed_cb;
  failed_policies_ = failed_policies;
}

void Verifier::getVerificationFailedCallback(
    VerificationFailedCallback **verfication_failed_cb) {
  *verfication_failed_cb = &verification_failed_cb_;
}

void Verifier::callVerificationFailedCallback(Suffix suffix,
                                              VerificationPolicy &policy) {
  if (verification_failed_cb_ == interface::VOID_HANDLER) {
    return;
  }

  if (find(failed_policies_.begin(), failed_policies_.end(), policy) !=
      failed_policies_.end()) {
    policy = verification_failed_cb_(suffix, policy);
  }
}

// ---------------------------------------------------------
// Void Verifier
// ---------------------------------------------------------
bool VoidVerifier::verifyPacket(PacketPtr packet) { return true; }

bool VoidVerifier::verifyBuffer(const std::vector<uint8_t> &buffer,
                                const utils::MemBuf::Ptr &signature,
                                CryptoHashType hash_type) {
  return true;
}

bool VoidVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                const utils::MemBuf::Ptr &signature,
                                CryptoHashType hash_type) {
  return true;
}

Verifier::PolicyMap VoidVerifier::verifyPackets(
    const std::vector<PacketPtr> &packets) {
  PolicyMap policies;

  for (const auto &packet : packets) {
    auth::Suffix suffix = packet->getName().getSuffix();
    VerificationPolicy policy = VerificationPolicy::ACCEPT;
    callVerificationFailedCallback(suffix, policy);
    policies[suffix] = policy;
  }

  return policies;
}

Verifier::PolicyMap VoidVerifier::verifyPackets(
    const std::vector<PacketPtr> &packets, const SuffixMap &suffix_map) {
  return verifyPackets(packets);
}

// ---------------------------------------------------------
// Asymmetric Verifier
// ---------------------------------------------------------
AsymmetricVerifier::AsymmetricVerifier(std::shared_ptr<EVP_PKEY> key) {
  setKey(key);
}

AsymmetricVerifier::AsymmetricVerifier(const std::string &cert_path) {
  useCertificate(cert_path);
}

AsymmetricVerifier::AsymmetricVerifier(std::shared_ptr<X509> cert) {
  useCertificate(cert);
}

void AsymmetricVerifier::setKey(std::shared_ptr<EVP_PKEY> key) { key_ = key; };

void AsymmetricVerifier::useCertificate(const std::string &cert_path) {
  FILE *certf = fopen(cert_path.c_str(), "rb");

  if (certf == nullptr) {
    throw errors::RuntimeException("Certificate not found");
  }

  std::shared_ptr<X509> cert = std::shared_ptr<X509>(
      PEM_read_X509(certf, nullptr, nullptr, nullptr), ::X509_free);
  useCertificate(cert);

  fclose(certf);
}

void AsymmetricVerifier::useCertificate(std::shared_ptr<X509> cert) {
  key_ =
      std::shared_ptr<EVP_PKEY>(X509_get_pubkey(cert.get()), ::EVP_PKEY_free);
}

bool AsymmetricVerifier::verifyBuffer(const std::vector<uint8_t> &buffer,
                                      const utils::MemBuf::Ptr &signature,
                                      CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  std::shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

  if (mdctx == nullptr) {
    throw errors::RuntimeException("Digest context allocation failed");
  }

  if (EVP_DigestVerifyInit(mdctx.get(), nullptr, (*hash_evp)(), nullptr,
                           key_.get()) != 1) {
    throw errors::RuntimeException("Digest initialization failed");
  }

  if (EVP_DigestVerifyUpdate(mdctx.get(), buffer.data(), buffer.size()) != 1) {
    throw errors::RuntimeException("Digest update failed");
  }

  return EVP_DigestVerifyFinal(mdctx.get(), signature->data(),
                               signature->length()) == 1;
}

bool AsymmetricVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                      const utils::MemBuf::Ptr &signature,
                                      CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  std::shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

  if (mdctx == nullptr) {
    throw errors::RuntimeException("Digest context allocation failed");
  }

  if (EVP_DigestVerifyInit(mdctx.get(), nullptr, (*hash_evp)(), nullptr,
                           key_.get()) != 1) {
    throw errors::RuntimeException("Digest initialization failed");
  }

  do {
    if (EVP_DigestVerifyUpdate(mdctx.get(), p->data(), p->length()) != 1) {
      throw errors::RuntimeException("Digest update failed");
    }

    p = p->next();
  } while (p != buffer);

  return EVP_DigestVerifyFinal(mdctx.get(), signature->data(),
                               signature->length()) == 1;
}

// ---------------------------------------------------------
// Symmetric Verifier
// ---------------------------------------------------------
SymmetricVerifier::SymmetricVerifier(const std::string &passphrase) {
  setPassphrase(passphrase);
}

// Create and set a symmetric key from a passphrase.
void SymmetricVerifier::setPassphrase(const std::string &passphrase) {
  key_ = std::shared_ptr<EVP_PKEY>(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                   (const unsigned char *)passphrase.c_str(),
                                   passphrase.size()),
      EVP_PKEY_free);
}

bool SymmetricVerifier::verifyBuffer(const std::vector<uint8_t> &buffer,
                                     const utils::MemBuf::Ptr &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf::Ptr &signature_bis =
      core::PacketManager<>::getInstance().getMemBuf();
  signature_bis->append(signature->length());
  size_t signature_bis_len;
  std::shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis->writableData(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature->length() == signature_bis_len &&
         *signature == *signature_bis;
}

bool SymmetricVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                     const utils::MemBuf::Ptr &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  const utils::MemBuf::Ptr &signature_bis =
      core::PacketManager<>::getInstance().getMemBuf();
  signature_bis->append(signature->length());
  size_t signature_bis_len;
  std::shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis->writableData(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature->length() == signature_bis_len &&
         *signature == *signature_bis;
}

}  // namespace auth
}  // namespace transport
