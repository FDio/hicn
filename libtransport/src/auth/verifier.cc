/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
  core::Packet::Format format = packet->getFormat();

  if (!packet->hasAH()) {
    throw errors::MalformedAHPacketException();
  }

  // Get crypto suite, hash type, signature length
  CryptoSuite suite = packet->getValidationAlgorithm();
  CryptoHashType hash_type = getHashType(suite);

  // Copy IP+TCP / ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, packet->packet_start_, &header_copy, false);

  // Retrieve packet signature
  std::vector<uint8_t> signature_raw = packet->getSignature();
  signature_raw.resize(packet->getSignatureSize());

  // Reset fields that are not used to compute signature
  packet->resetForHash();

  // Check signatures
  bool valid_packet = verifyBuffer(static_cast<utils::MemBuf *>(packet),
                                   signature_raw, hash_type);

  // Restore header
  hicn_packet_copy_header(format, &header_copy, packet->packet_start_, false);
  packet->setSignature(signature_raw);
  packet->setSignatureSize(signature_raw.size());

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
                                const std::vector<uint8_t> &signature,
                                CryptoHashType hash_type) {
  return true;
}

bool VoidVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                const std::vector<uint8_t> &signature,
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
                                      const std::vector<uint8_t> &signature,
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

  return EVP_DigestVerifyFinal(mdctx.get(), signature.data(),
                               signature.size()) == 1;
}

bool AsymmetricVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                      const std::vector<uint8_t> &signature,
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

  return EVP_DigestVerifyFinal(mdctx.get(), signature.data(),
                               signature.size()) == 1;
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
                                     const std::vector<uint8_t> &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  std::vector<uint8_t> signature_bis(signature.size());
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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis.data(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature == signature_bis && signature.size() == signature_bis_len;
}

bool SymmetricVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                     const std::vector<uint8_t> &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  std::vector<uint8_t> signature_bis(signature.size());
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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis.data(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature == signature_bis && signature.size() == signature_bis_len;
}

}  // namespace auth
}  // namespace transport
