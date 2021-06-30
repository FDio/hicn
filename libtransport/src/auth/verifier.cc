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

using namespace std;

namespace transport {
namespace auth {

const vector<VerificationPolicy> Verifier::DEFAULT_FAILED_POLICIES = {
    VerificationPolicy::DROP,
    VerificationPolicy::ABORT,
};

// ---------------------------------------------------------
// Base Verifier
// ---------------------------------------------------------
Verifier::Verifier()
    : verification_failed_cb_(interface::VOID_HANDLER),
      failed_policies_(DEFAULT_FAILED_POLICIES) {}

bool Verifier::verifyPacket(PacketPtr packet) {
  core::Packet::Format format = packet->getFormat();

  if (!packet->authenticationHeader()) {
    throw errors::MalformedAHPacketException();
  }

  // Get crypto suite, hash type, signature length
  CryptoSuite suite = packet->getValidationAlgorithm();
  CryptoHashType hash_type = getHashType(suite);
  size_t signature_len = packet->getSignatureSizeReal();

  // Copy IP+TCP / ICMP header before zeroing them
  hicn_header_t header_copy;
  hicn_packet_copy_header(format, packet->packet_start_, &header_copy, false);
  packet->setSignatureSizeGap(0u);

  // Retrieve packet signature
  uint8_t *packet_signature = packet->getSignature();
  vector<uint8_t> signature_raw(packet_signature,
                                packet_signature + signature_len);

  // Reset fields that are not used to compute signature
  packet->resetForHash();

  // Check signatures
  bool valid_packet = verifyBuffer(static_cast<utils::MemBuf *>(packet),
                                   signature_raw, hash_type);

  // Restore header
  hicn_packet_copy_header(format, &header_copy, packet->packet_start_, false);
  packet->setSignatureSizeGap(packet->getSignatureSize() - signature_len);

  return valid_packet;
}

Verifier::PolicyMap Verifier::verifyPackets(const vector<PacketPtr> &packets) {
  PolicyMap policies;

  for (const auto &packet : packets) {
    Suffix suffix = packet->getName().getSuffix();
    VerificationPolicy policy = VerificationPolicy::ABORT;

    if (verifyPacket(packet)) {
      policy = VerificationPolicy::ACCEPT;
    }

    policies[suffix] = policy;
    callVerificationFailedCallback(packet, policy);
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

    policies[packet_hash.first] = policy;
  }

  return policies;
}

Verifier::PolicyMap Verifier::verifyPackets(const vector<PacketPtr> &packets,
                                            const SuffixMap &suffix_map) {
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

    policies[suffix] = policy;
    callVerificationFailedCallback(packet, policy);
  }

  return policies;
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

// ---------------------------------------------------------
// Void Verifier
// ---------------------------------------------------------
bool VoidVerifier::verifyPacket(PacketPtr packet) { return true; }

bool VoidVerifier::verifyBuffer(const vector<uint8_t> &buffer,
                                const vector<uint8_t> &signature,
                                CryptoHashType hash_type) {
  return true;
}

bool VoidVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                const vector<uint8_t> &signature,
                                CryptoHashType hash_type) {
  return true;
}

Verifier::PolicyMap VoidVerifier::verifyPackets(
    const vector<PacketPtr> &packets) {
  PolicyMap policies;

  for (const auto &packet : packets) {
    policies[packet->getName().getSuffix()] = VerificationPolicy::ACCEPT;
  }

  return policies;
}

Verifier::PolicyMap VoidVerifier::verifyPackets(
    const vector<PacketPtr> &packets, const SuffixMap &suffix_map) {
  return verifyPackets(packets);
}

// ---------------------------------------------------------
// Asymmetric Verifier
// ---------------------------------------------------------
AsymmetricVerifier::AsymmetricVerifier(shared_ptr<EVP_PKEY> key) {
  setKey(key);
}

AsymmetricVerifier::AsymmetricVerifier(const string &cert_path) {
  useCertificate(cert_path);
}

AsymmetricVerifier::AsymmetricVerifier(shared_ptr<X509> cert) {
  useCertificate(cert);
}

void AsymmetricVerifier::setKey(shared_ptr<EVP_PKEY> key) { key_ = key; };

void AsymmetricVerifier::useCertificate(const string &cert_path) {
  FILE *certf = fopen(cert_path.c_str(), "rb");

  if (certf == nullptr) {
    throw errors::RuntimeException("Certificate not found");
  }

  shared_ptr<X509> cert = shared_ptr<X509>(
      PEM_read_X509(certf, nullptr, nullptr, nullptr), ::X509_free);
  useCertificate(cert);

  fclose(certf);
}

void AsymmetricVerifier::useCertificate(shared_ptr<X509> cert) {
  key_ = shared_ptr<EVP_PKEY>(X509_get_pubkey(cert.get()), ::EVP_PKEY_free);
}

bool AsymmetricVerifier::verifyBuffer(const vector<uint8_t> &buffer,
                                      const vector<uint8_t> &signature,
                                      CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

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
                                      const vector<uint8_t> &signature,
                                      CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  shared_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);

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
SymmetricVerifier::SymmetricVerifier(const string &passphrase) {
  setPassphrase(passphrase);
}

// Create and set a symmetric key from a passphrase.
void SymmetricVerifier::setPassphrase(const string &passphrase) {
  key_ = shared_ptr<EVP_PKEY>(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                   (const unsigned char *)passphrase.c_str(),
                                   passphrase.size()),
      EVP_PKEY_free);
}

bool SymmetricVerifier::verifyBuffer(const vector<uint8_t> &buffer,
                                     const vector<uint8_t> &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  vector<uint8_t> signature_bis(signature.size());
  size_t signature_bis_len;
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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis.data(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature == signature_bis && signature.size() == signature_bis_len;
}

bool SymmetricVerifier::verifyBuffer(const utils::MemBuf *buffer,
                                     const vector<uint8_t> &signature,
                                     CryptoHashType hash_type) {
  CryptoHashEVP hash_evp = CryptoHash::getEVP(hash_type);

  if (hash_evp == nullptr) {
    throw errors::RuntimeException("Unknown hash type");
  }

  const utils::MemBuf *p = buffer;
  vector<uint8_t> signature_bis(signature.size());
  size_t signature_bis_len;
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

  if (EVP_DigestSignFinal(mdctx.get(), signature_bis.data(),
                          &signature_bis_len) != 1) {
    throw errors::RuntimeException("Digest computation failed");
  }

  return signature == signature_bis && signature.size() == signature_bis_len;
}

}  // namespace auth
}  // namespace transport
