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

#pragma once

#include <hicn/transport/auth/common.h>
#include <hicn/transport/auth/policies.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/interfaces/callbacks.h>

extern "C" {
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
}

namespace transport {
namespace auth {

class Verifier {
  // The base Verifier class.
 public:
  using SuffixMap = std::unordered_map<Suffix, CryptoHash>;
  using PolicyMap = std::unordered_map<Suffix, VerificationPolicy>;

  // The VerificationFailedCallback will be called by the transport if a
  // data packet (either a manifest or a content object) was not validated.
  // The application decides what to do then by returning a
  // VerificationPolicy object.
  using VerificationFailedCallback = std::function<auth::VerificationPolicy(
      const core::ContentObject &content_object, std::error_code ec)>;

  // The list of VerificationPolicy that will trigger the
  // VerificationFailedCallback.
  static const std::vector<VerificationPolicy> DEFAULT_FAILED_POLICIES;

  Verifier();

  virtual ~Verifier();

  // Verify a single packet or buffer.
  virtual bool verifyPacket(PacketPtr packet);
  virtual bool verifyBuffer(const std::vector<uint8_t> &buffer,
                            const std::vector<uint8_t> &signature,
                            CryptoHashType hash_type) = 0;
  virtual bool verifyBuffer(const utils::MemBuf *buffer,
                            const std::vector<uint8_t> &signature,
                            CryptoHashType hash_type) = 0;

  // Verify a batch of packets. Return a mapping from packet suffixes to their
  // VerificationPolicy.
  virtual PolicyMap verifyPackets(const std::vector<PacketPtr> &packets);
  VerificationPolicy verifyPackets(PacketPtr packet) {
    return verifyPackets(std::vector<PacketPtr>{packet})
        .at(packet->getName().getSuffix());
  }

  // Verify that a set of packet hashes are present in another set of hashes
  // that was extracted from manifests. Return a mapping from packet suffixes to
  // their VerificationPolicy.
  virtual PolicyMap verifyHashes(const SuffixMap &packet_map,
                                 const SuffixMap &suffix_map);

  // Verify that a batch of packets are valid using a map from packet suffixes
  // to hashes. A packet is considered valid if its hash is present in the map.
  // Return a mapping from packet suffixes to their VerificationPolicy.
  virtual PolicyMap verifyPackets(const std::vector<PacketPtr> &packets,
                                  const SuffixMap &suffix_map);
  VerificationPolicy verifyPackets(PacketPtr packet,
                                   const SuffixMap &suffix_map) {
    return verifyPackets(std::vector<PacketPtr>{packet}, suffix_map)
        .at(packet->getName().getSuffix());
  }

  // Set the callback called when packet verification fails.
  void setVerificationFailedCallback(
      VerificationFailedCallback verification_failed_cb,
      const std::vector<VerificationPolicy> &failed_policies =
          DEFAULT_FAILED_POLICIES);

  // Retrieve the VerificationFailedCallback function.
  void getVerificationFailedCallback(
      VerificationFailedCallback **verification_failed_cb);

 protected:
  VerificationFailedCallback verification_failed_cb_;
  std::vector<VerificationPolicy> failed_policies_;

  // Call VerificationFailedCallback if it is set and update the packet policy.
  void callVerificationFailedCallback(PacketPtr packet,
                                      VerificationPolicy &policy);
};

class VoidVerifier : public Verifier {
  // This class is the default socket verifier. It ignores any packet signature
  // and always returns true.
 public:
  bool verifyPacket(PacketPtr packet) override;
  bool verifyBuffer(const std::vector<uint8_t> &buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;
  bool verifyBuffer(const utils::MemBuf *buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;

  PolicyMap verifyPackets(const std::vector<PacketPtr> &packets) override;

  PolicyMap verifyPackets(const std::vector<PacketPtr> &packets,
                          const SuffixMap &suffix_map) override;
};

class AsymmetricVerifier : public Verifier {
  // This class uses asymmetric verification to validate packets. The public key
  // can be directly set or extracted from a certificate.
 public:
  AsymmetricVerifier() = default;

  // Construct an AsymmetricVerifier from an asymmetric key.
  AsymmetricVerifier(std::shared_ptr<EVP_PKEY> key);

  // Construct an AsymmetricVerifier from a certificate file.
  AsymmetricVerifier(const std::string &cert_path);
  AsymmetricVerifier(std::shared_ptr<X509> cert);

  // Set the asymmetric key.
  void setKey(std::shared_ptr<EVP_PKEY> key);

  // Extract the public key from a certificate.
  void useCertificate(const std::string &cert_path);
  void useCertificate(std::shared_ptr<X509> cert);

  bool verifyBuffer(const std::vector<uint8_t> &buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;
  bool verifyBuffer(const utils::MemBuf *buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;

 private:
  std::shared_ptr<EVP_PKEY> key_;
};

class SymmetricVerifier : public Verifier {
  // This class uses symmetric verification to validate packets. The symmetric
  // key is derived from a passphrase.
 public:
  SymmetricVerifier() = default;

  // Construct a SymmetricVerifier from a passphrase.
  SymmetricVerifier(const std::string &passphrase);

  // Create and set a symmetric key from a passphrase.
  void setPassphrase(const std::string &passphrase);

  bool verifyBuffer(const std::vector<uint8_t> &buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;
  bool verifyBuffer(const utils::MemBuf *buffer,
                    const std::vector<uint8_t> &signature,
                    CryptoHashType hash_type) override;

 protected:
  std::shared_ptr<EVP_PKEY> key_;
};

}  // namespace auth
}  // namespace transport
