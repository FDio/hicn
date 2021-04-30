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

#include <algorithm>

extern "C" {
#include <parc/security/parc_CertificateFactory.h>
#include <parc/security/parc_InMemoryVerifier.h>
#include <parc/security/parc_Security.h>
#include <parc/security/parc_SymmetricKeySigner.h>
#include <parc/security/parc_Verifier.h>
}

namespace transport {
namespace auth {

class Verifier {
  // The base class from which all verifier classes derive.
 public:
  // The VerificationFailedCallback will be called by the transport if a data
  // packet (either a manifest or a content object) cannot be verified. The
  // application decides what to do then by returning a VerificationPolicy
  // object.
  using VerificationFailedCallback = std::function<auth::VerificationPolicy(
      const core::ContentObject &content_object, std::error_code ec)>;

  // The list of VerificationPolicy that will trigger the
  // VerificationFailedCallback.
  static const std::vector<VerificationPolicy> DEFAULT_FAILED_POLICIES;

  Verifier();

  virtual ~Verifier();

  // Verify a single packet and return whether or not the packet signature is
  // valid.
  virtual bool verifyPacket(PacketPtr packet);

  // Verify a batch of packets. Return a vector with the same size as the packet
  // list, element i of that vector will contain the VerificationPolicy for
  // packet i.
  virtual std::vector<VerificationPolicy> verifyPackets(
      const std::vector<PacketPtr> &packets);
  VerificationPolicy verifyPackets(PacketPtr packet) {
    return verifyPackets(std::vector<PacketPtr>{packet}).front();
  }

  // Verify that a batch of packets are valid using a map from packet suffixes
  // to hashes. A packet is considered valid if its hash correspond to the hash
  // present in the map. Return a vector with the same size as the packet list,
  // element i of that vector will contain the VerificationPolicy for packet i.
  virtual std::vector<VerificationPolicy> verifyPackets(
      const std::vector<PacketPtr> &packets,
      const std::unordered_map<Suffix, HashEntry> &suffix_map);
  VerificationPolicy verifyPackets(
      PacketPtr packet,
      const std::unordered_map<Suffix, HashEntry> &suffix_map) {
    return verifyPackets(std::vector<PacketPtr>{packet}, suffix_map).front();
  }

  // Add a general PARC key which can be used to verify packet signatures.
  void addKey(PARCKey *key);

  // Set the hasher object used to compute packet hashes.
  void setHasher(PARCCryptoHasher *hasher);

  // Set the callback for the case packet verification fails.
  void setVerificationFailedCallback(
      VerificationFailedCallback verification_failed_cb,
      const std::vector<VerificationPolicy> &failed_policies =
          DEFAULT_FAILED_POLICIES);

  // Retrieve the VerificationFailedCallback function.
  void getVerificationFailedCallback(
      VerificationFailedCallback **verification_failed_cb);

  static size_t getSignatureSize(const PacketPtr);

 protected:
  PARCCryptoHasher *hasher_;
  PARCVerifier *verifier_;
  VerificationFailedCallback verification_failed_cb_;
  std::vector<VerificationPolicy> failed_policies_;

  // Internally compute a packet hash using the hasher object.
  virtual CryptoHash computeHash(PacketPtr packet);

  // Call VerificationFailedCallback if it is set and update the packet policy.
  void callVerificationFailedCallback(PacketPtr packet,
                                      VerificationPolicy &policy);
};

class VoidVerifier : public Verifier {
  // This class is the default socket verifier. It ignores completely the packet
  // signature and always returns true.
 public:
  bool verifyPacket(PacketPtr packet) override;

  std::vector<VerificationPolicy> verifyPackets(
      const std::vector<PacketPtr> &packets) override;

  std::vector<VerificationPolicy> verifyPackets(
      const std::vector<PacketPtr> &packets,
      const std::unordered_map<Suffix, HashEntry> &suffix_map) override;
};

class AsymmetricVerifier : public Verifier {
  // This class uses asymmetric verification to validate packets. The public key
  // can be set directly or extracted from a certificate.
 public:
  AsymmetricVerifier() = default;

  // Add a public key to the verifier.
  AsymmetricVerifier(PARCKey *pub_key);

  // Construct an AsymmetricVerifier from a certificate file.
  AsymmetricVerifier(const std::string &cert_path);

  // Extract the public key of a certificate file.
  void setCertificate(const std::string &cert_path);
};

class SymmetricVerifier : public Verifier {
  // This class uses symmetric verification to validate packets. The symmetric
  // key is derived from a passphrase.
 public:
  SymmetricVerifier() = default;

  // Construct a SymmetricVerifier from a passphrase.
  SymmetricVerifier(const std::string &passphrase);

  ~SymmetricVerifier();

  // Create and set a symmetric key from a passphrase.
  void setPassphrase(const std::string &passphrase);

  // Construct a signer object. Passphrase must be set beforehand.
  void setSigner(const PARCCryptoSuite &suite);

  virtual std::vector<VerificationPolicy> verifyPackets(
      const std::vector<PacketPtr> &packets) override;

 protected:
  PARCBuffer *passphrase_;
  PARCSigner *signer_;
};

}  // namespace auth
}  // namespace transport
