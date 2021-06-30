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

#include <gtest/gtest.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/auth/identity.h>
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/content_object.h>

namespace transport {
namespace auth {

namespace {
class AuthTest : public ::testing::Test {
 protected:
  const std::string PASSPHRASE = "hunter2";

  AuthTest() = default;
  ~AuthTest() {}
  void SetUp() override {}
  void TearDown() override {}
};
}  // namespace

TEST_F(AuthTest, VoidVerifier) {
  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH);

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);

  // Verify that VoidVerifier validates the packet
  std::shared_ptr<Verifier> verifier = std::make_shared<VoidVerifier>();
  EXPECT_EQ(verifier->verifyPacket(&packet), true);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, AsymmetricRSA) {
  // Create the RSA signer from an Identity object
  Identity identity("test_rsa.p12", PASSPHRASE, CryptoSuite::RSA_SHA256, 1024u,
                    30, "RSAVerifier");

  std::shared_ptr<Signer> signer = identity.getSigner();

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);

  // Sign the packet
  signer->signPacket(&packet);

  // Create the RSA verifier
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(identity.getCertificate());

  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
  EXPECT_EQ(signer->getSuite(), CryptoSuite::RSA_SHA256);
  EXPECT_EQ(signer->getSignatureSize(), 128u);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, AsymmetricBufferRSA) {
  // Create the RSA signer from an Identity object
  Identity identity("test_rsa.p12", PASSPHRASE, CryptoSuite::RSA_SHA256, 1024u,
                    30, "RSAVerifier");

  std::shared_ptr<AsymmetricSigner> signer = identity.getSigner();
  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<X509> cert = identity.getCertificate();
  AsymmetricVerifier verif(cert);
  bool res = verif.verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, AsymmetricBufferDSA) {
  // Create the DSA signer from an Identity object
  Identity identity("test_dsa.p12", PASSPHRASE, CryptoSuite::DSA_SHA256, 1024u,
                    30, "DSAVerifier");

  std::shared_ptr<AsymmetricSigner> signer = identity.getSigner();
  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<X509> cert = identity.getCertificate();
  AsymmetricVerifier verif(cert);
  bool res = verif.verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, AsymmetricVerifierDSA) {
  // Create the DSA signer from an Identity object
  Identity identity("test_dsa.p12", PASSPHRASE, CryptoSuite::DSA_SHA256, 1024u,
                    30, "DSAVerifier");

  std::shared_ptr<Signer> signer = identity.getSigner();

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);
  // this test has to be done before the signature is compute
  // EXPECT_EQ(signer->getSignatureSize(), 256u);
  signer->signPacket(&packet);
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(identity.getCertificate());

  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
  EXPECT_EQ(signer->getSuite(), CryptoSuite::DSA_SHA256);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, AsymmetricBufferECDSA) {
  // Create the ECDSA signer from an Identity object
  Identity identity("test_ecdsa.p12", PASSPHRASE, CryptoSuite::ECDSA_SHA256,
                    256u, 30, "ECDSAVerifier");

  std::shared_ptr<AsymmetricSigner> signer = identity.getSigner();
  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<X509> cert = identity.getCertificate();
  AsymmetricVerifier verif(cert);
  bool res = verif.verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, AsymmetricVerifierECDSA) {
  Identity identity("test_ecdsa.p12", PASSPHRASE, CryptoSuite::ECDSA_SHA256,
                    256u, 30, "ECDSAVerifier");

  std::shared_ptr<Signer> signer = identity.getSigner();
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(identity.getCertificate());
  // Create a content object
  for (int i = 0; i < 100; i++) {
    core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

    // Fill it with bogus data
    uint8_t buffer[256] = {0};
    packet.appendPayload(buffer, 256);
    signer->signPacket(&packet);

    EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
    EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
    EXPECT_EQ(signer->getSuite(), CryptoSuite::ECDSA_SHA256);
    EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
  }
}

TEST_F(AuthTest, HMACbuffer) {
  // Create the HMAC signer from a passphrase
  std::shared_ptr<Signer> signer =
      std::make_shared<SymmetricSigner>(CryptoSuite::HMAC_SHA256, PASSPHRASE);

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  std::string payload = "bonjour";
  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();
  SymmetricVerifier hmac(PASSPHRASE);
  bool res = hmac.verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, HMACVerifier) {
  // Create the HMAC signer from a passphrase
  std::shared_ptr<SymmetricSigner> signer =
      std::make_shared<SymmetricSigner>(CryptoSuite::HMAC_SHA256, PASSPHRASE);

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);

  // Sign the packet
  signer->signPacket(&packet);

  // Create the HMAC verifier
  std::shared_ptr<Verifier> verifier =
      std::make_shared<SymmetricVerifier>(PASSPHRASE);

  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
  EXPECT_EQ(signer->getSuite(), CryptoSuite::HMAC_SHA256);
  EXPECT_EQ(signer->getSignatureSize(), 32u);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

}  // namespace auth
}  // namespace transport
