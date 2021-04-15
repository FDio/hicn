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
#include <hicn/transport/auth/crypto_hash_type.h>
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
  ASSERT_EQ(verifier->verifyPacket(&packet), true);
  ASSERT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, RSAVerifier) {
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
  PARCKey *key = parcSigner_CreatePublicKey(signer->getParcSigner());
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(key);

  ASSERT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  ASSERT_EQ(signer->getCryptoHashType(), CryptoHashType::SHA_256);
  ASSERT_EQ(signer->getCryptoSuite(), CryptoSuite::RSA_SHA256);
  ASSERT_EQ(signer->getSignatureSize(), 128u);
  ASSERT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);

  // Release PARC objects
  parcKey_Release(&key);
}

TEST_F(AuthTest, HMACVerifier) {
  // Create the HMAC signer from a passphrase
  std::shared_ptr<Signer> signer =
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

  ASSERT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  ASSERT_EQ(signer->getCryptoHashType(), CryptoHashType::SHA_256);
  ASSERT_EQ(signer->getCryptoSuite(), CryptoSuite::HMAC_SHA256);
  ASSERT_EQ(signer->getSignatureSize(), 32u);
  ASSERT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

}  // namespace auth
}  // namespace transport
