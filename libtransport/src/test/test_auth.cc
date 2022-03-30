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
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/content_object.h>
#include <openssl/rand.h>

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)>;
using DSA_ptr = std::unique_ptr<DSA, decltype(&::DSA_free)>;

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
  // Create the RSA keys
  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);
  std::shared_ptr<EVP_PKEY> pubKey(EVP_PKEY_new(), EVP_PKEY_free);
  RSA_ptr rsa(RSA_new(), ::RSA_free);
  BN_ptr pub_exp(BN_new(), ::BN_free);

  BN_set_word(pub_exp.get(), RSA_F4);
  if (1 != RSA_generate_key_ex(rsa.get(), 2048u, pub_exp.get(), NULL))
    throw errors::RuntimeException("can't generate the key");
  RSA_ptr rsa_pub(RSAPublicKey_dup(rsa.get()), ::RSA_free);
  RSA_ptr rsa_priv(RSAPrivateKey_dup(rsa.get()), ::RSA_free);
  if (1 != EVP_PKEY_set1_RSA(pubKey.get(), rsa_pub.get()))
    throw errors::RuntimeException("can't generate the key");
  if (1 != EVP_PKEY_set1_RSA(privateKey.get(), rsa_priv.get()))
    throw errors::RuntimeException("can't generate the key");
  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::RSA_SHA256, privateKey, pubKey);

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);

  // Sign the packet
  signer->signPacket(&packet);

  // Create the RSA verifier
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(pubKey);

  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
  EXPECT_EQ(signer->getSuite(), CryptoSuite::RSA_SHA256);
  EXPECT_EQ(signer->getSignatureSize(), 256u);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, AsymmetricBufferRSA) {
  // Create the RSA keys
  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);
  std::shared_ptr<EVP_PKEY> pubKey(EVP_PKEY_new(), EVP_PKEY_free);
  RSA_ptr rsa(RSA_new(), ::RSA_free);
  BN_ptr pub_exp(BN_new(), ::BN_free);

  BN_set_word(pub_exp.get(), RSA_F4);
  if (1 != RSA_generate_key_ex(rsa.get(), 2048u, pub_exp.get(), NULL))
    throw errors::RuntimeException("can't generate the key");
  RSA_ptr rsa_pub(RSAPublicKey_dup(rsa.get()), ::RSA_free);
  RSA_ptr rsa_priv(RSAPrivateKey_dup(rsa.get()), ::RSA_free);
  if (1 != EVP_PKEY_set1_RSA(pubKey.get(), rsa_pub.get()))
    throw errors::RuntimeException("can't generate the key");
  if (1 != EVP_PKEY_set1_RSA(privateKey.get(), rsa_priv.get()))
    throw errors::RuntimeException("can't generate the key");
  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::RSA_SHA256, privateKey, pubKey);

  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<AsymmetricVerifier> verif =
      std::make_shared<AsymmetricVerifier>(pubKey);
  bool res = verif->verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, AsymmetricBufferDSA) {
  // Create the DSA keys

  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);

  DSA_ptr dsa(DSA_new(), ::DSA_free);
  unsigned char buf[32];
  if (RAND_bytes(buf, sizeof(buf)) != 1) {
    throw errors::RuntimeException("can't generate the key");
  }
  if (DSA_generate_parameters_ex(dsa.get(), 1024u, buf, sizeof(buf), NULL, NULL,
                                 NULL) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (DSA_generate_key(dsa.get()) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (EVP_PKEY_set1_DSA(privateKey.get(), dsa.get()) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (1 != EVP_PKEY_set1_DSA(privateKey.get(), dsa.get()))
    throw errors::RuntimeException("can't generate the key");

  std::shared_ptr<X509> cert(X509_new(), ::X509_free);
  X509_set_pubkey(cert.get(), privateKey.get());
  std::shared_ptr<EVP_PKEY> pubKey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::DSA_SHA256, privateKey, pubKey);

  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<AsymmetricVerifier> verif =
      std::make_shared<AsymmetricVerifier>(pubKey);
  bool res = verif->verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}

TEST_F(AuthTest, AsymmetricVerifierDSA) {
  // Create the DSA keys
  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);

  DSA_ptr dsa(DSA_new(), ::DSA_free);
  unsigned char buf[32];
  if (RAND_bytes(buf, sizeof(buf)) != 1) {
    throw errors::RuntimeException("can't generate the key");
  }
  if (DSA_generate_parameters_ex(dsa.get(), 1024u, buf, sizeof(buf), NULL, NULL,
                                 NULL) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (DSA_generate_key(dsa.get()) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (EVP_PKEY_set1_DSA(privateKey.get(), dsa.get()) != 1)
    throw errors::RuntimeException("can't generate the key");
  if (1 != EVP_PKEY_set1_DSA(privateKey.get(), dsa.get()))
    throw errors::RuntimeException("can't generate the key");

  std::shared_ptr<X509> cert(X509_new(), ::X509_free);
  X509_set_pubkey(cert.get(), privateKey.get());
  std::shared_ptr<EVP_PKEY> pubKey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::DSA_SHA256, privateKey, pubKey);

  // Create a content object
  core::ContentObject packet(HF_INET6_TCP_AH, signer->getSignatureSize());

  // Fill it with bogus data
  uint8_t buffer[256] = {0};
  packet.appendPayload(buffer, 256);
  // this test has to be done before the signature is compute
  // EXPECT_EQ(signer->getSignatureSize(), 256u);
  signer->signPacket(&packet);
  std::shared_ptr<Verifier> verifier =
      std::make_shared<AsymmetricVerifier>(cert);

  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP_AH);
  EXPECT_EQ(signer->getHashType(), CryptoHashType::SHA256);
  EXPECT_EQ(signer->getSuite(), CryptoSuite::DSA_SHA256);
  EXPECT_EQ(verifier->verifyPackets(&packet), VerificationPolicy::ACCEPT);
}

TEST_F(AuthTest, AsymmetricBufferECDSA) {
  // Create the ECDSA keys
  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);
  std::shared_ptr<EVP_PKEY> pubKey(EVP_PKEY_new(), EVP_PKEY_free);
  EC_KEY_ptr ec_priv(EC_KEY_new_by_curve_name(NID_secp256k1), ::EC_KEY_free);
  EC_KEY_ptr ec_pub(EC_KEY_new(), ::EC_KEY_free);
  EC_KEY_set_asn1_flag(ec_priv.get(), OPENSSL_EC_NAMED_CURVE);
  if (EC_KEY_generate_key(ec_priv.get()) == 0)
    throw errors::RuntimeException("can't generate the ecdsa key");
  if (1 != EVP_PKEY_set1_EC_KEY(privateKey.get(), ec_priv.get()))
    throw errors::RuntimeException("can't generate the key");
  EC_KEY_set_group(ec_pub.get(), EC_KEY_get0_group(ec_priv.get()));
  EC_KEY_set_public_key(ec_pub.get(), EC_KEY_get0_public_key(ec_priv.get()));
  if (1 != EVP_PKEY_set1_EC_KEY(pubKey.get(), ec_pub.get()))
    throw errors::RuntimeException("can't generate the key");

  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::ECDSA_SHA256, privateKey, pubKey);

  std::string payload = "bonjour";

  std::vector<uint8_t> buffer(payload.begin(), payload.end());
  signer->signBuffer(buffer);
  std::vector<uint8_t> sig = signer->getSignature();

  std::shared_ptr<AsymmetricVerifier> verif =
      std::make_shared<AsymmetricVerifier>(pubKey);
  bool res = verif->verifyBuffer(
      buffer, std::vector<uint8_t>(sig.data(), sig.data() + sig.size()),
      CryptoHashType::SHA256);
  EXPECT_EQ(res, true);
}  // namespace auth

TEST_F(AuthTest, AsymmetricVerifierECDSA) {
  // Create the ECDSA keys
  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);
  std::shared_ptr<EVP_PKEY> pubKey(EVP_PKEY_new(), EVP_PKEY_free);
  EC_KEY_ptr ec_priv(EC_KEY_new_by_curve_name(NID_secp256k1), ::EC_KEY_free);
  EC_KEY_ptr ec_pub(EC_KEY_new(), ::EC_KEY_free);
  EC_KEY_set_asn1_flag(ec_priv.get(), OPENSSL_EC_NAMED_CURVE);
  if (EC_KEY_generate_key(ec_priv.get()) == 0)
    throw errors::RuntimeException("can't generate the ecdsa key");
  if (1 != EVP_PKEY_set1_EC_KEY(privateKey.get(), ec_priv.get()))
    throw errors::RuntimeException("can't generate the key");
  EC_KEY_set_group(ec_pub.get(), EC_KEY_get0_group(ec_priv.get()));
  EC_KEY_set_public_key(ec_pub.get(), EC_KEY_get0_public_key(ec_priv.get()));
  if (1 != EVP_PKEY_set1_EC_KEY(pubKey.get(), ec_pub.get()))
    throw errors::RuntimeException("can't generate the key");

  std::shared_ptr<AsymmetricSigner> signer = std::make_shared<AsymmetricSigner>(
      CryptoSuite::ECDSA_SHA256, privateKey, pubKey);

  std::shared_ptr<AsymmetricVerifier> verifier =
      std::make_shared<AsymmetricVerifier>(pubKey);
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
