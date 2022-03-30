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

#pragma once

#include <hicn/transport/auth/common.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/auth/crypto_suite.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/membuf.h>

#include <memory>
extern "C" {
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
}

namespace transport {
namespace auth {

class Signer {
  // The base class from which all signer classes derive.

 public:
  Signer();

  virtual ~Signer();

  // Sign a packet.
  virtual void signPacket(PacketPtr packet);
  virtual void signBuffer(const std::vector<uint8_t> &buffer);
  virtual void signBuffer(const utils::MemBuf *buffer);

  // Return the signature.
  std::vector<uint8_t> getSignature() const;

  // Return the signature as a string
  std::string getStringSignature() const;

  // Return the signature size in bytes.
  virtual std::size_t getSignatureSize() const;

  // Return the field size necessary to hold the signature. The field size is
  // always a multiple of 4. Use this function when allocating the signature
  // packet header.
  virtual std::size_t getSignatureFieldSize() const;

  // Return the crypto suite associated to the signer.
  CryptoSuite getSuite() const;

  // Return the hash algorithm associated to the signer.
  CryptoHashType getHashType() const;

  // Print signature to stdout
  void display();

 protected:
  CryptoSuite suite_;
  std::vector<uint8_t> signature_;
  std::size_t signature_len_;
  std::shared_ptr<EVP_PKEY> key_;
  CryptoHash key_id_;
};

class VoidSigner : public Signer {
  // This class is the default socket signer. It does not sign packet.
 public:
  VoidSigner() = default;

  void signPacket(PacketPtr packet) override;
  void signBuffer(const std::vector<uint8_t> &buffer) override;
  void signBuffer(const utils::MemBuf *buffer) override;
};

class AsymmetricSigner : public Signer {
  // This class uses asymmetric verification to sign packets.
 public:
  AsymmetricSigner() = default;

  // Create an AsymmetricSigner from a keystore file (.p12).
  AsymmetricSigner(std::string keystore_path, std::string password);

  // Construct an AsymmetricSigner from a key store and a given crypto
  // suite.
  AsymmetricSigner(CryptoSuite suite, std::shared_ptr<EVP_PKEY> key,
                   std::shared_ptr<EVP_PKEY> pub_key);

  void setKey(CryptoSuite suite, std::shared_ptr<EVP_PKEY> key,
              std::shared_ptr<EVP_PKEY> pub_key);

  std::size_t getSignatureFieldSize() const override;
};

class SymmetricSigner : public Signer {
  // This class uses symmetric verification to sign packets. The symmetric
  // key is derived from a passphrase.
 public:
  SymmetricSigner() = default;

  // Construct a SymmetricSigner from a passphrase and a given crypto suite.
  SymmetricSigner(CryptoSuite suite, const std::string &passphrase);
};

}  // namespace auth
}  // namespace transport
