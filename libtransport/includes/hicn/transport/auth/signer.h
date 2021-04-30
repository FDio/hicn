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
#include <hicn/transport/errors/errors.h>

extern "C" {
#include <parc/security/parc_PublicKeySigner.h>
#include <parc/security/parc_Security.h>
#include <parc/security/parc_Signer.h>
#include <parc/security/parc_SymmetricKeySigner.h>
}

namespace transport {
namespace auth {

class Signer {
  // The base class from which all signer classes derive.
 public:
  Signer();

  Signer(PARCSigner *signer);

  virtual ~Signer();

  // Sign a packet.
  virtual void signPacket(PacketPtr packet);

  // Set the signer object used to sign packets.
  void setSigner(PARCSigner *signer);

  // Return the signature size.
  size_t getSignatureSize() const;

  // Return the crypto suite associated to the signer.
  CryptoSuite getCryptoSuite() const;

  // Return the hash algorithm associated to the signer.
  CryptoHashType getCryptoHashType() const;

  // Return the PARC signer.
  PARCSigner *getParcSigner() const;

  // Return the PARC key store containing the signer key.
  PARCKeyStore *getParcKeyStore() const;

 protected:
  PARCSigner *signer_;
  PARCKeyId *key_id_;
};

class AsymmetricSigner : public Signer {
  // This class uses asymmetric verification to sign packets. The public key
  // must be given from a PARCKeyStore.
 public:
  AsymmetricSigner() = default;
  AsymmetricSigner(PARCSigner *signer) : Signer(signer){};

  // Construct an AsymmetricSigner from a key store and a given crypto suite.
  AsymmetricSigner(CryptoSuite suite, PARCKeyStore *key_store);
};

class SymmetricSigner : public Signer {
  // This class uses symmetric verification to sign packets. The symmetric
  // key is derived from a passphrase.
 public:
  SymmetricSigner() = default;
  SymmetricSigner(PARCSigner *signer) : Signer(signer){};

  // Construct an SymmetricSigner from a key store and a given crypto suite.
  SymmetricSigner(CryptoSuite suite, PARCKeyStore *key_store);

  // Construct an AsymmetricSigner from a passphrase and a given crypto suite.
  SymmetricSigner(CryptoSuite suite, const std::string &passphrase);
};

}  // namespace auth
}  // namespace transport
