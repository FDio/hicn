/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <hicn/transport/core/packet.h>

extern "C" {
#include <parc/security/parc_CryptoHashType.h>
#include <parc/security/parc_CryptoSuite.h>
#include <parc/security/parc_KeyStore.h>
#include <parc/security/parc_Signer.h>
#include <parc/security/parc_SymmetricKeySigner.h>
}

namespace utils {

using Packet = transport::core::Packet;

/**
 * A signer can use a single key (asymmetric or symmetric) to sign a packet.
 */
class Signer {
  friend class Identity;

 public:
  /**
   * Create a Signer
   *
   * @param keyStore A keystore containing a private key or simmetric key to
   * use to sign packet with this Signer.
   * @param suite CryptoSuite to use to verify the signature
   */
  Signer(PARCKeyStore *keyStore, CryptoSuite suite);

  /**
   * Create a Signer
   *
   * @param passphrase A string from which the symmetric key will be derived
   * @param suite CryptoSuite to use to verify the signature
   */
  Signer(const std::string &passphrase, CryptoSuite suite);

  Signer(const PARCSigner *signer, CryptoSuite suite);

  Signer(const PARCSigner *signer);

  ~Signer();

  /**
   * @brief Sign a packet
   *
   * This method is general and must be used for Public-private key signature,
   * HMAC and CRC.
   *
   * @param packet A pointer to the header of the packet to sign. Mutable
   * field in the packet must be set to 0.
   * @param key_id Indentifier of the key to use to generate the signature.
   */
  void sign(Packet &packet);

  size_t getSignatureLength();

  PARCKeyStore *getKeyStore();

 private:
  PARCBufferComposer *composer_ = nullptr;
  PARCBuffer *key_buffer_ = nullptr;
  PARCSymmetricKeyStore *symmetricKeyStore_ = nullptr;
  PARCSigner *signer_ = nullptr;
  PARCSignature *signature_ = nullptr;
  PARCKeyId *key_id_ = nullptr;
  CryptoSuite suite_;
  size_t signature_length_;
  static uint8_t zeros[200];
};

}  // namespace utils
