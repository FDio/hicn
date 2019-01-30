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
#include <parc/security/parc_KeyId.h>
#include <parc/security/parc_Verifier.h>
}

namespace utils {

using Packet = transport::core::Packet;

/**
 * A verifier holds a crypto cache that contains all the keys to use for
 * verify signatures/hmacs.
 */
class Verifier {
 public:
  Verifier();

  ~Verifier();

  /**
   * @brief Check if a key is already in this Verifier.
   *
   * A PARCVerifier contains a CryptoCache with a set of key to use for
   * verification purposes.
   *
   * @param keyId Identifier of the key to match in the CryptoCache of the
   * Verifier.
   * @return true if the key is found, false otherwise.
   */
  bool hasKey(PARCKeyId *keyId);

  /**
   * @brief Add a key to this Verifier
   *
   * @param key to add
   * @return true if the key was added successfully, false otherwise.
   */
  bool addKey(PARCKey *key);

  PARCKeyId *addKeyFromCertificate(const std::string &file_name);

  /**
   * @brief Verify a Signature
   *
   * This method is general and must be used for Public-private key signature,
   * HMAC and CRC.
   *
   * @param signature A pointer to the buffer holding the signature
   * @param sign_len Lenght of the signature (must be consistent with the type
   * of the key)
   * @param bufferSigned A pointer to the packet header signed with
   * signature. Mutable fields and the signature field in the packet must be
   * set to 0
   * @param buf_len Lenght of bufferSigned
   * @param suite CryptoSuite to use to verify the signature
   * @param key_id Indentifier of the key to use to verify the signature. The
   * key must be already present in the Verifier.
   */
  int verify(const Packet &packet);

 private:
  PARCVerifier *verifier_;
  static uint8_t zeros[200];
};

}  // namespace utils
