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

#include <hicn/transport/security/crypto_suite.h>
#include <hicn/transport/security/signer.h>

extern "C" {
#include <parc/security/parc_Identity.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/security/parc_Pkcs12KeyStore.h>
};

#include <string>

namespace utils {

class Identity {
 public:
  Identity(const std::string &keystore_name,
           const std::string &keystore_password, CryptoSuite suite,
           unsigned int signature_length, unsigned int validity_days,
           const std::string &subject_name);

  Identity(const Identity &other);

  Identity(std::string &file_name, std::string &password,
           utils::CryptoHashType hash_algorithm);

  ~Identity();

  static Identity generateIdentity(const std::string &subject_name);

  std::string getFileName();

  std::string getPassword();

  std::shared_ptr<Signer> getSigner();

  size_t getSignatureLength() const;

 private:
  PARCIdentity *identity_;
  std::shared_ptr<Signer> signer_;
  utils::CryptoHashType hash_algorithm_;
};

}  // namespace utils
