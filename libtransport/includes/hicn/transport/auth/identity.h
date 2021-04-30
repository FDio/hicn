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

#include <hicn/transport/auth/signer.h>

extern "C" {
#include <parc/security/parc_Identity.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/security/parc_Pkcs12KeyStore.h>
#include <parc/security/parc_Security.h>
};

namespace transport {
namespace auth {

class Identity {
  // This class holds several information about a client, including its public
  // key.
 public:
  // Generate a new identity from the given parameters. The identity will be
  // saved in 'keystore_path' and encrypted using 'keystore_pwd'.
  Identity(const std::string &keystore_path, const std::string &keystore_pwd,
           CryptoSuite suite, unsigned int signature_len,
           unsigned int validity_days, const std::string &subject_name);

  // Create an identity from an already existing keystore path.
  Identity(std::string &keystore_path, std::string &keystore_pwd,
           CryptoHashType hash_type);

  Identity(const Identity &other);
  Identity(Identity &&other);
  ~Identity();

  // Return the asymmetric signer object created from the public key.
  std::shared_ptr<AsymmetricSigner> getSigner() const;

  // Return the key store filename.
  std::string getFilename() const;

  // Return the key store password.
  std::string getPassword() const;

  // Generate a new random identity.
  static Identity generateIdentity(const std::string &subject_name = "");

 private:
  PARCIdentity *identity_;
  std::shared_ptr<AsymmetricSigner> signer_;
};

}  // namespace auth
}  // namespace transport
