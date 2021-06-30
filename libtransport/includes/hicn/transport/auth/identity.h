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

#include <errno.h>
#include <fcntl.h>
#include <hicn/transport/auth/signer.h>
#include <unistd.h>

extern "C" {
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
}

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

  std::shared_ptr<X509> getCertificate() const;

  std::shared_ptr<EVP_PKEY> getPrivateKey() const;

  // Generate a new random identity.
  static Identity generateIdentity(const std::string &subject_name = "");

 private:
  static void free_key(EVP_PKEY *T) { EVP_PKEY_free(T); }

  std::string pwd_;
  std::string filename_;
  std::shared_ptr<AsymmetricSigner> signer_;
  std::shared_ptr<X509> cert_;
};

}  // namespace auth
}  // namespace transport
