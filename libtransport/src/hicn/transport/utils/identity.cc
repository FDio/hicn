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

#include <hicn/transport/utils/identity.h>

extern "C" {
#include <parc/security/parc_PublicKeySigner.h>
#include <parc/security/parc_Security.h>
}

namespace utils {

Identity::Identity(const std::string &keystore_name,
                   const std::string &keystore_password, CryptoSuite suite,
                   unsigned int key_length, unsigned int validity_days,
                   const std::string &subject_name) {
  parcSecurity_Init();

  bool success = parcPkcs12KeyStore_CreateFile(
      keystore_name.c_str(), keystore_password.c_str(), subject_name.c_str(),
      parcCryptoSuite_GetSigningAlgorithm(static_cast<PARCCryptoSuite>(suite)),
      key_length, validity_days);

  parcAssertTrue(
      success,
      "parcPkcs12KeyStore_CreateFile('%s', '%s', '%s', %d, %d) failed.",
      keystore_name.c_str(), keystore_password.c_str(), subject_name.c_str(),
      static_cast<int>(key_length), validity_days);

  PARCIdentityFile *identity_file =
      parcIdentityFile_Create(keystore_name.c_str(), keystore_password.c_str());

  identity_ =
      parcIdentity_Create(identity_file, PARCIdentityFileAsPARCIdentity);

  PARCSigner *signer = parcIdentity_CreateSigner(
      identity_,
      parcCryptoSuite_GetCryptoHash(static_cast<PARCCryptoSuite>(suite)));

  signer_ = std::make_shared<Signer>(signer, suite);

  parcSigner_Release(&signer);
  parcIdentityFile_Release(&identity_file);
}

Identity::Identity(const Identity &other)
    : signer_(other.signer_), hash_algorithm_(other.hash_algorithm_) {
  parcSecurity_Init();
  identity_ = parcIdentity_Acquire(other.identity_);
}

Identity Identity::generateIdentity(const std::string &subject_name) {
  std::string keystore_name = "keystore";
  std::string keystore_password = "password";
  std::size_t key_length = 1024;
  unsigned int validity_days = 30;
  CryptoSuite suite = CryptoSuite::RSA_SHA256;

  return utils::Identity(keystore_name, keystore_password, suite,
                         (unsigned int)key_length, validity_days, subject_name);
}

Identity::Identity(std::string &file_name, std::string &password,
                   transport::core::HashAlgorithm hash_algorithm)
    : hash_algorithm_(hash_algorithm) {
  parcSecurity_Init();

  PARCIdentityFile *identity_file =
      parcIdentityFile_Create(file_name.c_str(), password.c_str());

  identity_ =
      parcIdentity_Create(identity_file, PARCIdentityFileAsPARCIdentity);

  PARCSigner *signer = parcIdentity_CreateSigner(
      identity_, static_cast<PARCCryptoHashType>(hash_algorithm));

  signer_ = std::make_shared<Signer>(
      signer, CryptoSuite(parcSigner_GetCryptoSuite(signer)));

  parcSigner_Release(&signer);
  parcIdentityFile_Release(&identity_file);
}

Identity::~Identity() {
  parcIdentity_Release(&identity_);
  parcSecurity_Fini();
}

std::string Identity::getFileName() {
  return std::string(parcIdentity_GetFileName(identity_));
}

std::string Identity::getPassword() {
  return std::string(parcIdentity_GetPassWord(identity_));
}

std::shared_ptr<Signer> Identity::getSigner() { return signer_; }

size_t Identity::getSignatureLength() const {
  return signer_->getSignatureLength();
}

}  // namespace utils
