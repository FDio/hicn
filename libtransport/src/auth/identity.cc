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

#include <hicn/transport/auth/identity.h>

using namespace std;

namespace transport {
namespace auth {

Identity::Identity(const string &keystore_path, const string &keystore_pwd,
                   CryptoSuite suite, unsigned int signature_len,
                   unsigned int validity_days, const string &subject_name)
    : identity_(nullptr), signer_(nullptr) {
  parcSecurity_Init();

  bool success = parcPkcs12KeyStore_CreateFile(
      keystore_path.c_str(), keystore_pwd.c_str(), subject_name.c_str(),
      parcCryptoSuite_GetSigningAlgorithm(static_cast<PARCCryptoSuite>(suite)),
      signature_len, validity_days);

  parcAssertTrue(
      success,
      "parcPkcs12KeyStore_CreateFile('%s', '%s', '%s', %d, %d, %d) failed.",
      keystore_path.c_str(), keystore_pwd.c_str(), subject_name.c_str(),
      static_cast<int>(suite), static_cast<int>(signature_len), validity_days);

  PARCIdentityFile *identity_file =
      parcIdentityFile_Create(keystore_path.c_str(), keystore_pwd.c_str());

  identity_ =
      parcIdentity_Create(identity_file, PARCIdentityFileAsPARCIdentity);

  PARCSigner *signer = parcIdentity_CreateSigner(
      identity_,
      parcCryptoSuite_GetCryptoHash(static_cast<PARCCryptoSuite>(suite)));

  signer_ = make_shared<AsymmetricSigner>(signer);

  parcSigner_Release(&signer);
  parcIdentityFile_Release(&identity_file);
}

Identity::Identity(string &keystore_path, string &keystore_pwd,
                   CryptoHashType hash_type)
    : identity_(nullptr), signer_(nullptr) {
  parcSecurity_Init();

  PARCIdentityFile *identity_file =
      parcIdentityFile_Create(keystore_path.c_str(), keystore_pwd.c_str());

  identity_ =
      parcIdentity_Create(identity_file, PARCIdentityFileAsPARCIdentity);

  PARCSigner *signer = parcIdentity_CreateSigner(
      identity_, static_cast<PARCCryptoHashType>(hash_type));

  signer_ = make_shared<AsymmetricSigner>(signer);

  parcSigner_Release(&signer);
  parcIdentityFile_Release(&identity_file);
}

Identity::Identity(const Identity &other)
    : identity_(nullptr), signer_(other.signer_) {
  parcSecurity_Init();
  identity_ = parcIdentity_Acquire(other.identity_);
}

Identity::Identity(Identity &&other)
    : identity_(nullptr), signer_(move(other.signer_)) {
  parcSecurity_Init();
  identity_ = parcIdentity_Acquire(other.identity_);
  parcIdentity_Release(&other.identity_);
}

Identity::~Identity() {
  if (identity_) parcIdentity_Release(&identity_);
  parcSecurity_Fini();
}

shared_ptr<AsymmetricSigner> Identity::getSigner() const { return signer_; }

string Identity::getFilename() const {
  return string(parcIdentity_GetFileName(identity_));
}

string Identity::getPassword() const {
  return string(parcIdentity_GetPassWord(identity_));
}

Identity Identity::generateIdentity(const string &subject_name) {
  string keystore_name = "keystore";
  string keystore_password = "password";
  size_t key_length = 1024;
  unsigned int validity_days = 30;
  CryptoSuite suite = CryptoSuite::RSA_SHA256;

  return Identity(keystore_name, keystore_password, suite,
                  (unsigned int)key_length, validity_days, subject_name);
}

}  // namespace auth
}  // namespace transport
