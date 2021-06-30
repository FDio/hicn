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

// function needed to create the a certificate
static bool _addRandomSerial(X509 *cert) {
  unsigned long serial = 0;
  unsigned char serial_bytes[sizeof(serial)];

  // Construct random positive serial number.
  RAND_bytes(serial_bytes, sizeof(serial_bytes));
  serial_bytes[0] &= 0x7F;
  serial = 0;
  for (size_t i = 0; i < sizeof(serial_bytes); i++) {
    serial = (256 * serial) + serial_bytes[i];
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  return true;
}

static bool _addValidityPeriod(X509 *cert, size_t validityDays) {
  // Set the validity from now for the specified number of days.
  X509_gmtime_adj(X509_get_notBefore(cert), (long)0);
  X509_gmtime_adj(X509_get_notAfter(cert), (long)(60 * 60 * 24 * validityDays));
  return true;
}

static bool _addSubjectName(X509 *cert, const char *subjectname) {
  // Set up the simple subject name and issuer name for the certificate.
  X509_NAME *name = X509_get_subject_name(cert);

  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 (unsigned char *)subjectname, -1, -1, 0)) {
    if (X509_set_issuer_name(cert, name)) {
      return true;
    }
  }
  return false;
}
static bool _addCertificateExtensionWithContext(X509 *cert, int nid,
                                                const char *value) {
  X509_EXTENSION *extension;
  X509V3_CTX context;

  X509V3_set_ctx_nodb(&context);
  X509V3_set_ctx(&context, cert, cert, NULL, NULL, 0);
  extension = X509V3_EXT_conf_nid(NULL, &context, nid, value);
  if (extension == NULL) {
    return false;
  }
  X509_add_ext(cert, extension, -1);
  X509_EXTENSION_free(extension);
  return true;
}
static bool _addCertificateExtension(X509 *cert, int nid, const char *value) {
  X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
  if (extension == NULL) {
    return false;
  }
  X509_add_ext(cert, extension, -1);
  X509_EXTENSION_free(extension);
  return true;
}

static bool _addExtensions(X509 *cert) {
  // Add the necessary extensions.
  if (_addCertificateExtension(cert, NID_basic_constraints,
                               "critical,CA:FALSE") == true) {
    if (_addCertificateExtension(
            cert, NID_key_usage,
            "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,"
            "keyAgreement") == true) {
      if (_addCertificateExtension(cert, NID_ext_key_usage, "clientAuth") ==
          true) {
        return true;
      }
    }
  }
  return false;
}
static bool _addKeyIdentifier(X509 *cert) {
  unsigned char spkid[SHA256_DIGEST_LENGTH];
  char spkid_hex[1 + 2 * SHA256_DIGEST_LENGTH];
  if (ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(),
                       X509_get_X509_PUBKEY(cert), spkid, NULL)) {
    for (int i = 0; i < 32; i++) {
      snprintf(&spkid_hex[2 * i], 3, "%02X", (unsigned)spkid[i]);
    }
    if (_addCertificateExtension(cert, NID_subject_key_identifier, spkid_hex) ==
        true) {
      if (_addCertificateExtensionWithContext(
              cert, NID_authority_key_identifier, "keyid:always") == true) {
        return true;
      }
    }
  }
  return false;
}

namespace transport {
namespace auth {

Identity::Identity(const string &keystore_path, const string &keystore_pwd,
                   CryptoSuite suite, unsigned int signature_len,
                   unsigned int validity_days, const string &subject_name)
    : cert_(X509_new(), ::X509_free) {
  // create the file and complete it.
  // first we create the certificate

  // to create the cert we will need a private key

  std::shared_ptr<EVP_PKEY> privateKey(EVP_PKEY_new(), EVP_PKEY_free);

  if (suite == CryptoSuite::RSA_SHA512 || suite == CryptoSuite::RSA_SHA256) {
    RSA *rsa = RSA_new();
    BIGNUM *pub_exp;

    pub_exp = BN_new();

    BN_set_word(pub_exp, RSA_F4);
    if (1 != RSA_generate_key_ex(rsa, signature_len, pub_exp, NULL))
      throw errors::RuntimeException("can't generate the key");
    if (1 != EVP_PKEY_set1_RSA(privateKey.get(), rsa))
      throw errors::RuntimeException("can't generate the key");
  } else if (suite == CryptoSuite::ECDSA_SHA256) {
    int curve_params;
    switch (signature_len) {
      case 160u:
        curve_params = NID_secp160k1;
        break;
      case 192u:
        curve_params = NID_secp192k1;
        break;
      case 224u:
        curve_params = NID_secp224k1;
        break;
      case 256u:
        curve_params = NID_secp256k1;
        break;
      default:
        curve_params = -1;
        break;
    }
    if (curve_params == -1)
      throw errors::RuntimeException("can't generate the key");
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve_params);
    if (ec_key == NULL)
      throw errors::RuntimeException("can't create ecdsa key from curve");
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (EC_KEY_generate_key(ec_key) == 0)
      throw errors::RuntimeException("can't generate the ecdsa key");
    if (EVP_PKEY_set1_EC_KEY(privateKey.get(), ec_key) == 0)
      throw errors::RuntimeException("can't generate the ecdsa key");
  } else if (suite == CryptoSuite::DSA_SHA256) {
    DSA *dsa = DSA_new();
    unsigned char buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
      throw errors::RuntimeException("can't generate the key");
    }
    if (DSA_generate_parameters_ex(dsa, signature_len, buffer, sizeof(buffer),
                                   NULL, NULL, NULL) != 1)
      throw errors::RuntimeException("can't generate the key");
    if (DSA_generate_key(dsa) != 1)
      throw errors::RuntimeException("can't generate the key");
    if (EVP_PKEY_set1_DSA(privateKey.get(), dsa) != 1)
      throw errors::RuntimeException("can't generate the key");
  }
  bool success = true;
  success = success && (X509_set_version(cert_.get(), 2) == 1);  // 2 => X509v3
  success = success && _addRandomSerial(cert_.get());
  success = success && _addValidityPeriod(cert_.get(), validity_days);
  success = success && (X509_set_pubkey(cert_.get(), privateKey.get()) == 1);
  success = success && _addSubjectName(cert_.get(), subject_name.c_str());
  success = success && _addExtensions(cert_.get());
  success =
      success && (X509_sign(cert_.get(), privateKey.get(), EVP_sha256()) != 0);
  success = success && _addKeyIdentifier(cert_.get());
  if (!success) {
    throw errors::RuntimeException("error while creating the certificate");
  }
  // the certificate is created. We create the pkcs12 object to write the p12
  // file
  PKCS12 *p12 = PKCS12_create(
      keystore_pwd.c_str(), "ccnxuser", privateKey.get(), cert_.get(), NULL, 0,
      0, 0 /*default iter*/, PKCS12_DEFAULT_ITER /*mac_iter*/, 0);
  filename_ = keystore_path;
  int fp = open(filename_.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fp == -1) throw errors::RuntimeException("impossible to create the file");
  FILE *fp_f = fdopen(fp, "wb");
  if (fp_f == NULL)
    throw errors::RuntimeException("impossible to create the file");
  i2d_PKCS12_fp(fp_f, p12);
  fclose(fp_f);
  close(fp);
  std::shared_ptr<EVP_PKEY> publickey(X509_get_pubkey(cert_.get()),
                                      EVP_PKEY_free);
  signer_ = std::shared_ptr<AsymmetricSigner>(
      new AsymmetricSigner(suite, privateKey, publickey));
  signer_->signature_len_ = signature_len;
}

Identity::Identity(string &keystore_path, string &keystore_pwd,
                   CryptoHashType hash_type)
    : cert_(X509_new(), ::X509_free) {
  filename_ = keystore_path;
  pwd_ = keystore_path;
  // get the key and certificate by first opening the keystore file
  FILE *p12file = fopen(keystore_path.c_str(), "r");
  if (p12file == NULL)
    throw errors::RuntimeException("impossible open keystore");
  PKCS12 *p12 = d2i_PKCS12_fp(p12file, NULL);
  EVP_PKEY *privatekey;
  EVP_PKEY *publickey;
  X509 *cert = cert_.get();
  // now we parse the file to get the first key and certificate
  if (1 != PKCS12_parse(p12, keystore_pwd.c_str(), &privatekey, &cert, NULL))
    throw errors::RuntimeException("impossible to get the private key");
  publickey = X509_get_pubkey(cert);
  // to have the cryptosuite we use the nid number that is used to identify the
  // suite.
  CryptoSuite suite = getSuite(X509_get_signature_nid(cert));
  signer_ = std::shared_ptr<AsymmetricSigner>(new AsymmetricSigner(
      suite, std::shared_ptr<EVP_PKEY>(privatekey, EVP_PKEY_free),
      std::shared_ptr<EVP_PKEY>(publickey, EVP_PKEY_free)));
  PKCS12_free(p12);
}

Identity::Identity(const Identity &other) {
  pwd_ = other.pwd_;
  filename_ = other.filename_;
  signer_ = other.signer_;
  cert_ = other.cert_;
}

Identity::Identity(Identity &&other) {
  signer_ = std::move(other.signer_);
  other.signer_.reset();
  cert_ = std::move(other.cert_);
  other.cert_.reset();
  pwd_ = other.pwd_;
  other.pwd_ = "";
  filename_ = other.filename_;
  other.filename_ = "";
  signer_ = other.signer_;
  other.signer_ = nullptr;
}

Identity::~Identity() {}

shared_ptr<AsymmetricSigner> Identity::getSigner() const { return signer_; }

string Identity::getFilename() const { return filename_; }

std::shared_ptr<X509> Identity::getCertificate() const { return cert_; }
std::shared_ptr<EVP_PKEY> Identity::getPrivateKey() const {
  return signer_->key_;
}

string Identity::getPassword() const { return pwd_; }

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
