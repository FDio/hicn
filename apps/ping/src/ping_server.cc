/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <hicn/transport/interfaces/socket_producer.h>
#ifndef _WIN32
#include <hicn/transport/utils/daemonizator.h>
#include <unistd.h>
#else
#include <openssl/applink.c>
#endif

#include <glog/logging.h>
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/utils/string_tokenizer.h>

#include <asio.hpp>

namespace transport {

namespace interface {

using HashAlgorithm = core::HashAlgorithm;
using CryptoSuite = auth::CryptoSuite;

class CallbackContainer {
  const std::size_t log2_content_object_buffer_size = 12;

 private:
  std::shared_ptr<ContentObject> createContentObject(const Name &name,
                                                     uint32_t lifetime,
                                                     const Interest &interest) {
    auto &content_object = content_objects_[content_objects_index_++ & mask_];

    content_object->setName(name);
    content_object->setLifetime(lifetime);
    content_object->setLocator(interest.getLocator());
    content_object->setSrcPort(interest.getDstPort());
    content_object->setDstPort(interest.getSrcPort());
    content_object->setTTL(ttl_);

    if (VLOG_IS_ON(2)) {
      LOG(INFO) << ">>> send object " << content_object->getName()
                << " src port: " << content_object->getSrcPort()
                << " dst port: " << content_object->getDstPort()
                << " TTL: " << (int)content_object->getTTL();
    } else if (VLOG_IS_ON(1)) {
      LOG(INFO) << ">>> send object " << content_object->getName();
    }

    if (VLOG_IS_ON(3)) {
      LOG(INFO) << "----- object dump -----";
      content_object->dump();
      LOG(INFO) << "-----------------------";
    }

    if (sign_ && signer_) signer_->signPacket(content_object.get());
    return content_object;
  }

 public:
  CallbackContainer(const Name &prefix, uint32_t object_size, uint8_t ttl,
                    auth::Signer *signer, bool sign, std::string passphrase,
                    uint32_t lifetime)
      : buffer_(object_size, 'X'),
        content_objects_((std::uint32_t)(1 << log2_content_object_buffer_size)),
        mask_((std::uint16_t)(1 << log2_content_object_buffer_size) - 1),
        content_objects_index_(0),
        ttl_(ttl),
        signer_(signer),
        sign_(sign) {
    // Verifier for interest manifests
    if (!passphrase.empty())
      verifier_ = std::make_unique<auth::SymmetricVerifier>(passphrase);

    core::Packet::Format format;
    if (prefix.getAddressFamily() == AF_INET) {
      format = HICN_PACKET_FORMAT_IPV4_TCP;
      if (sign_) {
        format = HICN_PACKET_FORMAT_IPV4_TCP_AH;
      }
    } else {
      format = HICN_PACKET_FORMAT_IPV6_TCP;
      if (sign_) {
        format = HICN_PACKET_FORMAT_IPV6_TCP_AH;
      }
    }

    for (int i = 0; i < (1 << log2_content_object_buffer_size); i++) {
      content_objects_[i] = std::make_shared<ContentObject>(
          prefix, format, 0, (const uint8_t *)buffer_.data(), buffer_.size());
      content_objects_[i]->setLifetime(lifetime);
    }
  }

  void processInterest(ProducerSocket &p, Interest &interest,
                       uint32_t lifetime) {
    if (verifier_ && interest.hasManifest()) {
      auto t0 = utils::SteadyTime::now();
      if (verifier_->verifyPacket(&interest)) {
        auto t1 = utils::SteadyTime::now();
        auto dt = utils::SteadyTime::getDurationUs(t0, t1);
        LOG(INFO) << "Verification time: " << dt.count();
        LOG(INFO) << "<<< Signature Ok.";
      } else {
        LOG(ERROR) << "<<< Signature verification failed!";
      }
    }

    if (VLOG_IS_ON(2)) {
      LOG(INFO) << "<<< received interest " << interest.getName()
                << " src port: " << interest.getSrcPort()
                << " dst port: " << interest.getDstPort()
                << "TTL: " << (int)interest.getTTL()
                << " suffixes in manifest: " << interest.numberOfSuffixes();
    } else if (VLOG_IS_ON(1)) {
      LOG(INFO) << "<<< received interest " << interest.getName();
    }

    if (VLOG_IS_ON(3)) {
      LOG(INFO) << "----- interest dump -----";
      interest.dump();
      LOG(INFO) << "-------------------------";
    }

    if (!interest.isValid()) throw std::runtime_error("Bad interest format");
    Name name = interest.getName();

    if (!interest.hasManifest()) {  // Single interest
      auto content_object = createContentObject(name, lifetime, interest);
      p.produce(*content_object);
    } else {  // Interest manifest
      uint32_t _, *suffix = NULL;
      UNUSED(_);

      interest_manifest_foreach_suffix(interest.getIntManifestHeader(), suffix,
                                       _) {
        name.setSuffix(*suffix);

        auto content_object = createContentObject(name, lifetime, interest);
        p.produce(*content_object);
      }
    }

    VLOG(1) << "\n";
  }

 private:
  std::string buffer_;
  std::vector<std::shared_ptr<ContentObject>> content_objects_;
  std::uint16_t mask_;
  std::uint16_t content_objects_index_;
  uint8_t ttl_;
  auth::Signer *signer_;
  bool sign_;
  std::unique_ptr<auth::Verifier> verifier_;
};

void help() {
  LOG(INFO) << "usage: hicn-preoducer-ping [options]";
  LOG(INFO) << "PING options";
  LOG(INFO) << "-s <val>          object content size (default 1350B)";
  LOG(INFO) << "-n <val>          hicn name (default b001::/64)";
  LOG(INFO) << "-l                data lifetime";
  LOG(INFO) << "-t                set ttl (default 64)";
  LOG(INFO) << "OUTPUT options";
  LOG(INFO) << "-V                verbose, prints statistics about the "
               "messagges sent "
               "                  and received (default false)";
  LOG(INFO) << "-D                dump, dumps sent and received packets "
               "(default false)";
  LOG(INFO) << "-q                quiet, not prints (default false)";
  LOG(INFO) << "-z <io_module>    IO module to use. Default: hicnlight_module";
  LOG(INFO) << "-F <conf_file>    Path to optional configuration file for "
               "libtransport";
#ifndef _WIN32
  LOG(INFO) << "-d                daemon mode";
#endif
  LOG(INFO) << "-H                prints this message";
}

int main(int argc, char **argv) {
  transport::interface::global_config::GlobalConfigInterface global_conf;
#ifdef _WIN32
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
  bool daemon = false;
#endif
  std::string name_prefix = "b001::0/64";
  std::string delimiter = "/";
  uint32_t object_size = 1250;
  uint8_t ttl = 64;
  std::string keystore_path = "./rsa_crypto_material.p12";
  std::string keystore_password = "cisco";
  std::string passphrase = "";
  bool sign = false;
  uint32_t data_lifetime = default_values::content_object_expiry_time;

  std::string conf_file;
  transport::interface::global_config::IoModuleConfiguration io_config;
  io_config.name = "hicnlight_module";

  int opt;
#ifndef _WIN32
  while ((opt = getopt(argc, argv, "a:s:n:t:l:frdHk:p:z:F:")) != -1) {
#else
  while ((opt = getopt(argc, argv, "s:n:t:l:frHk:p:z:F:")) != -1) {
#endif
    switch (opt) {
      case 'a':
        passphrase = optarg;
        break;
      case 's':
        object_size = std::stoi(optarg);
        break;
      case 'n':
        name_prefix = optarg;
        break;
      case 't':
        ttl = (uint8_t)std::stoi(optarg);
        break;
      case 'l':
        data_lifetime = std::stoi(optarg);
        break;
#ifndef _WIN32
      case 'd':
        daemon = true;
        break;
#endif
      case 'k':
        keystore_path = optarg;
        sign = true;
        break;
      case 'p':
        keystore_password = optarg;
        break;
      case 'z':
        io_config.name = optarg;
        break;
      case 'F':
        conf_file = optarg;
        break;
      case 'H':
      default:
        help();
        exit(EXIT_FAILURE);
    }
  }

#ifndef _WIN32
  if (daemon) {
    utils::Daemonizator::daemonize();
  }
#endif

  /**
   * IO module configuration
   */
  io_config.set();

  /**
   * Parse config file
   */
  global_conf.parseConfigurationFile(conf_file);

  core::Prefix producer_namespace(name_prefix);

  utils::StringTokenizer tokenizer(name_prefix, delimiter);
  std::string ip_address = tokenizer.nextToken();
  Name n(ip_address);

  if (object_size > 1350) object_size = 1350;

  CallbackContainer *stubs;
  std::unique_ptr<auth::Signer> signer;

  if (sign) {
    signer = std::make_unique<auth::AsymmetricSigner>(keystore_path,
                                                      keystore_password);
    stubs = new CallbackContainer(n, object_size, ttl, signer.get(), sign,
                                  passphrase, data_lifetime);
  } else {
    auth::Signer *signer = nullptr;
    stubs = new CallbackContainer(n, object_size, ttl, signer, sign, passphrase,
                                  data_lifetime);
  }

  ProducerSocket p;
  p.registerPrefix(producer_namespace);

  p.setSocketOption(GeneralTransportOptions::MANIFEST_MAX_CAPACITY, 0U);
  p.setSocketOption(GeneralTransportOptions::OUTPUT_BUFFER_SIZE, 0U);
  p.setSocketOption(
      ProducerCallbacksOptions::CACHE_MISS,
      (ProducerInterestCallback)bind(&CallbackContainer::processInterest, stubs,
                                     std::placeholders::_1,
                                     std::placeholders::_2, data_lifetime));

  p.connect();
  p.start();

  asio::io_service io_service;
  asio::signal_set signal_set(io_service, SIGINT);
  signal_set.async_wait(
      [&p, &io_service](const std::error_code &, const int &) {
        LOG(INFO) << "STOPPING!!";
        p.stop();
        io_service.stop();
      });

  io_service.run();

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

}  // namespace interface

}  // end namespace transport

int main(int argc, char **argv) {
  return transport::interface::main(argc, argv);
}
