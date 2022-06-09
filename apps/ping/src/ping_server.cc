/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

 public:
  CallbackContainer(const Name &prefix, uint32_t object_size, bool verbose,
                    bool dump, bool quite, bool flags, bool reset, uint8_t ttl,
                    auth::Signer *signer, bool sign, std::string passphrase,
                    uint32_t lifetime)
      : buffer_(object_size, 'X'),
        content_objects_((std::uint32_t)(1 << log2_content_object_buffer_size)),
        mask_((std::uint16_t)(1 << log2_content_object_buffer_size) - 1),
        content_objects_index_(0),
        verbose_(verbose),
        dump_(dump),
        quite_(quite),
        flags_(flags),
        reset_(reset),
        ttl_(ttl),
        signer_(signer),
        sign_(sign) {
    // Verifier for interest manifests
    if (!passphrase.empty())
      verifier_ = std::make_unique<auth::SymmetricVerifier>(passphrase);

    core::Packet::Format format;
    if (prefix.getAddressFamily() == AF_INET) {
      format = core::Packet::Format::HF_INET_TCP;
      if (sign_) {
        format = core::Packet::Format::HF_INET_TCP_AH;
      }
    } else {
      format = core::Packet::Format::HF_INET6_TCP;
      if (sign_) {
        format = core::Packet::Format::HF_INET6_TCP_AH;
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
        std::cout << "Verification time: " << dt.count() << std::endl;
        std::cout << "<<< Signature Ok." << std::endl;
      } else {
        std::cout << "<<< Signature verification failed!" << std::endl;
      }
    }

    if (verbose_) {
      std::cout << "<<< received interest " << interest.getName()
                << " src port: " << interest.getSrcPort()
                << " dst port: " << interest.getDstPort()
                << " flags: " << interest.printFlags()
                << "TTL: " << (int)interest.getTTL()
                << " suffixes in manifest: " << interest.numberOfSuffixes()
                << std::endl;
    } else if (!quite_) {
      std::cout << "<<< received interest " << interest.getName() << std::endl;
    }

    if (dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest.dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (interest.testRst()) {
      std::cout << "!!!got a reset, I don't reply" << std::endl;
    } else {
      uint32_t *suffix = interest.firstSuffix();
      uint32_t n_suffixes_in_manifest = interest.numberOfSuffixes();
      uint32_t *request_bitmap = interest.getRequestBitmap();
      if (!interest.isValid()) throw std::runtime_error("Bad interest format");

      Name name = interest.getName();
      uint32_t pos = 0;  // Position of current suffix in manifest
      do {
        // If suffix can be processed, i.e. no manifest with bitmap excluding it
        if (!interest.hasManifest() || is_bit_set(request_bitmap, pos)) {
          auto &content_object =
              content_objects_[content_objects_index_++ & mask_];

          content_object->setName(interest.getName());
          content_object->setLifetime(lifetime);
          content_object->setLocator(interest.getLocator());
          content_object->setSrcPort(interest.getDstPort());
          content_object->setDstPort(interest.getSrcPort());
          content_object->setTTL(ttl_);

          if (!sign_) {
            content_object->resetFlags();
          }

          if (flags_) {
            if (interest.testSyn()) {
              content_object->setSyn();
              content_object->setAck();
            } else if (interest.testAck()) {
              content_object->setAck();
            }  // here I may need to handle the FIN flag;
          } else if (reset_) {
            content_object->setRst();
          }

          if (verbose_) {
            std::cout << ">>> send object " << content_object->getName()
                      << " src port: " << content_object->getSrcPort()
                      << " dst port: " << content_object->getDstPort()
                      << " flags: " << content_object->printFlags()
                      << " TTL: " << (int)content_object->getTTL() << std::endl;
          } else if (!quite_) {
            std::cout << ">>> send object " << content_object->getName()
                      << std::endl;
          }

          if (dump_) {
            std::cout << "----- object dump -----" << std::endl;
            content_object->dump();
            std::cout << "-----------------------" << std::endl;
          }

          if (sign_ && signer_) {
            signer_->signPacket(content_object.get());
          }

          p.produce(*content_object);
        }

        if (interest.hasManifest()) {
          uint32_t seq = *suffix;
          suffix++;

          interest.setName(name.setSuffix(seq));
        }
      } while (pos++ < n_suffixes_in_manifest);

      if (!quite_) std::cout << std::endl;
    }
  }

 private:
  std::string buffer_;
  std::vector<std::shared_ptr<ContentObject>> content_objects_;
  std::uint16_t mask_;
  std::uint16_t content_objects_index_;
  bool verbose_;
  bool dump_;
  bool quite_;
  bool flags_;
  bool reset_;
  uint8_t ttl_;
  auth::Signer *signer_;
  bool sign_;
  std::unique_ptr<auth::Verifier> verifier_;
};

void help() {
  std::cout << "usage: hicn-preoducer-ping [options]" << std::endl;
  std::cout << "PING options" << std::endl;
  std::cout << "-s <val>          object content size (default 1350B)"
            << std::endl;
  std::cout << "-n <val>          hicn name (default b001::/64)" << std::endl;
  std::cout << "-f                set tcp flags according to the flag received "
               "                  (default false)"
            << std::endl;
  std::cout << "-l                data lifetime" << std::endl;
  std::cout
      << "-r                always reply with a reset flag (default false)"
      << std::endl;
  std::cout << "-t                set ttl (default 64)" << std::endl;
  std::cout << "OUTPUT options" << std::endl;
  std::cout << "-V                verbose, prints statistics about the "
               "messagges sent "
               "                  and received (default false)"
            << std::endl;
  std::cout << "-D                dump, dumps sent and received packets "
               "(default false)"
            << std::endl;
  std::cout << "-q                quite, not prints (default false)"
            << std::endl;
  std::cerr << "-z <io_module>    IO module to use. Default: hicnlightng_module"
            << std::endl;
  std::cerr << "-F <conf_file>    Path to optional configuration file for "
               "libtransport"
            << std::endl;
#ifndef _WIN32
  std::cout << "-d                daemon mode" << std::endl;
#endif
  std::cout << "-H                prints this message" << std::endl;
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
  bool verbose = false;
  bool dump = false;
  bool quite = false;
  bool flags = false;
  bool reset = false;
  uint32_t object_size = 1250;
  uint8_t ttl = 64;
  std::string keystore_path = "./rsa_crypto_material.p12";
  std::string keystore_password = "cisco";
  std::string passphrase = "";
  bool sign = false;
  uint32_t data_lifetime = default_values::content_object_expiry_time;

  std::string conf_file;
  transport::interface::global_config::IoModuleConfiguration io_config;
  io_config.name = "hicnlightng_module";

  int opt;
#ifndef _WIN32
  while ((opt = getopt(argc, argv, "a:s:n:t:l:qfrVDdHk:p:z:F:")) != -1) {
#else
  while ((opt = getopt(argc, argv, "s:n:t:l:qfrVDHk:p:z:F:")) != -1) {
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
      case 'V':
        verbose = true;
        break;
      case 'D':
        dump = true;
        break;
      case 'q':
        verbose = false;
        dump = false;
        quite = true;
        break;
#ifndef _WIN32
      case 'd':
        daemon = true;
        break;
#endif
      case 'f':
        flags = true;
        break;
      case 'r':
        reset = true;
        break;
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
    stubs = new CallbackContainer(n, object_size, verbose, dump, quite, flags,
                                  reset, ttl, signer.get(), sign, passphrase,
                                  data_lifetime);
  } else {
    auth::Signer *signer = nullptr;
    stubs = new CallbackContainer(n, object_size, verbose, dump, quite, flags,
                                  reset, ttl, signer, sign, passphrase,
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
        std::cout << "STOPPING!!" << std::endl;
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
