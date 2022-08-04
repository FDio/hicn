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

#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/portal.h>
#include <hicn/transport/utils/chrono_typedefs.h>

#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <map>

#define SYN_STATE 1
#define ACK_STATE 2

namespace transport {

namespace core {

namespace ping {

typedef std::map<uint64_t, utils::SteadyTime::TimePoint> SendTimeMap;
typedef auth::AsymmetricVerifier Verifier;

class Configuration {
 public:
  uint64_t num_int_manifest_suffixes_;
  uint64_t interestLifetime_;
  uint64_t pingInterval_;
  uint64_t maxPing_;
  uint64_t first_suffix_;
  std::string name_;
  std::string certificate_;
  std::string passphrase_;
  uint16_t srcPort_;
  uint16_t dstPort_;
  bool verbose_;
  bool dump_;
  bool jump_;
  bool quiet_;
  uint32_t jump_freq_;
  uint32_t jump_size_;
  uint8_t ttl_;

  Configuration() {
    num_int_manifest_suffixes_ = 0;  // Number of suffixes in interest manifest
    interestLifetime_ = 500;         // ms
    pingInterval_ = 1000000;         // us
    maxPing_ = 10;                   // number of interests
    first_suffix_ = 0;
    name_ = "b001::1";  // string
    srcPort_ = 9695;
    dstPort_ = 8080;
    verbose_ = false;
    dump_ = false;
    jump_ = false;
    quiet_ = false;
    jump_freq_ = 0;
    jump_size_ = 0;
    ttl_ = 64;
  }
};

class Client : interface::Portal::TransportCallback {
 public:
  Client(Configuration *c) : portal_(), signals_(io_service_, SIGINT) {
    // Let the main thread to catch SIGINT
    signals_.async_wait(std::bind(&Client::afterSignal, this));
    timer_.reset(new asio::steady_timer(portal_.getThread().getIoService()));
    config_ = c;
    sequence_number_ = config_->first_suffix_;
    last_jump_ = 0;
    processed_ = 0;
    state_ = SYN_STATE;
    sent_ = 0;
    received_ = 0;
    timedout_ = 0;
    if (!c->certificate_.empty()) {
      verifier_.useCertificate(c->certificate_);
    }

    // If interst manifest, sign it
    if (c->num_int_manifest_suffixes_ != 0) {
      assert(!c->passphrase_.empty());
      signer_ = std::make_unique<auth::SymmetricSigner>(
          auth::CryptoSuite::HMAC_SHA256, c->passphrase_);
    }
  }

  virtual ~Client() {}

  void ping() {
    std::cout << "start ping" << std::endl;

    portal_.getThread().add([this]() {
      portal_.connect();
      portal_.registerTransportCallback(this);
      doPing();
    });

    io_service_.run();
  }

  void onInterest(Interest &interest) override {
    throw errors::RuntimeException("Unexpected interest received.");
  }

  void onContentObject(Interest &interest, ContentObject &object) override {
    double rtt = 0;

    if (!config_->certificate_.empty()) {
      auto t0 = utils::SteadyTime::now();
      if (verifier_.verifyPacket(&object)) {
        auto t1 = utils::SteadyTime::now();
        auto dt = utils::SteadyTime::getDurationUs(t0, t1);
        std::cout << "Verification time: " << dt.count() << std::endl;
        std::cout << "<<< Signature Ok." << std::endl;
      } else {
        std::cout << "<<< Signature verification failed!" << std::endl;
      }
    }

    auto it = send_timestamps_.find(interest.getName().getSuffix());
    if (it != send_timestamps_.end()) {
      rtt =
          utils::SteadyTime::getDurationUs(it->second, utils::SteadyTime::now())
              .count();
      send_timestamps_.erase(it);
    }

    if (config_->verbose_) {
      std::cout << "<<< recevied object. " << std::endl;
      std::cout << "<<< interest name: " << interest.getName()
                << " (n_suffixes=" << interest.numberOfSuffixes() << ")"
                << " src port: " << interest.getSrcPort()
                << " dst port: " << interest.getDstPort() << std::endl;
      std::cout << "<<< object name: " << object.getName()
                << " src port: " << object.getSrcPort()
                << " dst port: " << object.getDstPort() << " path label "
                << object.getPathLabel() << " ("
                << (object.getPathLabel() >> 24) << ")"
                << " TTL: " << (int)object.getTTL() << std::endl;
    } else if (!config_->quiet_) {
      std::cout << "<<< received object. " << std::endl;
      std::cout << "<<< round trip: " << rtt << " [us]" << std::endl;
      std::cout << "<<< interest name: " << interest.getName() << std::endl;
      std::cout << "<<< object name: " << object.getName() << std::endl;
      std::cout << "<<< content object size: "
                << object.payloadSize() + object.headerSize() << " [bytes]"
                << std::endl;
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest.dump();
      std::cout << "-------------------------" << std::endl;
      std::cout << "----- object dump -------" << std::endl;
      object.dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (!config_->quiet_) std::cout << std::endl;

    received_++;
    processed_++;
    if (processed_ >= config_->maxPing_) {
      afterSignal();
    }
  }

  void onTimeout(Interest::Ptr &interest, const Name &name) override {
    if (config_->verbose_) {
      std::cout << "### timeout for " << name
                << " src port: " << interest->getSrcPort()
                << " dst port: " << interest->getDstPort() << std::endl;
    } else if (!config_->quiet_) {
      std::cout << "### timeout for " << name << std::endl;
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest->dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (!config_->quiet_) std::cout << std::endl;

    timedout_++;
    processed_++;
    if (processed_ >= config_->maxPing_) {
      afterSignal();
    }
  }

  void onError(const std::error_code &ec) override {
    std::cout << "Aborting ping due to internal error: " << ec.message()
              << std::endl;
    afterSignal();
  }

  void doPing() {
    const Name interest_name(config_->name_, (uint32_t)sequence_number_);
    hicn_packet_format_t format;
    if (interest_name.getAddressFamily() == AF_INET) {
      format = HICN_PACKET_FORMAT_IPV4_TCP;
    } else {
      format = HICN_PACKET_FORMAT_IPV6_TCP;
    }

    size_t additional_header_size = 0;
    if (signer_) additional_header_size = signer_->getSignatureFieldSize();
    auto interest = std::make_shared<Interest>(interest_name, format,
                                               additional_header_size);

    interest->setLifetime(uint32_t(config_->interestLifetime_));

    interest->setSrcPort(config_->srcPort_);
    interest->setDstPort(config_->dstPort_);
    interest->setTTL(config_->ttl_);
    uint64_t seq_offset = 1;
    while (seq_offset <= config_->num_int_manifest_suffixes_ &&
           sequence_number_ + seq_offset < config_->maxPing_) {
      interest->appendSuffix(sequence_number_ + seq_offset);
      seq_offset++;
    }

    if (config_->verbose_) {
      std::cout << ">>> send interest " << interest->getName()
                << " src port: " << interest->getSrcPort()
                << " dst port: " << interest->getDstPort()
                << " TTL: " << (int)interest->getTTL()
                << " suffixes in manifest: "
                << config_->num_int_manifest_suffixes_ << std::endl;
    } else if (!config_->quiet_) {
      std::cout << ">>> send interest " << interest->getName() << std::endl;
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest->dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (!config_->quiet_) std::cout << std::endl;

    send_timestamps_[sequence_number_] = utils::SteadyTime::now();
    for (uint64_t i = 1; i < seq_offset; i++)
      send_timestamps_[sequence_number_ + i] = utils::SteadyTime::now();

    interest->encodeSuffixes();
    if (signer_) signer_->signPacket(interest.get());

    portal_.sendInterest(interest, interest->getLifetime());

    sequence_number_ += seq_offset;
    sent_ += seq_offset;

    if (sent_ < config_->maxPing_) {
      this->timer_->expires_from_now(
          std::chrono::microseconds(config_->pingInterval_));
      this->timer_->async_wait([this](const std::error_code e) {
        if (!e) {
          doPing();
        }
      });
    }
  }

  void afterSignal() {
    std::cout << "Stop ping" << std::endl;
    std::cout << "Sent: " << sent_ << " Received: " << received_
              << " Timeouts: " << timedout_ << std::endl;
    io_service_.stop();
  }

  void reset() {
    timer_.reset(new asio::steady_timer(portal_.getThread().getIoService()));
    sequence_number_ = config_->first_suffix_;
    last_jump_ = 0;
    processed_ = 0;
    state_ = SYN_STATE;
    sent_ = 0;
    received_ = 0;
    timedout_ = 0;
  }

 private:
  SendTimeMap send_timestamps_;
  asio::io_service io_service_;
  interface::Portal portal_;
  asio::signal_set signals_;
  uint64_t sequence_number_;
  uint64_t last_jump_;
  uint64_t processed_;
  uint32_t state_;
  uint32_t sent_;
  uint32_t received_;
  uint32_t timedout_;
  std::unique_ptr<asio::steady_timer> timer_;
  Configuration *config_;
  Verifier verifier_;
  std::unique_ptr<auth::Signer> signer_;
};

void help() {
  std::cout << "usage: hicn-consumer-ping [options]" << std::endl;
  std::cout << "PING options" << std::endl;
  std::cout
      << "-i <val>          ping interval in microseconds (default 1000000ms)"
      << std::endl;
  std::cout << "-m <val>          maximum number of pings to send (default 10)"
            << std::endl;
  std::cout << "-s <val>          sorce port (default 9695)" << std::endl;
  std::cout << "-d <val>          destination port (default 8080)" << std::endl;
  std::cout << "-t <val>          set packet ttl (default 64)" << std::endl;
  std::cout << "-a <val> <pass>   set the passphrase and the number of "
               "suffixes in interest manifest (default 0);"
            << std::endl;
  std::cout << "                  e.g. '-m 6 -a -2' sends two interest (0 and "
               "3) with 2 suffixes each (1,2 and 4,5 respectively)"
            << std::endl;
  std::cout << "HICN options" << std::endl;
  std::cout << "-n <val>          hicn name (default b001::1)" << std::endl;
  std::cout
      << "-l <val>          interest lifetime in milliseconds (default 500ms)"
      << std::endl;
  std::cout << "OUTPUT options" << std::endl;
  std::cout << "-V                verbose, prints statistics about the "
               "messagges sent and received (default false)"
            << std::endl;
  std::cout << "-D                dump, dumps sent and received packets "
               "(default false)"
            << std::endl;
  std::cout << "-q                quiet, not prints (default false)"
            << std::endl;
  std::cerr << "-z <io_module>    IO module to use. Default: hicnlight_module"
            << std::endl;
  std::cerr << "-F <conf_file>    Path to optional configuration file for "
               "libtransport"
            << std::endl;
  std::cout << "-H                prints this message" << std::endl;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  transport::interface::global_config::GlobalConfigInterface global_conf;

  Configuration *c = new Configuration();
  int opt;
  std::string producer_certificate = "";

  std::string conf_file;
  transport::interface::global_config::IoModuleConfiguration io_config;
  io_config.name = "hicnlight_module";

  while ((opt = getopt(argc, argv, "a:j::t:i:m:s:d:n:l:f:c:SAOqVDHz:F:")) !=
         -1) {
    switch (opt) {
      case 'a':
        c->num_int_manifest_suffixes_ = std::stoi(optarg);
        c->passphrase_ = argv[optind];
        break;
      case 't':
        c->ttl_ = (uint8_t)std::stoi(optarg);
        break;
      case 'i':
        c->pingInterval_ = std::stoi(optarg);
        break;
      case 'm':
        c->maxPing_ = std::stoi(optarg);
        break;
      case 'f':
        c->first_suffix_ = std::stoul(optarg);
        break;
      case 's':
        c->srcPort_ = std::stoi(optarg);
        break;
      case 'd':
        c->dstPort_ = std::stoi(optarg);
        break;
      case 'n':
        c->name_ = optarg;
        break;
      case 'l':
        c->interestLifetime_ = std::stoi(optarg);
        break;
      case 'V':
        c->verbose_ = true;
        ;
        break;
      case 'D':
        c->dump_ = true;
        break;
      case 'q':
        c->quiet_ = true;
        c->verbose_ = false;
        c->dump_ = false;
        break;
      case 'c':
        c->certificate_ = std::string(optarg);
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

  /**
   * IO module configuration
   */
  io_config.set();

  /**
   * Parse config file
   */
  global_conf.parseConfigurationFile(conf_file);

  auto ping = std::make_unique<Client>(c);

  auto t0 = std::chrono::steady_clock::now();
  ping->ping();
  auto t1 = std::chrono::steady_clock::now();

  std::cout << "Elapsed time: "
            << utils::SteadyTime::getDurationMs(t0, t1).count() << "ms"
            << std::endl;

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

}  // namespace ping

}  // namespace core

}  // namespace transport

int main(int argc, char *argv[]) {
  return transport::core::ping::main(argc, argv);
}
