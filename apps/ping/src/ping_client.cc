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
#include <hicn/transport/utils/traffic_generator.h>

#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <map>

#define SYN_STATE 1
#define ACK_STATE 2

namespace transport {

namespace core {

namespace ping {

using SendTimeMap = std::map<uint64_t, utils::SteadyTime::TimePoint>;
using Verifier = auth::AsymmetricVerifier;

class Configuration {
 public:
  static constexpr char TRAFFIC_GENERATOR_RAND[] = "RANDOM";

  uint32_t num_int_manifest_suffixes_ =
      0;  // Number of suffixes in interest manifest (suffix in the header
          // is not included in the count)
  uint64_t interestLifetime_ = 500;  // ms
  uint64_t pingInterval_ = 1000000;  // us
  uint32_t maxPing_ = 10;            // number of interests
  uint32_t first_suffix_ = 0;
  std::string name_ = "b001::1";
  std::string certificate_;
  std::string passphrase_;
  std::string traffic_generator_type_;
  uint16_t srcPort_ = 9695;
  uint16_t dstPort_ = 8080;
  bool verbose_ = false;
  bool dump_ = false;
  bool jump_ = false;
  bool quiet_ = false;
  uint32_t jump_freq_ = 0;
  uint32_t jump_size_ = 0;
  uint8_t ttl_ = 64;

  Configuration() = default;
};

class Client : private interface::Portal::TransportCallback {
 public:
  explicit Client(Configuration *c)
      : signals_(io_service_, SIGINT),
        config_(c),
        timer_(std::make_unique<asio::steady_timer>(
            portal_.getThread().getIoService())) {
    // Let the main thread to catch SIGINT
    signals_.async_wait(std::bind(&Client::afterSignal, this));

    if (!c->certificate_.empty()) {
      verifier_.useCertificate(c->certificate_);
    }

    // If interst manifest, sign it
    if (c->num_int_manifest_suffixes_ != 0) {
      assert(!c->passphrase_.empty());
      signer_ = std::make_unique<auth::SymmetricSigner>(
          auth::CryptoSuite::HMAC_SHA256, c->passphrase_);
    }

    if (c->traffic_generator_type_ ==
        std::string(Configuration::TRAFFIC_GENERATOR_RAND)) {
      traffic_generator_ =
          std::make_unique<RandomTrafficGenerator>(config_->maxPing_);
    } else {
      traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
          config_->name_, config_->first_suffix_, config_->maxPing_);
    }
  }

  virtual ~Client() = default;

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
    uint64_t rtt = 0;

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

    if (auto it = send_timestamps_.find(interest.getName().getSuffix());
        it != send_timestamps_.end()) {
      rtt =
          utils::SteadyTime::getDurationUs(it->second, utils::SteadyTime::now())
              .count();
      send_timestamps_.erase(it);
    }

    if (config_->verbose_) {
      std::cout << "<<< recevied object. " << std::endl;
      std::cout << "<<< interest name: " << interest.getName().getPrefix()
                << " (n_suffixes=" << config_->num_int_manifest_suffixes_ << ")"
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
      std::cout << "<<< interest name: " << interest.getName().getPrefix()
                << std::endl;
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
    std::string name = traffic_generator_->getPrefix();
    uint32_t sequence_number = traffic_generator_->getSuffix();
    const Name interest_name(name, sequence_number);

    hicn_packet_format_t format;
    if (interest_name.getAddressFamily() == AF_INET) {
      format = signer_ ? HICN_PACKET_FORMAT_IPV4_TCP_AH
                       : HICN_PACKET_FORMAT_IPV4_TCP;
    } else {
      format = signer_ ? HICN_PACKET_FORMAT_IPV6_TCP_AH
                       : HICN_PACKET_FORMAT_IPV6_TCP;
    }

    size_t additional_header_size = 0;
    if (signer_) additional_header_size = signer_->getSignatureFieldSize();
    auto interest = std::make_shared<Interest>(interest_name, format,
                                               additional_header_size);

    interest->setLifetime(uint32_t(config_->interestLifetime_));

    interest->setSrcPort(config_->srcPort_);
    interest->setDstPort(config_->dstPort_);
    interest->setTTL(config_->ttl_);

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

    if (!config_->quiet_) std::cout << std::endl;

    send_timestamps_[sequence_number] = utils::SteadyTime::now();
    for (int i = 0; i < config_->num_int_manifest_suffixes_ &&
                    !traffic_generator_->hasFinished();
         i++) {
      uint32_t sequence_number = traffic_generator_->getSuffix();

      interest->appendSuffix(sequence_number);
      send_timestamps_[sequence_number] = utils::SteadyTime::now();
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest->dump();
      std::cout << "-------------------------" << std::endl;
    }

    interest->encodeSuffixes();
    if (signer_) signer_->signPacket(interest.get());
    portal_.sendInterest(interest, interest->getLifetime());

    if (!traffic_generator_->hasFinished()) {
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
    std::cout << "Sent: " << traffic_generator_->getSentCount()
              << " Received: " << received_ << " Timeouts: " << timedout_
              << std::endl;
    io_service_.stop();
  }

  void reset() {
    timer_.reset(new asio::steady_timer(portal_.getThread().getIoService()));
    traffic_generator_->reset();
    last_jump_ = 0;
    processed_ = 0;
    state_ = SYN_STATE;
    received_ = 0;
    timedout_ = 0;
  }

 private:
  SendTimeMap send_timestamps_;
  asio::io_service io_service_;
  interface::Portal portal_;
  asio::signal_set signals_;
  Configuration *config_;
  std::unique_ptr<asio::steady_timer> timer_;
  uint64_t last_jump_ = 0;
  uint64_t processed_ = 0;
  uint32_t state_ = SYN_STATE;
  uint32_t received_ = 0;
  uint32_t timedout_ = 0;
  Verifier verifier_;
  std::unique_ptr<auth::Signer> signer_;
  std::unique_ptr<TrafficGenerator> traffic_generator_;
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
  std::cout << "-b <type>         Traffic generator type. Use 'RANDOM' for "
               "random prefixes and suffixes. Default: sequential suffixes."
            << std::endl;
  std::cout << "-H                prints this message" << std::endl;
}

int start(int argc, char *argv[]) {
#ifdef _WIN32
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  transport::interface::global_config::GlobalConfigInterface global_conf;

  auto c = std::make_unique<Configuration>();
  int opt;
  std::string producer_certificate = "";

  std::string conf_file;
  transport::interface::global_config::IoModuleConfiguration io_config;
  io_config.name = "hicnlight_module";

  while ((opt = getopt(argc, argv, "a:b:j::t:i:m:s:d:n:l:f:c:SAOqVDHz:F:")) !=
         -1) {
    switch (opt) {
      case 'a':
        c->num_int_manifest_suffixes_ = std::stoi(optarg);
        c->passphrase_ = argv[optind];
        break;
      case 'b':
        c->traffic_generator_type_ = optarg;
        break;
      case 't':
        c->ttl_ = uint8_t(std::stoi(optarg));
        break;
      case 'i':
        c->pingInterval_ = std::stoi(optarg);
        break;
      case 'm':
        c->maxPing_ = std::stoi(optarg);
        break;
      case 'f':
        c->first_suffix_ = uint32_t(std::stoul(optarg));
        break;
      case 's':
        c->srcPort_ = uint16_t(std::stoi(optarg));
        break;
      case 'd':
        c->dstPort_ = uint16_t(std::stoi(optarg));
        break;
      case 'n':
        c->name_ = optarg;
        break;
      case 'l':
        c->interestLifetime_ = std::stoi(optarg);
        break;
      case 'V':
        c->verbose_ = true;
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
      case 'H':;
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

  auto ping = std::make_unique<Client>(c.get());

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
  return transport::core::ping::start(argc, argv);
}
