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

#include <hicn/apps/utils/logger.h>
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

static constexpr uint32_t SYN_STATE = 1;

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
  bool jump_ = false;
  uint32_t jump_freq_ = 0;
  uint32_t jump_size_ = 0;
  hicn_packet_format_t packet_format_ = HICN_PACKET_FORMAT_DEFAULT;

  Configuration() = default;
};

class Client : public interface::Portal::TransportCallback {
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
    LoggerInfo() << "Starting ping...";

    portal_.getThread().add([this]() {
      portal_.connect();
      portal_.registerTransportCallback(this);
      doPing();
    });

    io_service_.run();
  }

  void onInterest(Interest &interest) override {
    LoggerInfo() << "Unexpected interest received.";
  }

  void onContentObject(Interest &interest, ContentObject &object) override {
    uint64_t rtt = 0;

    if (!config_->certificate_.empty()) {
      auto t0 = utils::SteadyTime::now();
      if (verifier_.verifyPacket(&object)) {
        auto t1 = utils::SteadyTime::now();
        auto dt = utils::SteadyTime::getDurationUs(t0, t1);
        LoggerInfo() << "Verification time: " << dt.count();
        LoggerInfo() << "<<< Signature Ok.";
      } else {
        LoggerErr() << "<<< Signature verification failed!";
      }
    }

    if (auto it = send_timestamps_.find(interest.getName().getSuffix());
        it != send_timestamps_.end()) {
      rtt =
          utils::SteadyTime::getDurationUs(it->second, utils::SteadyTime::now())
              .count();
      send_timestamps_.erase(it);
    }

    if (LoggerIsOn(2)) {
      LoggerInfo() << "<<< recevied object. ";
      LoggerInfo() << "<<< interest name: " << interest.getName().getPrefix()
                   << " (n_suffixes=" << config_->num_int_manifest_suffixes_
                   << ")";
      LoggerInfo() << "<<< object name: " << object.getName() << " path label "
                   << object.getPathLabel() << " ("
                   << (object.getPathLabel() >> 24) << ")";
    } else if (LoggerIsOn(1)) {
      LoggerInfo() << "<<< received object. ";
      LoggerInfo() << "<<< round trip: " << rtt << " [us]";
      LoggerInfo() << "<<< interest name: " << interest.getName().getPrefix();

      LoggerInfo() << "<<< object name: " << object.getName();
      LoggerInfo() << "<<< content object size: "
                   << object.payloadSize() + object.headerSize() << " [bytes]";
    }

    if (LoggerIsOn(3)) {
      LoggerInfo() << "----- interest dump -----";
      interest.dump();
      LoggerInfo() << "-------------------------";
      LoggerInfo() << "----- object dump -------";
      object.dump();
      LoggerInfo() << "-------------------------";
    }
    LoggerVerbose(1) << "\n";

    received_++;
    processed_++;
    if (processed_ >= config_->maxPing_) {
      afterSignal();
    }
  }

  void onTimeout(Interest::Ptr &interest, const Name &name) override {
    if (LoggerIsOn(2)) {
      LoggerInfo() << "### timeout for " << name;
    } else if (LoggerIsOn(1)) {
      LoggerInfo() << "### timeout for " << name;
    }

    if (LoggerIsOn(3)) {
      LoggerInfo() << "----- interest dump -----";
      interest->dump();
      LoggerInfo() << "-------------------------";
    }
    LoggerVerbose(1) << "\n";

    timedout_++;
    processed_++;
    if (processed_ >= config_->maxPing_) afterSignal();
  }

  void onError(const std::error_code &ec) override {
    LoggerErr() << "Aborting ping due to internal error: " << ec.message();
    afterSignal();
  }

  void checkFamily(hicn_packet_format_t format, int family) {
    switch (HICN_PACKET_FORMAT_GET(format, 0)) {
      case IPPROTO_IP:
        if (family != AF_INET) throw std::runtime_error("Bad packet format");
        break;
      case IPPROTO_IPV6:
        if (family != AF_INET6) throw std::runtime_error("Bad packet format");
        break;
      default:
        throw std::runtime_error("Bad packet format");
    }
  }

  void doPing() {
    std::string name = traffic_generator_->getPrefix();
    uint32_t sequence_number = traffic_generator_->getSuffix();
    const Name interest_name(name, sequence_number);

    hicn_packet_format_t format = config_->packet_format_;

    switch (format) {
      case HICN_PACKET_FORMAT_NEW:
        /* Nothing to do */
        break;
      case HICN_PACKET_FORMAT_IPV4_TCP:
      case HICN_PACKET_FORMAT_IPV6_TCP:
        checkFamily(format, interest_name.getAddressFamily());
        break;
      default:
        throw std::runtime_error("Bad packet format");
    }

    /*
     * Eventually add the AH header if a signer is defined. Raise an error
     * if format include the AH header but no signer is defined.
     */
    if (HICN_PACKET_FORMAT_IS_AH(format)) {
      if (!signer_) throw std::runtime_error("Bad packet format");
    } else {
      if (signer_) format = Packet::toAHFormat(format);
    }

    auto interest = core::PacketManager<>::getInstance().getPacket<Interest>(
        format, signer_ ? signer_->getSignatureFieldSize() : 0);
    interest->setName(interest_name);

    interest->setLifetime(uint32_t(config_->interestLifetime_));

    if (LoggerIsOn(2)) {
      LoggerInfo() << ">>> send interest " << interest->getName()
                   << " suffixes in manifest: "
                   << config_->num_int_manifest_suffixes_;
    } else if (LoggerIsOn(1)) {
      LoggerInfo() << ">>> send interest " << interest->getName();
    }
    LoggerVerbose(1) << "\n";

    send_timestamps_[sequence_number] = utils::SteadyTime::now();
    for (uint32_t i = 0; i < config_->num_int_manifest_suffixes_ &&
                         !traffic_generator_->hasFinished();
         i++) {
      uint32_t sequence_number = traffic_generator_->getSuffix();

      interest->appendSuffix(sequence_number);
      send_timestamps_[sequence_number] = utils::SteadyTime::now();
    }

    if (LoggerIsOn(3)) {
      LoggerInfo() << "----- interest dump -----";
      interest->dump();
      LoggerInfo() << "-------------------------";
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
    LoggerInfo() << "Stopping ping...";
    LoggerInfo() << "Sent: " << traffic_generator_->getSentCount()
                 << " Received: " << received_ << " Timeouts: " << timedout_;
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

static std::unordered_map<std::string, hicn_packet_format_t> const
    packet_format_map = {{"ipv4_tcp", HICN_PACKET_FORMAT_IPV4_TCP},
                         {"ipv6_tcp", HICN_PACKET_FORMAT_IPV6_TCP},
                         {"new", HICN_PACKET_FORMAT_NEW}};

std::string str_tolower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return s;
}

void help() {
  LoggerInfo() << "usage: hicn-consumer-ping [options]";
  LoggerInfo() << "PING options";
  LoggerInfo() << "-i <val>          ping interval in microseconds (default "
                  "1000000ms)";
  LoggerInfo()
      << "-m <val>          maximum number of pings to send (default 10)";
  LoggerInfo() << "-a <val> <pass>   set the passphrase and the number of "
                  "suffixes in interest manifest (default 0);";
  LoggerInfo()
      << "                  e.g. '-m 6 -a -2' sends two interest (0 and "
         "3) with 2 suffixes each (1,2 and 4,5 respectively)";
  LoggerInfo() << "HICN options";
  LoggerInfo() << "-n <val>          hicn name (default b001::1)";
  LoggerInfo()
      << "-l <val>          interest lifetime in milliseconds (default "
         "500ms)";
  LoggerInfo() << "OUTPUT options";
  LoggerInfo() << "-V                verbose, prints statistics about the "
                  "messagges sent and received (default false)";
  LoggerInfo() << "-D                dump, dumps sent and received packets "
                  "(default false)";
  LoggerInfo() << "-q                quiet, not prints (default false)";
  LoggerInfo()
      << "-z <io_module>    IO module to use. Default: hicnlight_module";
  LoggerInfo() << "-F <conf_file>    Path to optional configuration file for "
                  "libtransport";
  LoggerInfo() << "-b <type>         Traffic generator type. Use 'RANDOM' for "
                  "random prefixes and suffixes. Default: sequential suffixes.";
  LoggerInfo()
      << "-w <packet_format> Packet format (without signature, defaults "
         "to IPV6_TCP)";
  LoggerInfo() << "-H                prints this message";
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

  while ((opt = getopt(argc, argv, "a:b:i:m:f:n:l:c:z:F:w:H")) != -1) {
    switch (opt) {
      case 'a':
        c->num_int_manifest_suffixes_ = std::stoi(optarg);
        c->passphrase_ = argv[optind];
        break;
      case 'b':
        c->traffic_generator_type_ = optarg;
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
      case 'n':
        c->name_ = optarg;
        break;
      case 'l':
        c->interestLifetime_ = std::stoi(optarg);
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
      case 'w': {
        std::string packet_format_s = std::string(optarg);
        packet_format_s = str_tolower(packet_format_s);
        auto it = packet_format_map.find(std::string(optarg));
        if (it == packet_format_map.end())
          throw std::runtime_error("Bad packet format");
        c->packet_format_ = it->second;
        break;
      }
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

  LoggerInfo() << "Elapsed time: "
               << utils::SteadyTime::getDurationMs(t0, t1).count() << "ms";

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
