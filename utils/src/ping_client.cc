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

#include <hicn/transport/core/interest.h>
#include <hicn/transport/security/verifier.h>

#include <implementation/socket_consumer.h>

// Let's make the linker happy
#if !TRANSPORT_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL
#ifndef TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL
TRANSPORT_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL = 0;
#endif
#endif

#include <asio/steady_timer.hpp>
#include <chrono>
#include <map>

#define SYN_STATE 1
#define ACK_STATE 2

namespace transport {

namespace core {

namespace ping {

typedef std::map<uint64_t, uint64_t> SendTimeMap;
typedef utils::Verifier Verifier;

class Configuration {
 public:
  uint64_t interestLifetime_;
  uint64_t pingInterval_;
  uint64_t maxPing_;
  uint64_t first_suffix_;
  std::string name_;
  std::string certificate_;
  uint16_t srcPort_;
  uint16_t dstPort_;
  bool verbose_;
  bool dump_;
  bool jump_;
  bool open_;
  bool always_syn_;
  bool always_ack_;
  bool quiet_;
  uint32_t jump_freq_;
  uint32_t jump_size_;
  uint8_t ttl_;

  Configuration() {
    interestLifetime_ = 500;  // ms
    pingInterval_ = 1000000;  // us
    maxPing_ = 10;            // number of interests
    first_suffix_ = 0;
    name_ = "b001::1";  // string
    srcPort_ = 9695;
    dstPort_ = 8080;
    verbose_ = false;
    dump_ = false;
    jump_ = false;
    open_ = false;
    always_syn_ = false;
    always_ack_ = false;
    quiet_ = false;
    jump_freq_ = 0;
    jump_size_ = 0;
    ttl_ = 64;
  }
};

class Client : implementation::BasePortal::ConsumerCallback {
 public:
  Client(Configuration *c)
      : portal_(), signals_(portal_.getIoService(), SIGINT) {
    // Let the main thread to catch SIGINT
    portal_.connect();
    portal_.setConsumerCallback(this);

    signals_.async_wait(std::bind(&Client::afterSignal, this));

    timer_.reset(new asio::steady_timer(portal_.getIoService()));
    config_ = c;
    sequence_number_ = config_->first_suffix_;
    last_jump_ = 0;
    processed_ = 0;
    state_ = SYN_STATE;
    sent_ = 0;
    received_ = 0;
    timedout_ = 0;
    if (!c->certificate_.empty()) {
      key_id_ = verifier_.addKeyFromCertificate(c->certificate_);
    }
  }

  virtual ~Client() {}

  void ping() {
    std::cout << "start ping" << std::endl;
    doPing();
    portal_.runEventsLoop();
  }

  void onContentObject(Interest::Ptr &&interest,
                       ContentObject::Ptr &&object) override {
    uint64_t rtt = 0;

    if (!config_->certificate_.empty()) {
      auto t0 = std::chrono::steady_clock::now();
      if (verifier_.verify(*object)) {
        auto t1 = std::chrono::steady_clock::now();
        auto dt =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);
        std::cout << "Verification time: " << dt.count() << std::endl;
        std::cout << "<<< Signature Ok." << std::endl;
      } else {
        std::cout << "<<< Signature verification failed!" << std::endl;
      }
    }

    auto it = send_timestamps_.find(interest->getName().getSuffix());
    if (it != send_timestamps_.end()) {
      rtt = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count() -
            it->second;
      send_timestamps_.erase(it);
    }

    if (config_->verbose_) {
      std::cout << "<<< recevied object. " << std::endl;
      std::cout << "<<< interest name: " << interest->getName()
                << " src port: " << interest->getSrcPort()
                << " dst port: " << interest->getDstPort()
                << " flags: " << interest->printFlags() << std::endl;
      std::cout << "<<< object name: " << object->getName()
                << " src port: " << object->getSrcPort()
                << " dst port: " << object->getDstPort()
                << " flags: " << object->printFlags() << " path label "
                << object->getPathLabel() << " ("
                << (object->getPathLabel() >> 24) << ")"
                << " TTL: " << (int)object->getTTL() << std::endl;
    } else if (!config_->quiet_) {
      std::cout << "<<< received object. " << std::endl;
      std::cout << "<<< round trip: " << rtt << " [us]" << std::endl;
      std::cout << "<<< interest name: " << interest->getName() << std::endl;
      std::cout << "<<< object name: " << object->getName() << std::endl;
      std::cout << "<<< content object size: "
                << object->payloadSize() + object->headerSize() << " [bytes]"
                << std::endl;
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest->dump();
      std::cout << "-------------------------" << std::endl;
      std::cout << "----- object dump -------" << std::endl;
      object->dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (!config_->quiet_) std::cout << std::endl;

    if (!config_->always_syn_) {
      if (object->testSyn() && object->testAck() && state_ == SYN_STATE) {
        state_ = ACK_STATE;
      }
    }

    received_++;
    processed_++;
    if (processed_ >= config_->maxPing_) {
      afterSignal();
    }
  }

  void onTimeout(Interest::Ptr &&interest) override {
    if (config_->verbose_) {
      std::cout << "### timeout for " << interest->getName()
                << " src port: " << interest->getSrcPort()
                << " dst port: " << interest->getDstPort()
                << " flags: " << interest->printFlags() << std::endl;
    } else if (!config_->quiet_) {
      std::cout << "### timeout for " << interest->getName() << std::endl;
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

  void doPing() {
    Name interest_name(config_->name_, (uint32_t)sequence_number_);
    hicn_format_t format;
    if (interest_name.getAddressFamily() == AF_INET) {
      format = HF_INET_TCP;
    } else {
      format = HF_INET6_TCP;
    }

    Interest::Ptr interest(new Interest(std::move(interest_name), format),
                           nullptr);

    interest->setLifetime(uint32_t(config_->interestLifetime_));

    interest->resetFlags();

    if (config_->open_ || config_->always_syn_) {
      if (state_ == SYN_STATE) {
        interest->setSyn();
      } else if (state_ == ACK_STATE) {
        interest->setAck();
      }
    } else if (config_->always_ack_) {
      interest->setAck();
    }

    interest->setSrcPort(config_->srcPort_);
    interest->setDstPort(config_->dstPort_);
    interest->setTTL(config_->ttl_);

    if (config_->verbose_) {
      std::cout << ">>> send interest " << interest->getName()
                << " src port: " << interest->getSrcPort()
                << " dst port: " << interest->getDstPort()
                << " flags: " << interest->printFlags()
                << " TTL: " << (int)interest->getTTL() << std::endl;
    } else if (!config_->quiet_) {
      std::cout << ">>> send interest " << interest->getName() << std::endl;
    }

    if (config_->dump_) {
      std::cout << "----- interest dump -----" << std::endl;
      interest->dump();
      std::cout << "-------------------------" << std::endl;
    }

    if (!config_->quiet_) std::cout << std::endl;

    send_timestamps_[sequence_number_] =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();

    portal_.sendInterest(std::move(interest));

    sequence_number_++;
    sent_++;

    if (sent_ < config_->maxPing_) {
      this->timer_->expires_from_now(
          std::chrono::microseconds(config_->pingInterval_));
      this->timer_->async_wait([this](const std::error_code e) { doPing(); });
    }
  }

  void afterSignal() {
    std::cout << "Stop ping" << std::endl;
    std::cout << "Sent: " << sent_ << " Received: " << received_
              << " Timeouts: " << timedout_ << std::endl;
    portal_.stopEventsLoop();
  }

  void reset() {
    timer_.reset(new asio::steady_timer(portal_.getIoService()));
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
  implementation::BasePortal portal_;
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
  PARCKeyId *key_id_;
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
  std::cout << "-O                open tcp connection (three way handshake) "
               "(default false)"
            << std::endl;
  std::cout << "-S                send always syn messages (default false)"
            << std::endl;
  std::cout << "-A                send always ack messages (default false)"
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
  std::cout << "-H                prints this message" << std::endl;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  Configuration *c = new Configuration();
  int opt;
  std::string producer_certificate = "";

  while ((opt = getopt(argc, argv, "j::t:i:m:s:d:n:l:f:c:SAOqVDH")) != -1) {
    switch (opt) {
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
      case 'O':
        c->always_syn_ = false;
        c->always_ack_ = false;
        c->open_ = true;
        break;
      case 'S':
        c->always_syn_ = true;
        c->always_ack_ = false;
        c->open_ = false;
        break;
      case 'A':
        c->always_syn_ = false;
        c->always_ack_ = true;
        c->open_ = false;
        break;
      case 'q':
        c->quiet_ = true;
        c->verbose_ = false;
        c->dump_ = false;
        break;
      case 'c':
        c->certificate_ = std::string(optarg);
        break;
      case 'H':
      default:
        help();
        exit(EXIT_FAILURE);
    }
  }

  auto ping = std::make_unique<Client>(c);

  auto t0 = std::chrono::steady_clock::now();
  ping->ping();
  auto t1 = std::chrono::steady_clock::now();

  std::cout
      << "Elapsed time: "
      << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()
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
