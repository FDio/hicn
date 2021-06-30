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

#include <server.h>

namespace hiperf {

/**
 * Hiperf server class: configure and setup an hicn producer following the
 * ServerConfiguration.
 */
class HIperfServer::Impl {
  const std::size_t log2_content_object_buffer_size = 8;

 public:
  Impl(const hiperf::ServerConfiguration &conf)
      : configuration_(conf),
        signals_(io_service_),
        rtc_timer_(io_service_),
        unsatisfied_interests_(),
        content_objects_((std::uint16_t)(1 << log2_content_object_buffer_size)),
        content_objects_index_(0),
        mask_((std::uint16_t)(1 << log2_content_object_buffer_size) - 1),
        last_segment_(0),
#ifndef _WIN32
        ptr_last_segment_(&last_segment_),
        input_(io_service_),
        rtc_running_(false),
#else
        ptr_last_segment_(&last_segment_),
#endif
        flow_name_(configuration_.name.getName()),
        socket_(io_service_),
        recv_buffer_(nullptr, 0) {
    std::string buffer(configuration_.payload_size_, 'X');
    std::cout << "Producing contents under name " << conf.name.getName()
              << std::endl;
#ifndef _WIN32
    if (configuration_.interactive_) {
      input_.assign(::dup(STDIN_FILENO));
    }
#endif

    for (int i = 0; i < (1 << log2_content_object_buffer_size); i++) {
      content_objects_[i] = ContentObject::Ptr(
          new ContentObject(conf.name.getName(), HF_INET6_TCP, 0,
                            (const uint8_t *)buffer.data(), buffer.size()));
      content_objects_[i]->setLifetime(
          default_values::content_object_expiry_time);
    }
  }

  void virtualProcessInterest(ProducerSocket &p, const Interest &interest) {
    content_objects_[content_objects_index_ & mask_]->setName(
        interest.getName());
    producer_socket_->produce(
        *content_objects_[content_objects_index_++ & mask_]);
  }

  void processInterest(ProducerSocket &p, const Interest &interest) {
    p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                      (ProducerInterestCallback)VOID_HANDLER);
    p.setSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                      5000000_U32);

    produceContent(p, interest.getName(), interest.getName().getSuffix());
    std::cout << "Received interest " << interest.getName().getSuffix()
              << std::endl;
  }

  void asyncProcessInterest(ProducerSocket &p, const Interest &interest) {
    p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                      (ProducerInterestCallback)bind(&Impl::cacheMiss, this,
                                                     std::placeholders::_1,
                                                     std::placeholders::_2));
    p.setSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                      5000000_U32);
    uint32_t suffix = interest.getName().getSuffix();

    if (suffix == 0) {
      last_segment_ = 0;
      ptr_last_segment_ = &last_segment_;
      unsatisfied_interests_.clear();
    }

    // The suffix will either be the one from the received interest or the
    // smallest suffix of a previous interest not satisfed
    if (!unsatisfied_interests_.empty()) {
      auto it =
          std::lower_bound(unsatisfied_interests_.begin(),
                           unsatisfied_interests_.end(), *ptr_last_segment_);
      if (it != unsatisfied_interests_.end()) {
        suffix = *it;
      }
      unsatisfied_interests_.erase(unsatisfied_interests_.begin(), it);
    }

    std::cout << "Received interest " << interest.getName().getSuffix()
              << ", starting production at " << suffix << std::endl;
    std::cout << unsatisfied_interests_.size() << " interests still unsatisfied"
              << std::endl;
    produceContentAsync(p, interest.getName(), suffix);
  }

  void produceContent(ProducerSocket &p, const Name &content_name,
                      uint32_t suffix) {
    auto b = utils::MemBuf::create(configuration_.download_size);
    std::memset(b->writableData(), '?', configuration_.download_size);
    b->append(configuration_.download_size);
    uint32_t total;

    utils::TimePoint t0 = utils::SteadyClock::now();
    total = p.produceStream(content_name, std::move(b),
                            !configuration_.multiphase_produce_, suffix);
    utils::TimePoint t1 = utils::SteadyClock::now();

    std::cout
        << "Written " << total
        << " data packets in output buffer (Segmentation time: "
        << std::chrono::duration_cast<utils::Microseconds>(t1 - t0).count()
        << " us)" << std::endl;
  }

  void produceContentAsync(ProducerSocket &p, Name content_name,
                           uint32_t suffix) {
    auto b = utils::MemBuf::create(configuration_.download_size);
    std::memset(b->writableData(), '?', configuration_.download_size);
    b->append(configuration_.download_size);

    p.asyncProduce(content_name, std::move(b),
                   !configuration_.multiphase_produce_, suffix,
                   &ptr_last_segment_);
  }

  void cacheMiss(ProducerSocket &p, const Interest &interest) {
    unsatisfied_interests_.push_back(interest.getName().getSuffix());
  }

  void onContentProduced(ProducerSocket &p, const std::error_code &err,
                         uint64_t bytes_written) {
    p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                      (ProducerInterestCallback)bind(
                          &Impl::asyncProcessInterest, this,
                          std::placeholders::_1, std::placeholders::_2));
  }

  std::shared_ptr<Identity> getProducerIdentity(std::string &keystore_path,
                                                std::string &keystore_pwd,
                                                CryptoHashType &hash_type) {
    if (access(keystore_path.c_str(), F_OK) != -1) {
      return std::make_shared<Identity>(keystore_path, keystore_pwd, hash_type);
    }
    return std::make_shared<Identity>(keystore_path, keystore_pwd,
                                      CryptoSuite::RSA_SHA256, 1024, 365,
                                      "producer-test");
  }

  int setup() {
    int ret;
    int production_protocol;

    if (configuration_.secure_) {
      auto identity = getProducerIdentity(configuration_.keystore_name,
                                          configuration_.keystore_password,
                                          configuration_.hash_algorithm);
      producer_socket_ = std::make_unique<P2PSecureProducerSocket>(
          configuration_.rtc_, identity);
    } else {
      if (!configuration_.rtc_) {
        production_protocol = ProductionProtocolAlgorithms::BYTE_STREAM;
      } else {
        production_protocol = ProductionProtocolAlgorithms::RTC_PROD;
      }

      producer_socket_ = std::make_unique<ProducerSocket>(production_protocol);
    }

    if (producer_socket_->setSocketOption(
            GeneralTransportOptions::MAKE_MANIFEST, configuration_.manifest) ==
        SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (!configuration_.passphrase.empty()) {
      std::shared_ptr<Signer> signer = std::make_shared<SymmetricSigner>(
          CryptoSuite::HMAC_SHA256, configuration_.passphrase);
      producer_socket_->setSocketOption(GeneralTransportOptions::SIGNER,
                                        signer);
    }

    if (!configuration_.keystore_name.empty()) {
      auto identity = getProducerIdentity(configuration_.keystore_name,
                                          configuration_.keystore_password,
                                          configuration_.hash_algorithm);
      std::shared_ptr<Signer> signer = identity->getSigner();
      producer_socket_->setSocketOption(GeneralTransportOptions::SIGNER,
                                        signer);
    }

    uint32_t rtc_header_size = 0;
    if (configuration_.rtc_) rtc_header_size = 12;
    producer_socket_->setSocketOption(
        GeneralTransportOptions::DATA_PACKET_SIZE,
        (uint32_t)(
            configuration_.payload_size_ + rtc_header_size +
            (configuration_.name.getAddressFamily() == AF_INET ? 40 : 60)));
    producer_socket_->registerPrefix(configuration_.name);
    producer_socket_->connect();

    if (configuration_.rtc_) {
      std::cout << "Running RTC producer: the prefix length will be ignored."
                   " Use /128 by default in RTC mode"
                << std::endl;
      return ERROR_SUCCESS;
    }

    if (!configuration_.virtual_producer) {
      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
              configuration_.content_lifetime) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::OUTPUT_BUFFER_SIZE, 200000U) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (!configuration_.live_production) {
        produceContent(*producer_socket_, configuration_.name.getName(), 0);
      } else {
        ret = producer_socket_->setSocketOption(
            ProducerCallbacksOptions::CACHE_MISS,
            (ProducerInterestCallback)bind(&Impl::asyncProcessInterest, this,
                                           std::placeholders::_1,
                                           std::placeholders::_2));

        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }
      }
    } else {
      ret = producer_socket_->setSocketOption(
          GeneralTransportOptions::OUTPUT_BUFFER_SIZE, 0U);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = producer_socket_->setSocketOption(
          ProducerCallbacksOptions::CACHE_MISS,
          (ProducerInterestCallback)bind(&Impl::virtualProcessInterest, this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    ret = producer_socket_->setSocketOption(
        ProducerCallbacksOptions::CONTENT_PRODUCED,
        (ProducerContentCallback)bind(
            &Impl::onContentProduced, this, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3));

    return ERROR_SUCCESS;
  }

  void receiveStream() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_.first, recv_buffer_.second), remote_,
        [this](std::error_code ec, std::size_t length) {
          if (ec) return;
          sendRTCContentFromStream(recv_buffer_.first, length);
          receiveStream();
        });
  }

  void sendRTCContentFromStream(uint8_t *buff, std::size_t len) {
    auto payload =
        content_objects_[content_objects_index_++ & mask_]->getPayload();
    // this is used to compute the data packet delay
    // Used only for performance evaluation
    // It requires clock synchronization between producer and consumer
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    uint8_t *start = (uint8_t *)payload->writableData();
    std::memcpy(start, &now, sizeof(uint64_t));
    std::memcpy(start + sizeof(uint64_t), buff, len);
    producer_socket_->produceDatagram(flow_name_, start,
                                      len + sizeof(uint64_t));
  }

  void sendRTCContentObjectCallback(std::error_code ec) {
    if (ec) return;
    rtc_timer_.expires_from_now(
        configuration_.production_rate_.getMicrosecondsForPacket(
            configuration_.payload_size_));
    rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback, this,
                                    std::placeholders::_1));
    auto payload =
        content_objects_[content_objects_index_++ & mask_]->getPayload();

    // this is used to compute the data packet delay
    // Used only for performance evaluation
    // It requires clock synchronization between producer and consumer
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

    std::memcpy(payload->writableData(), &now, sizeof(uint64_t));

    producer_socket_->produceDatagram(
        flow_name_, payload->data(),
        payload->length() < 1400 ? payload->length() : 1400);
  }

  void sendRTCContentObjectCallbackWithTrace(std::error_code ec) {
    if (ec) return;

    auto payload =
        content_objects_[content_objects_index_++ & mask_]->getPayload();

    uint32_t packet_len =
        configuration_.trace_[configuration_.trace_index_].size;

    // this is used to compute the data packet delay
    // used only for performance evaluation
    // it requires clock synchronization between producer and consumer
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

    std::memcpy(payload->writableData(), &now, sizeof(uint64_t));

    if (packet_len > payload->length()) packet_len = payload->length();
    if (packet_len > 1400) packet_len = 1400;

    producer_socket_->produceDatagram(flow_name_, payload->data(), packet_len);

    uint32_t next_index = configuration_.trace_index_ + 1;
    uint64_t schedule_next;
    if (next_index < configuration_.trace_.size()) {
      schedule_next =
          configuration_.trace_[next_index].timestamp -
          configuration_.trace_[configuration_.trace_index_].timestamp;
    } else {
      // here we need to loop, schedule in a random time
      schedule_next = 1000;
    }

    configuration_.trace_index_ =
        (configuration_.trace_index_ + 1) % configuration_.trace_.size();
    rtc_timer_.expires_from_now(std::chrono::microseconds(schedule_next));
    rtc_timer_.async_wait(
        std::bind(&Impl::sendRTCContentObjectCallbackWithTrace, this,
                  std::placeholders::_1));
  }

#ifndef _WIN32
  void handleInput(const std::error_code &error, std::size_t length) {
    if (error) {
      producer_socket_->stop();
      io_service_.stop();
    }

    if (rtc_running_) {
      std::cout << "stop real time content production" << std::endl;
      rtc_running_ = false;
      rtc_timer_.cancel();
    } else {
      std::cout << "start real time content production" << std::endl;
      rtc_running_ = true;
      rtc_timer_.expires_from_now(
          configuration_.production_rate_.getMicrosecondsForPacket(
              configuration_.payload_size_));
      rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback, this,
                                      std::placeholders::_1));
    }

    input_buffer_.consume(length);  // Remove newline from input.
    asio::async_read_until(
        input_, input_buffer_, '\n',
        std::bind(&Impl::handleInput, this, std::placeholders::_1,
                  std::placeholders::_2));
  }
#endif

  int parseTraceFile() {
    std::ifstream trace(configuration_.trace_file_);
    if (trace.fail()) {
      return -1;
    }
    std::string line;
    while (std::getline(trace, line)) {
      std::istringstream iss(line);
      hiperf::packet_t packet;
      iss >> packet.timestamp >> packet.size;
      configuration_.trace_.push_back(packet);
    }
    return 0;
  }

  int run() {
    std::cerr << "Starting to serve consumers" << std::endl;

    signals_.add(SIGINT);
    signals_.async_wait([this](const std::error_code &, const int &) {
      std::cout << "STOPPING!!" << std::endl;
      producer_socket_->stop();
      io_service_.stop();
    });

    if (configuration_.rtc_) {
#ifndef _WIN32
      if (configuration_.interactive_) {
        asio::async_read_until(
            input_, input_buffer_, '\n',
            std::bind(&Impl::handleInput, this, std::placeholders::_1,
                      std::placeholders::_2));
      } else if (configuration_.trace_based_) {
        std::cout << "trace-based mode enabled" << std::endl;
        if (configuration_.trace_file_ == nullptr) {
          std::cout << "cannot find the trace file" << std::endl;
          return ERROR_SETUP;
        }
        if (parseTraceFile() < 0) {
          std::cout << "cannot parse the trace file" << std::endl;
          return ERROR_SETUP;
        }
        rtc_running_ = true;
        rtc_timer_.expires_from_now(std::chrono::milliseconds(1));
        rtc_timer_.async_wait(
            std::bind(&Impl::sendRTCContentObjectCallbackWithTrace, this,
                      std::placeholders::_1));
      } else if (configuration_.input_stream_mode_) {
        rtc_running_ = true;
        // crate socket
        remote_ = asio::ip::udp::endpoint(
            asio::ip::address::from_string("127.0.0.1"), configuration_.port_);
        socket_.open(asio::ip::udp::v4());
        socket_.bind(remote_);
        recv_buffer_.first = (uint8_t *)malloc(1500);
        recv_buffer_.second = 1500;
        receiveStream();
      } else {
        rtc_running_ = true;
        rtc_timer_.expires_from_now(
            configuration_.production_rate_.getMicrosecondsForPacket(
                configuration_.payload_size_));
        rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback,
                                        this, std::placeholders::_1));
      }
#else
      rtc_timer_.expires_from_now(
          configuration_.production_rate_.getMicrosecondsForPacket(
              configuration_.payload_size_));
      rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback, this,
                                      std::placeholders::_1));
#endif
    }

    io_service_.run();

    return ERROR_SUCCESS;
  }

 private:
  hiperf::ServerConfiguration configuration_;
  asio::io_service io_service_;
  asio::signal_set signals_;
  asio::steady_timer rtc_timer_;
  std::vector<uint32_t> unsatisfied_interests_;
  std::vector<std::shared_ptr<ContentObject>> content_objects_;
  std::uint16_t content_objects_index_;
  std::uint16_t mask_;
  std::uint32_t last_segment_;
  std::uint32_t *ptr_last_segment_;
  std::unique_ptr<ProducerSocket> producer_socket_;
#ifndef _WIN32
  asio::posix::stream_descriptor input_;
  asio::streambuf input_buffer_;
  bool rtc_running_;
  Name flow_name_;
  asio::ip::udp::socket socket_;
  asio::ip::udp::endpoint remote_;
  std::pair<uint8_t *, std::size_t> recv_buffer_;
#endif
};

HIperfServer::HIperfServer(const ServerConfiguration &conf) {
  impl_ = new Impl(conf);
}

HIperfServer::~HIperfServer() { delete impl_; }

int HIperfServer::setup() { return impl_->setup(); }

void HIperfServer::run() { impl_->run(); }

}  // namespace hiperf
