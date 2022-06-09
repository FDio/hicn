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
  static inline constexpr std::size_t klog2_content_object_buffer_size() {
    return 8;
  }
  static inline constexpr std::size_t kcontent_object_buffer_size() {
    return (1 << klog2_content_object_buffer_size());
  }
  static inline constexpr std::size_t kmask() {
    return (kcontent_object_buffer_size() - 1);
  }

  /**
   * @brief As we can (potentially) setup many producer sockets, we need to keep
   * a separate context for each one of them. The context contains parameters
   * and variable that are specific to a single producer socket.
   */
  class ProducerContext
      : public Base<ProducerContext, ServerConfiguration, Impl>,
        public ProducerSocket::Callback {
   public:
    using ConfType = ServerConfiguration;
    using ParentType = typename HIperfServer::Impl;
    static inline const auto getContextType() { return "ProducerContext"; }

    ProducerContext(HIperfServer::Impl &server, int producer_identifier)
        : Base(server, server.io_service_, producer_identifier) {}

    // To make vector happy (move or copy constructor is needed when vector
    // resizes)
    ProducerContext(ProducerContext &&other) noexcept
        : Base(std::move(other)),
          unsatisfied_interests_(std::move(other.unsatisfied_interests_)),
          last_segment_(other.last_segment_),
          producer_socket_(std::move(other.producer_socket_)),
          content_objects_index_(other.content_objects_index_),
          payload_size_max_(other.payload_size_max_) {}

    virtual ~ProducerContext() = default;

    /**
     * @brief Produce datagram
     */
    void produceDatagram(const uint8_t *buffer, std::size_t buffer_size) const {
      assert(producer_socket_);

      auto size = std::min(buffer_size, payload_size_max_);

      producer_socket_->produceDatagram(flow_name_, buffer, size);
    }

    /**
     * @brief Create and setup the producer socket
     */
    int setup() {
      int ret;
      int production_protocol;
      std::shared_ptr<Signer> signer = std::make_shared<VoidSigner>();

      if (!configuration_.rtc_) {
        production_protocol = ProductionProtocolAlgorithms::BYTE_STREAM;
      } else {
        production_protocol = ProductionProtocolAlgorithms::RTC_PROD;
      }

      producer_socket_ = std::make_unique<ProducerSocket>(production_protocol);

      if (producer_socket_->setSocketOption(
              ProducerCallbacksOptions::PRODUCER_CALLBACK, this) ==
          SOCKET_OPTION_NOT_SET) {
        getOutputStream() << "Failed to set producer callback." << std::endl;
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::HASH_ALGORITHM,
              configuration_.hash_algorithm_) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::MANIFEST_MAX_CAPACITY,
              configuration_.manifest_max_capacity_) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(PACKET_FORMAT,
                                            configuration_.packet_format_) ==
          SOCKET_OPTION_NOT_SET) {
        getOutputStream() << "ERROR -- Impossible to set the packet format."
                          << std::endl;
        return ERROR_SETUP;
      }

      if (!configuration_.passphrase_.empty()) {
        signer = std::make_shared<SymmetricSigner>(CryptoSuite::HMAC_SHA256,
                                                   configuration_.passphrase_);
      }

      if (!configuration_.keystore_name_.empty()) {
        signer = std::make_shared<AsymmetricSigner>(
            configuration_.keystore_name_, configuration_.keystore_password_);
      }

      producer_socket_->setSocketOption(GeneralTransportOptions::SIGNER,
                                        signer);

      // Compute maximum payload size
      Packet::Format format = PayloadSize::getFormatFromPrefix(
          configuration_.name_, !configuration_.manifest_max_capacity_);
      payload_size_max_ = PayloadSize(format).getPayloadSizeMax(
          configuration_.rtc_ ? RTC_HEADER_SIZE : 0,
          configuration_.fec_type_.empty() ? 0 : FEC_HEADER_MAX_SIZE,
          !configuration_.manifest_max_capacity_
              ? signer->getSignatureFieldSize()
              : 0);

      if (configuration_.payload_size_ > payload_size_max_) {
        getOutputStream() << "WARNING: Payload has size "
                          << configuration_.payload_size_ << ", maximum is "
                          << payload_size_max_
                          << ". Payload will be truncated to fit." << std::endl;
      }

      // Verifier for aggregated interests
      std::shared_ptr<Verifier> verifier = std::make_shared<VoidVerifier>();
      if (!configuration_.aggr_interest_passphrase_.empty()) {
        verifier = std::make_unique<SymmetricVerifier>(
            configuration_.aggr_interest_passphrase_);
      }
      ret = producer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                              verifier);
      if (ret == SOCKET_OPTION_NOT_SET) return ERROR_SETUP;

      if (configuration_.rtc_) {
        ret = producer_socket_->setSocketOption(
            RtcTransportOptions::AGGREGATED_DATA,
            configuration_.aggregated_data_);

        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }

        ret = producer_socket_->setSocketOption(
            GeneralTransportOptions::FEC_TYPE, configuration_.fec_type_);

        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }
      }

      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
              configuration_.content_lifetime_) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      producer_socket_->registerPrefix(Prefix(flow_name_, 128));
      producer_socket_->connect();
      producer_socket_->start();

      if (configuration_.rtc_) {
        return ERROR_SUCCESS;
      }

      if (!configuration_.virtual_producer_) {
        if (producer_socket_->setSocketOption(
                GeneralTransportOptions::OUTPUT_BUFFER_SIZE, 200000U) ==
            SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }

        if (producer_socket_->setSocketOption(
                GeneralTransportOptions::MAX_SEGMENT_SIZE,
                static_cast<uint32_t>(configuration_.payload_size_)) ==
            SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }

        if (!configuration_.live_production_) {
          produceContent(*producer_socket_, configuration_.name_.makeName(), 0);
        } else {
          ret = producer_socket_->setSocketOption(
              ProducerCallbacksOptions::CACHE_MISS,
              (ProducerInterestCallback)bind(
                  &ProducerContext::asyncProcessInterest, this,
                  std::placeholders::_1, std::placeholders::_2));

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
            (ProducerInterestCallback)bind(
                &ProducerContext::virtualProcessInterest, this,
                std::placeholders::_1, std::placeholders::_2));

        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }
      }

      ret = producer_socket_->setSocketOption(
          ProducerCallbacksOptions::CONTENT_PRODUCED,
          (ProducerContentCallback)bind(
              &ProducerContext::onContentProduced, this, std::placeholders::_1,
              std::placeholders::_2, std::placeholders::_3));
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      return ERROR_SUCCESS;
    }

    int run() {
      getOutputStream() << "started to serve consumers with name " << flow_name_
                        << std::endl;
      return ERROR_SUCCESS;
    }

    void stop() {
      getOutputStream() << "stopped to serve consumers" << std::endl;
      producer_socket_->stop();
    }

   private:
    /**
     * @brief Produce an existing content object. Set the name as the
     * interest.
     */
    void virtualProcessInterest(ProducerSocket &p, const Interest &interest) {
      parent_.content_objects_[content_objects_index_ & kmask()]->setName(
          interest.getName());
      p.produce(*parent_.content_objects_[content_objects_index_++ & kmask()]);
    }

    /**
     * @brief Create and produce a buffer of configuration_.download_size_
     * length.
     */
    void produceContent(ProducerSocket &p, const Name &content_name,
                        uint32_t suffix) const {
      uint32_t total;

      auto b = utils::MemBuf::create(configuration_.download_size_);
      std::memset(b->writableData(), '?', configuration_.download_size_);
      b->append(configuration_.download_size_);

      utils::SteadyTime::TimePoint t0 = utils::SteadyTime::Clock::now();
      total = p.produceStream(content_name, std::move(b),
                              !configuration_.multiphase_produce_, suffix);
      utils::SteadyTime::TimePoint t1 = utils::SteadyTime::Clock::now();

      Logger() << "Written " << total
               << " data packets in output buffer (Segmentation time: "
               << utils::SteadyTime::getDurationUs(t0, t1).count() << " us)"
               << std::endl;
    }

    /**
     * @brief Synchronously produce content upon reception of one interest
     */
    void processInterest(ProducerSocket &p, const Interest &interest) const {
      p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                        (ProducerInterestCallback)VOID_HANDLER);
      p.setSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                        configuration_.content_lifetime_);

      produceContent(p, interest.getName(), interest.getName().getSuffix());
      Logger() << "Received interest " << interest.getName().getSuffix()
               << std::endl;
    }

    /**
     * @brief Async create and produce a buffer of
     * configuration_.download_size_ length.
     */
    void produceContentAsync(ProducerSocket &p, Name content_name,
                             uint32_t suffix) {
      parent_.produce_thread_.add([this, suffix, content_name, &p]() {
        auto b = utils::MemBuf::create(configuration_.download_size_);
        std::memset(b->writableData(), '?', configuration_.download_size_);
        b->append(configuration_.download_size_);

        last_segment_ =
            suffix + p.produceStream(content_name, std::move(b),
                                     !configuration_.multiphase_produce_,
                                     suffix);
      });
    }

    /**
     * @brief Asynchronously produce content upon reception of one interest
     */
    void asyncProcessInterest(ProducerSocket &p, const Interest &interest) {
      p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                        (ProducerInterestCallback)bind(
                            &ProducerContext::cacheMiss, this,
                            std::placeholders::_1, std::placeholders::_2));
      p.setSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                        configuration_.content_lifetime_);
      uint32_t suffix = interest.getName().getSuffix();

      if (suffix == 0) {
        last_segment_ = 0;
        unsatisfied_interests_.clear();
      }

      // The suffix will either come from the received interest or will be set
      // to the smallest suffix of a previous interest not satisfied
      if (!unsatisfied_interests_.empty()) {
        auto it = std::lower_bound(unsatisfied_interests_.begin(),
                                   unsatisfied_interests_.end(), last_segment_);
        if (it != unsatisfied_interests_.end()) {
          suffix = *it;
        }
        unsatisfied_interests_.erase(unsatisfied_interests_.begin(), it);
      }

      getOutputStream() << " Received interest "
                        << interest.getName().getSuffix()
                        << ", starting production at " << suffix << end_mod_
                        << std::endl;
      getOutputStream() << unsatisfied_interests_.size()
                        << " interests still unsatisfied" << end_mod_
                        << std::endl;
      produceContentAsync(p, interest.getName(), suffix);
    }

    /**
     * @brief Register cache miss events
     */
    void cacheMiss([[maybe_unused]] const ProducerSocket &p,
                   const Interest &interest) {
      unsatisfied_interests_.push_back(interest.getName().getSuffix());
    }

    /**
     * @brief When content is produced, set cache miss callback so that we can
     * register any cache miss happening after the production.
     */
    void onContentProduced(ProducerSocket &p,
                           [[maybe_unused]] const std::error_code &err,
                           [[maybe_unused]] uint64_t bytes_written) {
      p.setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                        (ProducerInterestCallback)bind(
                            &ProducerContext::asyncProcessInterest, this,
                            std::placeholders::_1, std::placeholders::_2));
    }

    /**
     * @brief Internal producer error. When this callback is triggered
     * something important happened. Here we stop the program.
     */
    void produceError(const std::error_code &err) noexcept override {
      getOutputStream() << "Error from producer transport: " << err.message()
                        << std::endl;
      parent_.stop();
    }

    // Members initialized by in-class initializer
    std::vector<uint32_t> unsatisfied_interests_;
    std::uint32_t last_segment_{0};
    std::unique_ptr<ProducerSocket> producer_socket_{nullptr};
    std::uint16_t content_objects_index_{0};
    std::size_t payload_size_max_{0};
  };

 public:
  explicit Impl(const hiperf::ServerConfiguration &conf) : config_(conf) {
#ifndef _WIN32
    if (config_.interactive_) {
      input_.assign(::dup(STDIN_FILENO));
    }
#endif

    // Allocate buffer to copy as content objects payload
    std::string buffer(config_.payload_size_, 'X');

    // Allocate array of content objects. They are share_ptr so that the
    // transport will only capture a reference to them instead of performing
    // an hard copy.
    for (std::size_t i = 0; i < kcontent_object_buffer_size(); i++) {
      const auto &element =
          content_objects_.emplace_back(std::make_shared<ContentObject>(
              config_.name_.makeName(), config_.packet_format_, 0,
              (const uint8_t *)buffer.data(), buffer.size()));
      element->setLifetime(default_values::content_object_expiry_time);
    }
  }

  ~Impl() = default;

  int setup() {
    int ret = ensureFlows(config_.name_, config_.parallel_flows_);
    if (ret != ERROR_SUCCESS) {
      return ret;
    }

    producer_contexts_.reserve(config_.parallel_flows_);
    for (uint32_t i = 0; i < config_.parallel_flows_; i++) {
      auto &ctx = producer_contexts_.emplace_back(*this, i);
      ret = ctx.setup();

      if (ret) {
        break;
      }
    }

    return ret;
  }

  void receiveStream() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_.writableData(), recv_buffer_.capacity()),
        remote_, [this](const std::error_code &ec, std::size_t length) {
          if (ec) return;
          sendRTCContentFromStream(recv_buffer_.writableData(), length);
          receiveStream();
        });
  }

  void sendRTCContentFromStream(const uint8_t *buff, std::size_t len) {
    auto payload = content_objects_[0]->getPayload();
    // this is used to compute the data packet delay
    // Used only for performance evaluation
    // It requires clock synchronization between producer and consumer
    auto now = utils::SystemTime::nowMs().count();

    auto start = payload->writableData();
    std::memcpy(start, &now, sizeof(uint64_t));
    std::memcpy(start + sizeof(uint64_t), buff, len);

    for (const auto &producer_context : producer_contexts_) {
      producer_context.produceDatagram(start, len + sizeof(uint64_t));
    }
  }

  void sendRTCContentObjectCallback(const std::error_code &ec) {
    if (ec) return;
    rtc_timer_.expires_from_now(
        config_.production_rate_.getMicrosecondsForPacket(
            config_.payload_size_));
    rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback, this,
                                    std::placeholders::_1));
    auto payload = content_objects_[0]->getPayload();

    // this is used to compute the data packet delay
    // Used only for performance evaluation
    // It requires clock synchronization between producer and consumer
    auto now = utils::SystemTime::nowMs().count();
    std::memcpy(payload->writableData(), &now, sizeof(uint64_t));

    for (const auto &producer_context : producer_contexts_) {
      producer_context.produceDatagram(payload->data(), payload->length());
    }
  }

  void sendRTCContentObjectCallbackWithTrace(const std::error_code &ec) {
    if (ec) return;

    auto payload = content_objects_[0]->getPayload();

    std::size_t packet_len = config_.trace_[config_.trace_index_].size;

    // this is used to compute the data packet delay
    // used only for performance evaluation
    // it requires clock synchronization between producer and consumer
    auto now = utils::SystemTime::nowMs().count();
    std::memcpy(payload->writableData(), &now, sizeof(uint64_t));

    if (packet_len > payload->length()) packet_len = payload->length();

    for (const auto &producer_context : producer_contexts_) {
      producer_context.produceDatagram(payload->data(), packet_len);
    }

    uint32_t next_index = config_.trace_index_ + 1;
    uint64_t schedule_next;
    if (next_index < config_.trace_.size()) {
      schedule_next = config_.trace_[next_index].timestamp -
                      config_.trace_[config_.trace_index_].timestamp;
    } else {
      // here we need to loop, schedule in a random time
      schedule_next = 1000;
    }

    config_.trace_index_ = (config_.trace_index_ + 1) % config_.trace_.size();
    rtc_timer_.expires_from_now(std::chrono::microseconds(schedule_next));
    rtc_timer_.async_wait(
        std::bind(&Impl::sendRTCContentObjectCallbackWithTrace, this,
                  std::placeholders::_1));
  }

  int parseTraceFile() {
    std::ifstream trace(config_.trace_file_);
    if (trace.fail()) {
      return -1;
    }
    std::string line;
    while (std::getline(trace, line)) {
      std::istringstream iss(line);
      hiperf::packet_t packet;
      iss >> packet.timestamp >> packet.size;
      config_.trace_.push_back(packet);
    }
    return 0;
  }

#ifndef _WIN32
  void handleInput(const std::error_code &error, std::size_t length) {
    if (error) {
      stop();
    }

    if (rtc_running_) {
      Logger() << "stop real time content production" << std::endl;
      rtc_running_ = false;
      rtc_timer_.cancel();
    } else {
      Logger() << "start real time content production" << std::endl;
      rtc_running_ = true;
      rtc_timer_.expires_from_now(
          config_.production_rate_.getMicrosecondsForPacket(
              config_.payload_size_));
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

  void stop() {
    for (auto &producer_context : producer_contexts_) {
      producer_context.stop();
    }

    io_service_.stop();
  }

  int run() {
    signals_.add(SIGINT);
    signals_.async_wait(
        [this](const std::error_code &, const int &) { stop(); });

    if (config_.rtc_) {
      if (config_.interactive_) {
        asio::async_read_until(
            input_, input_buffer_, '\n',
            std::bind(&Impl::handleInput, this, std::placeholders::_1,
                      std::placeholders::_2));
      } else if (config_.trace_based_) {
        Logger() << "trace-based mode enabled" << std::endl;
        if (config_.trace_file_ == nullptr) {
          Logger() << "cannot find the trace file" << std::endl;
          return ERROR_SETUP;
        }
        if (parseTraceFile() < 0) {
          Logger() << "cannot parse the trace file" << std::endl;
          return ERROR_SETUP;
        }
        rtc_running_ = true;
        rtc_timer_.expires_from_now(std::chrono::milliseconds(1));
        rtc_timer_.async_wait(
            std::bind(&Impl::sendRTCContentObjectCallbackWithTrace, this,
                      std::placeholders::_1));
      } else if (config_.input_stream_mode_) {
        rtc_running_ = true;
        // create socket
        remote_ = asio::ip::udp::endpoint(
            asio::ip::address::from_string("127.0.0.1"), config_.port_);
        socket_.open(asio::ip::udp::v4());
        socket_.bind(remote_);
        receiveStream();
      } else {
        rtc_running_ = true;
        rtc_timer_.expires_from_now(
            config_.production_rate_.getMicrosecondsForPacket(
                config_.payload_size_));
        rtc_timer_.async_wait(std::bind(&Impl::sendRTCContentObjectCallback,
                                        this, std::placeholders::_1));
      }
    }

    for (auto &producer_context : producer_contexts_) {
      producer_context.run();
    }

    io_service_.run();

    return ERROR_SUCCESS;
  }

  ServerConfiguration &getConfig() { return config_; }

 private:
  // Variables initialized by the constructor.
  ServerConfiguration config_;

  // Variable initialized in the in-class initializer list.
  asio::io_service io_service_;
  asio::signal_set signals_{io_service_};
  asio::steady_timer rtc_timer_{io_service_};
  asio::posix::stream_descriptor input_{io_service_};
  asio::ip::udp::socket socket_{io_service_};
  std::vector<ContentObject::Ptr> content_objects_;
  std::vector<ProducerContext> producer_contexts_;
  ::utils::EventThread produce_thread_;
  asio::streambuf input_buffer_;
  bool rtc_running_{false};
  asio::ip::udp::endpoint remote_;
  utils::MemBuf recv_buffer_{utils::MemBuf::CREATE, HIPERF_MTU};
};

HIperfServer::HIperfServer(const ServerConfiguration &conf)
    : impl_(std::make_unique<Impl>(conf)) {}

HIperfServer::~HIperfServer() = default;

int HIperfServer::setup() { return impl_->setup(); }

void HIperfServer::run() { impl_->run(); }

}  // namespace hiperf
