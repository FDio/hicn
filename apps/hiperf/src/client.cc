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

#include <client.h>
#include <hicn/transport/portability/endianess.h>

#include <libconfig.h++>

namespace hiperf {

/**
 * Forward declaration of client Read callbacks.
 */
class RTCCallback;
class Callback;

/**
 * Hiperf client class: configure and setup an hicn consumer following the
 * ClientConfiguration.
 */
class HIperfClient::Impl {
  friend class Callback;
  friend class RTCCallback;

  static inline constexpr uint16_t klog2_header_counter() { return 4; }
  static inline constexpr uint16_t kheader_counter_mask() {
    return (1 << klog2_header_counter()) - 1;
  }

  class ConsumerContext
      : public Base<ConsumerContext, ClientConfiguration, Impl>,
        private ConsumerSocket::ReadCallback {
    static inline const std::size_t kmtu = HIPERF_MTU;

   public:
    using ConfType = ClientConfiguration;
    using ParentType = typename HIperfClient::Impl;
    static inline auto getContextType() -> std::string {
      return "ConsumerContext";
    }

    ConsumerContext(Impl &client, int consumer_identifier)
        : Base(client, client.io_service_, consumer_identifier),
          receive_buffer_(
              utils::MemBuf::create(client.config_.receive_buffer_size_)),
          socket_(client.io_service_),
          payload_size_max_(PayloadSize(client.config_.packet_format_)
                                .getPayloadSizeMax(RTC_HEADER_SIZE)),
          nb_iterations_(client.config_.nb_iterations_) {}

    ConsumerContext(ConsumerContext &&other) noexcept
        : Base(std::move(other)),
          receive_buffer_(std::move(other.receive_buffer_)),
          socket_(std::move(other.socket_)),
          payload_size_max_(other.payload_size_max_),
          remote_(std::move(other.remote_)),
          nb_iterations_(other.nb_iterations_),
          saved_stats_(std::move(other.saved_stats_)),
          header_counter_(other.header_counter_),
          first_(other.first_),
          consumer_socket_(std::move(other.consumer_socket_)),
          producer_socket_(std::move(other.producer_socket_)) {}

    ~ConsumerContext() override = default;

    /***************************************************************
     * ConsumerSocket::ReadCallback implementation
     ***************************************************************/

    bool isBufferMovable() noexcept override { return false; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {
      *application_buffer = receive_buffer_->writableData();

      if (configuration_.rtc_) {
        *max_length = kmtu;
      } else {
        *max_length = configuration_.receive_buffer_size_;
      }
    }

    void readBufferAvailable(
        std::unique_ptr<utils::MemBuf> &&buffer) noexcept override {
      // Nothing to do here
      auto ret = std::move(buffer);
    }

    void readDataAvailable(std::size_t length) noexcept override {
      if (configuration_.rtc_) {
        saved_stats_.received_bytes_ += length;
        saved_stats_.received_data_pkt_++;

        // collecting delay stats. Just for performance testing
        auto senderTimeStamp =
            *reinterpret_cast<uint64_t *>(receive_buffer_->writableData());

        auto now = utils::SystemTime::nowMs().count();
        auto new_delay = double(now - senderTimeStamp);

        if (senderTimeStamp > now)
          new_delay = -1 * double(senderTimeStamp - now);

        saved_stats_.delay_sample_++;
        saved_stats_.avg_data_delay_ =
            saved_stats_.avg_data_delay_ +
            (double(new_delay) - saved_stats_.avg_data_delay_) /
                saved_stats_.delay_sample_;

        if (configuration_.test_mode_) {
          saved_stats_.data_delays_ += std::to_string(int(new_delay));
          saved_stats_.data_delays_ += ",";
        }

        if (configuration_.relay_ && configuration_.parallel_flows_ == 1) {
          producer_socket_->produceDatagram(
              configuration_.relay_name_.makeName(),
              receive_buffer_->writableData(),
              length < payload_size_max_ ? length : payload_size_max_);
        }
        if (configuration_.output_stream_mode_ &&
            configuration_.parallel_flows_ == 1) {
          const uint8_t *start = receive_buffer_->writableData();
          start += sizeof(uint64_t);
          std::size_t pkt_len = length - sizeof(uint64_t);
          socket_.send_to(asio::buffer(start, pkt_len), remote_);
        }
      }
    }

    size_t maxBufferSize() const override {
      return configuration_.rtc_ ? kmtu : configuration_.receive_buffer_size_;
    }

    void readError(const std::error_code &ec) noexcept override {
      getOutputStream() << "Error " << ec.message()
                        << " while reading from socket" << std::endl;
      parent_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      if (configuration_.rtc_) {
        getOutputStream() << "Data successfully read" << std::endl;
      } else {
        auto t2 = utils::SteadyTime::now();
        auto dt =
            utils::SteadyTime::getDurationUs(saved_stats_.t_download_, t2);
        auto usec = dt.count();

        getOutputStream() << "Content retrieved. Size: " << total_size
                          << " [Bytes]" << std::endl;

        getOutputStream() << "Elapsed Time: " << usec / 1000000.0
                          << " seconds -- "
                          << double(total_size * 8) * 1.0 / double(usec) * 1.0
                          << " [Mbps]" << std::endl;

        parent_.io_service_.stop();
      }
    }

    /***************************************************************
     * End of ConsumerSocket::ReadCallback implementation
     ***************************************************************/

   private:
    struct SavedStatistics {
      utils::SteadyTime::TimePoint t_stats_{};
      utils::SteadyTime::TimePoint t_download_{};
      uint32_t total_duration_milliseconds_{0};
      uint64_t old_bytes_value_{0};
      uint64_t old_interest_tx_value_{0};
      uint64_t old_fec_interest_tx_value_{0};
      uint64_t old_fec_data_rx_value_{0};
      uint64_t old_lost_data_value_{0};
      uint64_t old_bytes_recovered_value_{0};
      uint64_t old_definitely_lost_data_value_{0};
      uint64_t old_retx_value_{0};
      uint64_t old_sent_int_value_{0};
      uint64_t old_received_nacks_value_{0};
      uint32_t old_fec_pkt_{0};
      // IMPORTANT: to be used only for performance testing, when consumer and
      // producer are synchronized. Used for rtc only at the moment
      double avg_data_delay_{0};
      uint32_t delay_sample_{0};
      uint32_t received_bytes_{0};
      uint32_t received_data_pkt_{0};
      uint32_t auth_alerts_{0};
      std::string data_delays_{""};
    };

    /***************************************************************
     * Transport callbacks
     ***************************************************************/

    void checkReceivedRtcContent(
        [[maybe_unused]] const ConsumerSocket &c,
        [[maybe_unused]] const ContentObject &content_object) const {
      // Nothing to do here
    }

    void processLeavingInterest(const ConsumerSocket & /*c*/,
                                const Interest & /*interest*/) const {
      // Nothing to do here
    }

    transport::auth::VerificationPolicy onAuthFailed(
        transport::auth::Suffix /*suffix*/,
        transport::auth::VerificationPolicy /*policy*/) {
      saved_stats_.auth_alerts_++;
      return transport::auth::VerificationPolicy::ACCEPT;
    }

    void handleTimerExpiration([[maybe_unused]] const ConsumerSocket &c,
                               const TransportStatistics &stats) {
      const char separator = ' ';
      const int width = 18;

      utils::SteadyTime::TimePoint t2 = utils::SteadyTime::Clock::now();
      auto exact_duration =
          utils::SteadyTime::getDurationMs(saved_stats_.t_stats_, t2);

      std::stringstream interval_ms;
      interval_ms << saved_stats_.total_duration_milliseconds_ << "-"
                  << saved_stats_.total_duration_milliseconds_ +
                         exact_duration.count();

      std::stringstream bytes_transferred;
      bytes_transferred << std::fixed << std::setprecision(3)
                        << double(stats.getBytesRecv() -
                                  saved_stats_.old_bytes_value_) /
                               1000000.0
                        << std::setfill(separator);

      std::stringstream bandwidth;
      bandwidth << (double(stats.getBytesRecv() -
                           saved_stats_.old_bytes_value_) *
                    8) /
                       (exact_duration.count()) / 1000.0
                << std::setfill(separator);

      std::stringstream window;
      window << stats.getAverageWindowSize() << std::setfill(separator);

      std::stringstream avg_rtt;
      avg_rtt << std::setprecision(3) << std::fixed << stats.getAverageRtt()
              << std::setfill(separator);

      if (configuration_.rtc_) {
        std::stringstream lost_data;
        lost_data << stats.getLostData() - saved_stats_.old_lost_data_value_
                  << std::setfill(separator);

        std::stringstream bytes_recovered_data;
        bytes_recovered_data << stats.getBytesRecoveredData() -
                                    saved_stats_.old_bytes_recovered_value_
                             << std::setfill(separator);

        std::stringstream definitely_lost_data;
        definitely_lost_data << stats.getDefinitelyLostData() -
                                    saved_stats_.old_definitely_lost_data_value_
                             << std::setfill(separator);

        std::stringstream data_delay;
        data_delay << std::fixed << std::setprecision(3)
                   << saved_stats_.avg_data_delay_ << std::setfill(separator);

        std::stringstream received_data_pkt;
        received_data_pkt << saved_stats_.received_data_pkt_
                          << std::setfill(separator);

        std::stringstream goodput;
        goodput << std::fixed << std::setprecision(3)
                << (saved_stats_.received_bytes_ * 8.0) /
                       (exact_duration.count()) / 1000.0
                << std::setfill(separator);

        std::stringstream loss_rate;
        loss_rate << std::fixed << std::setprecision(2)
                  << stats.getLossRatio() * 100.0 << std::setfill(separator);

        std::stringstream retx_sent;
        retx_sent << stats.getRetxCount() - saved_stats_.old_retx_value_
                  << std::setfill(separator);

        std::stringstream interest_sent;
        interest_sent << stats.getInterestTx() -
                             saved_stats_.old_sent_int_value_
                      << std::setfill(separator);

        std::stringstream nacks;
        nacks << stats.getReceivedNacks() -
                     saved_stats_.old_received_nacks_value_
              << std::setfill(separator);

        std::stringstream fec_pkt;
        fec_pkt << stats.getReceivedFEC() - saved_stats_.old_fec_pkt_
                << std::setfill(separator);

        std::stringstream queuing_delay;
        queuing_delay << std::fixed << std::setprecision(3)
                      << stats.getQueuingDelay() << std::setfill(separator);

        std::stringstream residual_losses;
        double rl_perc = stats.getResidualLossRate() * 100;
        residual_losses << std::fixed << std::setprecision(2) << rl_perc
                        << std::setfill(separator);

        std::stringstream quality_score;
        quality_score << std::fixed << (int)stats.getQualityScore()
                      << std::setfill(separator);

        std::stringstream alerts;
        alerts << stats.getAlerts() << std::setfill(separator);

        std::stringstream auth_alerts;
        auth_alerts << saved_stats_.auth_alerts_ << std::setfill(separator);

        if ((header_counter_ == 0 && configuration_.print_headers_) || first_) {
          getOutputStream() << std::right << std::setw(width) << "Interval[ms]";
          getOutputStream()
              << std::right << std::setw(width) << "RecvData[pkt]";
          getOutputStream()
              << std::right << std::setw(width) << "Bandwidth[Mbps]";
          getOutputStream()
              << std::right << std::setw(width) << "Goodput[Mbps]";
          getOutputStream() << std::right << std::setw(width) << "LossRate[%]";
          getOutputStream() << std::right << std::setw(width) << "Retr[pkt]";
          getOutputStream() << std::right << std::setw(width) << "InterestSent";
          getOutputStream()
              << std::right << std::setw(width) << "ReceivedNacks";
          getOutputStream() << std::right << std::setw(width) << "SyncWnd[pkt]";
          getOutputStream() << std::right << std::setw(width) << "MinRtt[ms]";
          getOutputStream()
              << std::right << std::setw(width) << "QueuingDelay[ms]";
          getOutputStream()
              << std::right << std::setw(width) << "LostData[pkt]";
          getOutputStream()
              << std::right << std::setw(width) << "RecoveredData";
          getOutputStream()
              << std::right << std::setw(width) << "DefinitelyLost";
          getOutputStream() << std::right << std::setw(width) << "State";
          getOutputStream()
              << std::right << std::setw(width) << "DataDelay[ms]";
          getOutputStream() << std::right << std::setw(width) << "FecPkt";
          getOutputStream() << std::right << std::setw(width) << "Congestion";
          getOutputStream()
              << std::right << std::setw(width) << "ResidualLosses";
          getOutputStream() << std::right << std::setw(width) << "QualityScore";
          getOutputStream() << std::right << std::setw(width) << "Alerts";
          getOutputStream()
              << std::right << std::setw(width) << "AuthAlerts" << std::endl;

          first_ = false;
        }

        getOutputStream() << std::right << std::setw(width)
                          << interval_ms.str();
        getOutputStream() << std::right << std::setw(width)
                          << received_data_pkt.str();
        getOutputStream() << std::right << std::setw(width) << bandwidth.str();
        getOutputStream() << std::right << std::setw(width) << goodput.str();
        getOutputStream() << std::right << std::setw(width) << loss_rate.str();
        getOutputStream() << std::right << std::setw(width) << retx_sent.str();
        getOutputStream() << std::right << std::setw(width)
                          << interest_sent.str();
        getOutputStream() << std::right << std::setw(width) << nacks.str();
        getOutputStream() << std::right << std::setw(width) << window.str();
        getOutputStream() << std::right << std::setw(width) << avg_rtt.str();
        getOutputStream() << std::right << std::setw(width)
                          << queuing_delay.str();
        getOutputStream() << std::right << std::setw(width) << lost_data.str();
        getOutputStream() << std::right << std::setw(width)
                          << bytes_recovered_data.str();
        getOutputStream() << std::right << std::setw(width)
                          << definitely_lost_data.str();
        getOutputStream() << std::right << std::setw(width)
                          << stats.getCCStatus();
        getOutputStream() << std::right << std::setw(width) << data_delay.str();
        getOutputStream() << std::right << std::setw(width) << fec_pkt.str();
        getOutputStream() << std::right << std::setw(width)
                          << stats.isCongested();
        getOutputStream() << std::right << std::setw(width)
                          << residual_losses.str();
        getOutputStream() << std::right << std::setw(width)
                          << quality_score.str();
        getOutputStream() << std::right << std::setw(width) << alerts.str();
        getOutputStream() << std::right << std::setw(width) << auth_alerts.str()
                          << std::endl;

        if (configuration_.test_mode_) {
          if (saved_stats_.data_delays_.size() > 0)
            saved_stats_.data_delays_.pop_back();

          auto now = utils::SteadyTime::nowMs();
          getOutputStream() << std::fixed << std::setprecision(0) << now.count()
                            << " DATA-DELAYS:[" << saved_stats_.data_delays_
                            << "]" << std::endl;
        }
      } else {
        if ((header_counter_ == 0 && configuration_.print_headers_) || first_) {
          getOutputStream() << std::right << std::setw(width) << "Interval[ms]";
          getOutputStream() << std::right << std::setw(width) << "Transfer[MB]";
          getOutputStream()
              << std::right << std::setw(width) << "Bandwidth[Mbps]";
          getOutputStream() << std::right << std::setw(width) << "Retr[pkt]";
          getOutputStream() << std::right << std::setw(width) << "Cwnd[Int]";
          getOutputStream()
              << std::right << std::setw(width) << "AvgRtt[ms]" << std::endl;

          first_ = false;
        }

        getOutputStream() << std::right << std::setw(width)
                          << interval_ms.str();
        getOutputStream() << std::right << std::setw(width)
                          << bytes_transferred.str();
        getOutputStream() << std::right << std::setw(width) << bandwidth.str();
        getOutputStream() << std::right << std::setw(width)
                          << stats.getRetxCount();
        getOutputStream() << std::right << std::setw(width) << window.str();
        getOutputStream() << std::right << std::setw(width) << avg_rtt.str()
                          << std::endl;
      }

      saved_stats_.total_duration_milliseconds_ +=
          (uint32_t)exact_duration.count();
      saved_stats_.old_bytes_value_ = stats.getBytesRecv();
      saved_stats_.old_lost_data_value_ = stats.getLostData();
      saved_stats_.old_bytes_recovered_value_ = stats.getBytesRecoveredData();
      saved_stats_.old_definitely_lost_data_value_ =
          stats.getDefinitelyLostData();
      saved_stats_.old_fec_interest_tx_value_ = stats.getInterestFecTxCount();
      saved_stats_.old_fec_data_rx_value_ = stats.getBytesFecRecv();
      saved_stats_.old_retx_value_ = stats.getRetxCount();
      saved_stats_.old_sent_int_value_ = stats.getInterestTx();
      saved_stats_.old_received_nacks_value_ = stats.getReceivedNacks();
      saved_stats_.old_fec_pkt_ = stats.getReceivedFEC();
      saved_stats_.delay_sample_ = 0;
      saved_stats_.avg_data_delay_ = 0;
      saved_stats_.received_bytes_ = 0;
      saved_stats_.received_data_pkt_ = 0;
      saved_stats_.data_delays_ = "";
      saved_stats_.t_stats_ = utils::SteadyTime::Clock::now();

      header_counter_ = (header_counter_ + 1) & kheader_counter_mask();

      if (--nb_iterations_ == 0) {
        // We reached the maximum nb of runs. Stop now.
        parent_.io_service_.stop();
      }
    }

    /***************************************************************
     * Setup functions
     ***************************************************************/

    int setupRTCSocket() {
      int ret = ERROR_SUCCESS;

      configuration_.transport_protocol_ = RTC;

      if (configuration_.relay_ && configuration_.parallel_flows_ == 1) {
        int production_protocol = ProductionProtocolAlgorithms::RTC_PROD;
        producer_socket_ =
            std::make_unique<ProducerSocket>(production_protocol);
        producer_socket_->registerPrefix(configuration_.relay_name_);
        producer_socket_->connect();
        producer_socket_->start();
      }

      if (configuration_.output_stream_mode_ &&
          configuration_.parallel_flows_ == 1) {
        remote_ = asio::ip::udp::endpoint(
            asio::ip::address::from_string("127.0.0.1"), configuration_.port_);
        socket_.open(asio::ip::udp::v4());
      }

      consumer_socket_ =
          std::make_unique<ConsumerSocket>(configuration_.transport_protocol_);

      RtcTransportRecoveryStrategies recovery_strategy =
          RtcTransportRecoveryStrategies::RTX_ONLY;
      switch (configuration_.recovery_strategy_) {
        case 1:
          recovery_strategy = RtcTransportRecoveryStrategies::RECOVERY_OFF;
          break;
        case 2:
          recovery_strategy = RtcTransportRecoveryStrategies::RTX_ONLY;
          break;
        case 3:
          recovery_strategy = RtcTransportRecoveryStrategies::FEC_ONLY;
          break;
        case 4:
          recovery_strategy = RtcTransportRecoveryStrategies::DELAY_BASED;
          break;
        case 5:
          recovery_strategy = RtcTransportRecoveryStrategies::LOW_RATE;
          break;
        case 6:
          recovery_strategy =
              RtcTransportRecoveryStrategies::LOW_RATE_AND_BESTPATH;
          break;
        case 7:
          recovery_strategy =
              RtcTransportRecoveryStrategies::LOW_RATE_AND_REPLICATION;
          break;
        case 8:
          recovery_strategy =
              RtcTransportRecoveryStrategies::LOW_RATE_AND_ALL_FWD_STRATEGIES;
          break;
        case 9:
          recovery_strategy =
              RtcTransportRecoveryStrategies::FEC_ONLY_LOW_RES_LOSSES;
          break;
        case 10:
          recovery_strategy =
              RtcTransportRecoveryStrategies::DELAY_AND_BESTPATH;
          break;
        case 11:
          recovery_strategy =
              RtcTransportRecoveryStrategies::DELAY_AND_REPLICATION;
          break;
        default:
          break;
      }

      ret = consumer_socket_->setSocketOption(
          RtcTransportOptions::RECOVERY_STRATEGY,
          static_cast<uint32_t>(recovery_strategy));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          RtcTransportOptions::AGGREGATED_DATA,
          configuration_.aggregated_data_);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          RtcTransportOptions::CONTENT_SHARING_MODE,
          configuration_.content_sharing_mode_);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
          (ConsumerContentObjectCallback)std::bind(
              &Impl::ConsumerContext::checkReceivedRtcContent, this,
              std::placeholders::_1, std::placeholders::_2));
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      std::shared_ptr<TransportStatistics> transport_stats;
      ret = consumer_socket_->getSocketOption(
          OtherOptions::STATISTICS, (TransportStatistics **)&transport_stats);
      transport_stats->setAlpha(0.0);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      return ERROR_SUCCESS;
    }

    int setupRAAQMSocket() {
      int ret = ERROR_SUCCESS;

      configuration_.transport_protocol_ = RAAQM;

      consumer_socket_ =
          std::make_unique<ConsumerSocket>(configuration_.transport_protocol_);

      if (configuration_.beta_ != -1.f) {
        ret = consumer_socket_->setSocketOption(
            RaaqmTransportOptions::BETA_VALUE, configuration_.beta_);
        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }
      }

      if (configuration_.drop_factor_ != -1.f) {
        ret = consumer_socket_->setSocketOption(
            RaaqmTransportOptions::DROP_FACTOR, configuration_.drop_factor_);
        if (ret == SOCKET_OPTION_NOT_SET) {
          return ERROR_SETUP;
        }
      }

      return ERROR_SUCCESS;
    }

    int setupCBRSocket() {
      configuration_.transport_protocol_ = CBR;

      consumer_socket_ =
          std::make_unique<ConsumerSocket>(configuration_.transport_protocol_);

      return ERROR_SUCCESS;
    }

   public:
    int setup() {
      int ret;
      std::shared_ptr<Verifier> verifier = std::make_shared<VoidVerifier>();

      if (configuration_.rtc_) {
        ret = setupRTCSocket();
      } else if (configuration_.window_ < 0) {
        ret = setupRAAQMSocket();
      } else {
        ret = setupCBRSocket();
      }

      if (ret != ERROR_SUCCESS) {
        return ret;
      }

      ret = consumer_socket_->setSocketOption(
          GeneralTransportOptions::INTEREST_LIFETIME,
          configuration_.interest_lifetime_);
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          GeneralTransportOptions::MANIFEST_FACTOR_RELEVANT,
          configuration_.manifest_factor_relevant_);
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          GeneralTransportOptions::MANIFEST_FACTOR_ALERT,
          configuration_.manifest_factor_alert_);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          GeneralTransportOptions::PACKET_FORMAT,
          configuration_.packet_format_);
      if (ret == SOCKET_OPTION_NOT_SET) {
        getOutputStream() << "ERROR -- Impossible to set the packet format."
                          << std::endl;
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::FWD_STRATEGY_CHANGE,
          (StrategyCallback)[](
              [[maybe_unused]] notification::Strategy strategy){
              // nothing to do
          });
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::REC_STRATEGY_CHANGE,
          (StrategyCallback)[](
              [[maybe_unused]] notification::Strategy strategy){
              // nothing to do
          });
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(CURRENT_WINDOW_SIZE,
                                              configuration_.window_);
      if (ret == SOCKET_OPTION_NOT_SET) {
        getOutputStream()
            << "ERROR -- Impossible to set the size of the window."
            << std::endl;
        return ERROR_SETUP;
      }

      if (!configuration_.producer_certificate_.empty()) {
        verifier = std::make_shared<AsymmetricVerifier>(
            configuration_.producer_certificate_);
      }

      if (!configuration_.passphrase_.empty()) {
        verifier =
            std::make_shared<SymmetricVerifier>(configuration_.passphrase_);
      }

      verifier->setVerificationFailedCallback(
          std::bind(&HIperfClient::Impl::ConsumerContext::onAuthFailed, this,
                    std::placeholders::_1, std::placeholders::_2));

      ret = consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                              verifier);
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      // Signer for aggregatd interests
      std::shared_ptr<Signer> signer = std::make_shared<VoidSigner>();
      if (!configuration_.aggr_interest_passphrase_.empty()) {
        signer = std::make_shared<SymmetricSigner>(
            CryptoSuite::HMAC_SHA256, configuration_.aggr_interest_passphrase_);
      }
      ret = consumer_socket_->setSocketOption(GeneralTransportOptions::SIGNER,
                                              signer);
      if (ret == SOCKET_OPTION_NOT_SET) return ERROR_SETUP;

      if (configuration_.aggregated_interests_) {
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::AGGREGATED_INTERESTS, true);

        if (ret == SOCKET_OPTION_NOT_SET) return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::INTEREST_OUTPUT,
          (ConsumerInterestCallback)std::bind(
              &ConsumerContext::processLeavingInterest, this,
              std::placeholders::_1, std::placeholders::_2));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::READ_CALLBACK, this);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::STATS_SUMMARY,
          (ConsumerTimerCallback)std::bind(
              &Impl::ConsumerContext::handleTimerExpiration, this,
              std::placeholders::_1, std::placeholders::_2));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (consumer_socket_->setSocketOption(
              GeneralTransportOptions::STATS_INTERVAL,
              configuration_.report_interval_milliseconds_) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      consumer_socket_->connect();

      return ERROR_SUCCESS;
    }

    /***************************************************************
     * Run functions
     ***************************************************************/

    int run() {
      getOutputStream() << "Starting download of " << flow_name_ << std::endl;

      saved_stats_.t_download_ = saved_stats_.t_stats_ =
          utils::SteadyTime::now();
      consumer_socket_->consume(flow_name_);

      return ERROR_SUCCESS;
    }

    // Members initialized by the constructor
    std::shared_ptr<utils::MemBuf> receive_buffer_;
    asio::ip::udp::socket socket_;
    std::size_t payload_size_max_;
    asio::ip::udp::endpoint remote_;
    std::uint32_t nb_iterations_;

    // Members initialized by in-class initializer
    SavedStatistics saved_stats_{};
    uint16_t header_counter_{0};
    bool first_{true};
    std::unique_ptr<ConsumerSocket> consumer_socket_;
    std::unique_ptr<ProducerSocket> producer_socket_;
  };

 public:
  explicit Impl(const hiperf::ClientConfiguration &conf)
      : config_(conf), signals_(io_service_) {}

  virtual ~Impl() = default;

  int setup() {
    int ret = ensureFlows(config_.name_, config_.parallel_flows_);
    if (ret != ERROR_SUCCESS) {
      return ret;
    }

    consumer_contexts_.reserve(config_.parallel_flows_);
    for (uint32_t i = 0; i < config_.parallel_flows_; i++) {
      auto &ctx = consumer_contexts_.emplace_back(*this, i);
      ret = ctx.setup();

      if (ret) {
        break;
      }
    }

    return ret;
  }

  int run() {
    signals_.add(SIGINT);
    signals_.async_wait(
        [this](const std::error_code &, const int &) { io_service_.stop(); });

    for (auto &consumer_context : consumer_contexts_) {
      consumer_context.run();
    }

    io_service_.run();

    return ERROR_SUCCESS;
  }

  ClientConfiguration &getConfig() { return config_; }

 private:
  asio::io_service io_service_;
  hiperf::ClientConfiguration config_;
  asio::signal_set signals_;
  std::vector<ConsumerContext> consumer_contexts_;
};

HIperfClient::HIperfClient(const ClientConfiguration &conf)
    : impl_(std::make_unique<Impl>(conf)) {}

HIperfClient::~HIperfClient() = default;

int HIperfClient::setup() const { return impl_->setup(); }

void HIperfClient::run() const { impl_->run(); }

}  // namespace hiperf
