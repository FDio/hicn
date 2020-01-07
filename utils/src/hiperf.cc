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

#include <hicn/transport/interfaces/p2psecure_socket_consumer.h>
#include <hicn/transport/interfaces/p2psecure_socket_producer.h>
#include <hicn/transport/interfaces/rtc_socket_producer.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/identity.h>
#include <hicn/transport/utils/signer.h>
#ifndef _WIN32
#include <hicn/transport/utils/daemonizator.h>
#endif
#include <hicn/transport/utils/literals.h>

#include <fstream>
#include <iomanip>
#include <unordered_set>

#ifdef __linux__
#ifndef __ANDROID__
#include <mcheck.h>
#endif
#endif

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

namespace transport {

namespace interface {

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#define ERROR_SETUP -5
#define MIN_PROBE_SEQ 0xefffffff

/**
 * Container for command line configuration for hiperf client.
 */
struct ClientConfiguration {
  ClientConfiguration()
      : name("b001::abcd", 0), verify(false), beta(-1.f), drop_factor(-1.f),
        window(-1), virtual_download(true), producer_certificate(""),
        passphrase(""), receive_buffer(nullptr), download_size(0),
        report_interval_milliseconds_(1000), transport_protocol_(CBR),
        rtc_(false), test_mode_(false), secure_(false), producer_prefix_(),
        interest_lifetime_(500) {}

  Name name;
  bool verify;
  double beta;
  double drop_factor;
  double window;
  bool virtual_download;
  std::string producer_certificate;
  std::string passphrase;
  std::shared_ptr<utils::MemBuf> receive_buffer;
  std::size_t download_size;
  std::uint32_t report_interval_milliseconds_;
  TransportProtocolAlgorithms transport_protocol_;
  bool rtc_;
  bool test_mode_;
  bool secure_;
  Prefix producer_prefix_;
  uint32_t interest_lifetime_;
};

/**
 * Class for handling the production rate for the RTC producer.
 */
class Rate {
public:
  Rate() : rate_kbps_(0) {}

  Rate(const std::string &rate) {
    std::size_t found = rate.find("kbps");
    if (found != std::string::npos) {
      rate_kbps_ = std::stof(rate.substr(0, found));
    } else {
      throw std::runtime_error("Format " + rate + " not correct");
    }
  }

  Rate(const Rate &other) : rate_kbps_(other.rate_kbps_) {}

  Rate &operator=(const std::string &rate) {
    std::size_t found = rate.find("kbps");
    if (found != std::string::npos) {
      rate_kbps_ = std::stof(rate.substr(0, found));
    } else {
      throw std::runtime_error("Format " + rate + " not correct");
    }

    return *this;
  }

  std::chrono::microseconds getMicrosecondsForPacket(std::size_t packet_size) {
    return std::chrono::microseconds(
        (uint32_t)std::round(packet_size * 1000.0 * 8.0 / (double)rate_kbps_));
  }

private:
  float rate_kbps_;
};

/**
 * Container for command line configuration for hiperf server.
 */
struct ServerConfiguration {
  ServerConfiguration()
      : name("b001::abcd/64"), virtual_producer(true), manifest(false),
        live_production(false), sign(false), content_lifetime(600000000_U32),
        content_object_size(1440), download_size(20 * 1024 * 1024),
        hash_algorithm(HashAlgorithm::SHA_256), keystore_name(""),
        passphrase(""), keystore_password("cisco"), multiphase_produce_(false),
        rtc_(false), interactive_(false),
        production_rate_(std::string("2048kbps")), payload_size_(1400),
        secure_(false) {}

  Prefix name;
  bool virtual_producer;
  bool manifest;
  bool live_production;
  bool sign;
  std::uint32_t content_lifetime;
  std::uint16_t content_object_size;
  std::uint32_t download_size;
  HashAlgorithm hash_algorithm;
  std::string keystore_name;
  std::string passphrase;
  std::string keystore_password;
  bool multiphase_produce_;
  bool rtc_;
  bool interactive_;
  Rate production_rate_;
  std::size_t payload_size_;
  bool secure_;
};

/**
 * Forward declaration of client Read callbacks.
 */
class RTCCallback;
class Callback;
class KeyCallback;

/**
 * Hiperf client class: configure and setup an hicn consumer following the
 * ClientConfiguration.
 */
class HIperfClient {
  typedef std::chrono::time_point<std::chrono::steady_clock> Time;
  typedef std::chrono::microseconds TimeDuration;

  friend class Callback;
  friend class KeyCallback;
  friend class RTCCallback;

public:
  HIperfClient(const ClientConfiguration &conf)
      : configuration_(conf), total_duration_milliseconds_(0),
        old_bytes_value_(0), signals_(io_service_, SIGINT), expected_seg_(0),
        lost_packets_(std::unordered_set<uint32_t>()),
        rtc_callback_(configuration_.rtc_ ? new RTCCallback(*this) : nullptr),
        callback_(configuration_.rtc_ ? nullptr : new Callback(*this)),
        key_callback_(configuration_.rtc_ ? nullptr : new KeyCallback(*this)) {}

  ~HIperfClient() {
    delete callback_;
    delete key_callback_;
    delete rtc_callback_;
  }

  void checkReceivedRtcContent(ConsumerSocket &c,
                               const ContentObject &contentObject) {
    if (!configuration_.test_mode_)
      return;

    uint32_t receivedSeg = contentObject.getName().getSuffix();
    auto payload = contentObject.getPayload();

    if ((uint32_t)payload->length() == 8) { // 8 is the size of the NACK
                                            // payload
      uint32_t *payloadPtr = (uint32_t *)payload->data();
      uint32_t productionSeg = *(payloadPtr);
      uint32_t productionRate = *(++payloadPtr);

      if (productionRate == 0) {
        std::cout << "[STOP] producer is not producing content" << std::endl;
        return;
      }

      if (receivedSeg < productionSeg) {
        std::cout << "[OUT OF SYNCH] received NACK for " << receivedSeg
                  << ". Next expected packet " << productionSeg + 1
                  << std::endl;
        expected_seg_ = productionSeg;
      } else if (receivedSeg > productionSeg && receivedSeg < MIN_PROBE_SEQ) {
        std::cout << "[WINDOW TO LARGE] received NACK for " << receivedSeg
                  << ". Next expected packet " << productionSeg << std::endl;
      } else if (receivedSeg >= MIN_PROBE_SEQ) {
        std::cout << "[PROBE] probe number = " << receivedSeg << std::endl;
      }
      return;
    }

    if (receivedSeg > expected_seg_) {
      for (uint32_t i = expected_seg_; i < receivedSeg; i++) {
        std::cout << "[LOSS] lost packet " << i << std::endl;
        lost_packets_.insert(i);
      }
      expected_seg_ = receivedSeg + 1;
      return;
    } else if (receivedSeg < expected_seg_) {
      auto it = lost_packets_.find(receivedSeg);
      if (it != lost_packets_.end()) {
        std::cout << "[RECOVER] recovered packet " << receivedSeg << std::endl;
        lost_packets_.erase(it);
      } else {
        std::cout << "[OUT OF ORDER] recevied " << receivedSeg << " expedted "
                  << expected_seg_ << std::endl;
      }
      return;
    }
    expected_seg_ = receivedSeg + 1;
  }

  bool verifyData(ConsumerSocket &c, const ContentObject &contentObject) {
    if (contentObject.getPayloadType() == PayloadType::CONTENT_OBJECT) {
      std::cout << "VERIFY CONTENT" << std::endl;
    } else if (contentObject.getPayloadType() == PayloadType::MANIFEST) {
      std::cout << "VERIFY MANIFEST" << std::endl;
    }

    return true;
  }

  void processLeavingInterest(ConsumerSocket &c, const Interest &interest) {}

  void handleTimerExpiration(ConsumerSocket &c,
                             const protocol::TransportStatistics &stats) {
    if (configuration_.rtc_)
      return;

    const char separator = ' ';
    const int width = 20;

    utils::TimePoint t2 = utils::SteadyClock::now();
    auto exact_duration =
        std::chrono::duration_cast<utils::Milliseconds>(t2 - t_stats_);

    std::stringstream interval;
    interval << total_duration_milliseconds_ / 1000 << "-"
             << total_duration_milliseconds_ / 1000 +
                    exact_duration.count() / 1000;

    std::stringstream bytes_transferred;
    bytes_transferred << std::fixed << std::setprecision(3)
                      << (stats.getBytesRecv() - old_bytes_value_) / 1000000.0
                      << std::setfill(separator) << "[MBytes]";

    std::stringstream bandwidth;
    bandwidth << ((stats.getBytesRecv() - old_bytes_value_) * 8) /
                     (exact_duration.count()) / 1000.0
              << std::setfill(separator) << "[Mbps]";

    std::stringstream window;
    window << stats.getAverageWindowSize() << std::setfill(separator)
           << "[Interest]";

    std::stringstream avg_rtt;
    avg_rtt << stats.getAverageRtt() << std::setfill(separator) << "[us]";

    std::cout << std::left << std::setw(width) << "Interval";
    std::cout << std::left << std::setw(width) << "Transfer";
    std::cout << std::left << std::setw(width) << "Bandwidth";
    std::cout << std::left << std::setw(width) << "Retr";
    std::cout << std::left << std::setw(width) << "Cwnd";
    std::cout << std::left << std::setw(width) << "AvgRtt" << std::endl;

    std::cout << std::left << std::setw(width) << interval.str();
    std::cout << std::left << std::setw(width) << bytes_transferred.str();
    std::cout << std::left << std::setw(width) << bandwidth.str();
    std::cout << std::left << std::setw(width) << stats.getRetxCount();
    std::cout << std::left << std::setw(width) << window.str();
    std::cout << std::left << std::setw(width) << avg_rtt.str() << std::endl;
    std::cout << std::endl;

    total_duration_milliseconds_ += (uint32_t)exact_duration.count();
    old_bytes_value_ = stats.getBytesRecv();
    t_stats_ = utils::SteadyClock::now();
  }

  int setup() {
    int ret;

    if (configuration_.rtc_) {
      configuration_.transport_protocol_ = RTC;
    } else if (configuration_.window < 0) {
      configuration_.transport_protocol_ = RAAQM;
    } else {
      configuration_.transport_protocol_ = CBR;
    }

    if (configuration_.secure_) {
      consumer_socket_ = std::make_shared<P2PSecureConsumerSocket>(
          RAAQM, configuration_.transport_protocol_);
      if (configuration_.producer_prefix_.getPrefixLength() == 0) {
        std::cerr << "ERROR -- Missing producer prefix on which perform the "
                     "handshake."
                  << std::endl;
      } else {
        P2PSecureConsumerSocket &secure_consumer_socket =
            *(static_cast<P2PSecureConsumerSocket *>(consumer_socket_.get()));
        secure_consumer_socket.registerPrefix(configuration_.producer_prefix_);
      }
    } else {
      consumer_socket_ =
          std::make_shared<ConsumerSocket>(configuration_.transport_protocol_);
    }

    consumer_socket_->setSocketOption(
        GeneralTransportOptions::INTEREST_LIFETIME,
        configuration_.interest_lifetime_);

#if defined(DEBUG) && defined(__linux__)
    std::shared_ptr<transport::BasePortal> portal;
    consumer_socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal);
    signals_ =
        std::make_unique<asio::signal_set>(portal->getIoService(), SIGUSR1);
    signals_->async_wait([this](const std::error_code &, const int &) {
      std::cout << "Signal SIGUSR1!" << std::endl;
      mtrace();
    });
#endif

    if (consumer_socket_->setSocketOption(CURRENT_WINDOW_SIZE,
                                          configuration_.window) ==
        SOCKET_OPTION_NOT_SET) {
      std::cerr << "ERROR -- Impossible to set the size of the window."
                << std::endl;
      return ERROR_SETUP;
    }

    if (configuration_.transport_protocol_ == RAAQM &&
        configuration_.beta != -1.f) {
      if (consumer_socket_->setSocketOption(RaaqmTransportOptions::BETA_VALUE,
                                            configuration_.beta) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (configuration_.transport_protocol_ == RAAQM &&
        configuration_.drop_factor != -1.f) {
      if (consumer_socket_->setSocketOption(RaaqmTransportOptions::DROP_FACTOR,
                                            configuration_.drop_factor) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (consumer_socket_->setSocketOption(OtherOptions::VIRTUAL_DOWNLOAD,
                                          configuration_.virtual_download) ==
        SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (configuration_.verify) {
      std::shared_ptr<utils::Verifier> verifier =
          std::make_shared<utils::Verifier>();
      PARCKeyId *key_id_;

      if (!configuration_.producer_certificate.empty()) {
        key_id_ = verifier->addKeyFromCertificate(
            configuration_.producer_certificate);
        if (key_id_ == nullptr)
          return ERROR_SETUP;
      }

      if (!configuration_.passphrase.empty()) {
        key_id_ = verifier->addKeyFromPassphrase(
            configuration_.passphrase, utils::CryptoSuite::HMAC_SHA256);
        if (key_id_ == nullptr)
          return ERROR_SETUP;
      }

      if (consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                            verifier) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (consumer_socket_->setSocketOption(
            GeneralTransportOptions::VERIFY_SIGNATURE, configuration_.verify) ==
        SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::INTEREST_OUTPUT,
        (ConsumerInterestCallback)std::bind(
            &HIperfClient::processLeavingInterest, this, std::placeholders::_1,
            std::placeholders::_2));

    if (ret == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (!configuration_.rtc_) {
      /* key_callback_->setConsumer(consumer_socket_); */
      /* consumer_socket_->setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
       * key_callback_); */
      /* consumer_socket_->setSocketOption(GeneralTransportOptions::KEY_CONTENT,
       * true); */
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::READ_CALLBACK, callback_);
    } else {
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::READ_CALLBACK, rtc_callback_);
    }

    if (ret == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (configuration_.rtc_) {
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
          (ConsumerContentObjectCallback)std::bind(
              &HIperfClient::checkReceivedRtcContent, this,
              std::placeholders::_1, std::placeholders::_2));
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::STATS_SUMMARY,
        (ConsumerTimerCallback)std::bind(&HIperfClient::handleTimerExpiration,
                                         this, std::placeholders::_1,
                                         std::placeholders::_2));

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

  int run() {
    std::cout << "Starting download of " << configuration_.name << std::endl;

    signals_.async_wait([this](const std::error_code &, const int &) {
      consumer_socket_->stop();
      io_service_.stop();
    });

    t_download_ = t_stats_ = std::chrono::steady_clock::now();
    consumer_socket_->asyncConsume(configuration_.name);
    io_service_.run();

    return ERROR_SUCCESS;
  }

private:
  class RTCCallback : public ConsumerSocket::ReadCallback {
    static constexpr std::size_t mtu = 1500;

  public:
    RTCCallback(HIperfClient &hiperf_client) : client_(hiperf_client) {
      client_.configuration_.receive_buffer = utils::MemBuf::create(mtu);
    }

    bool isBufferMovable() noexcept override { return false; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {
      *application_buffer =
          client_.configuration_.receive_buffer->writableData();
      *max_length = mtu;
    }

    void readDataAvailable(std::size_t length) noexcept override {}

    size_t maxBufferSize() const override { return mtu; }

    void readError(const std::error_code ec) noexcept override {
      std::cerr << "Error while reading from RTC socket" << std::endl;
      client_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      std::cout << "Data successfully read" << std::endl;
    }

  private:
    HIperfClient &client_;
  };

  class Callback : public ConsumerSocket::ReadCallback {
    static constexpr std::size_t read_size = 16 * 1024;

  public:
    Callback(HIperfClient &hiperf_client) : client_(hiperf_client) {}

    bool isBufferMovable() noexcept override { return true; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {}

    void readDataAvailable(std::size_t length) noexcept override {}

    void readBufferAvailable(
        std::unique_ptr<utils::MemBuf> &&buffer) noexcept override {}

    size_t maxBufferSize() const override { return read_size; }

    void readError(const std::error_code ec) noexcept override {
      std::cerr << "Error " << ec.message() << " while reading from socket"
                << std::endl;
      client_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      Time t2 = std::chrono::steady_clock::now();
      TimeDuration dt =
          std::chrono::duration_cast<TimeDuration>(t2 - client_.t_download_);
      long usec = (long)dt.count();

      std::cout << "Content retrieved. Size: " << total_size << " [Bytes]"
                << std::endl;

      std::cerr << "Elapsed Time: " << usec / 1000000.0 << " seconds -- "
                << (total_size * 8) * 1.0 / usec * 1.0 << " [Mbps]"
                << std::endl;

      client_.io_service_.stop();
    }

  private:
    HIperfClient &client_;
  };

  class KeyCallback : public ConsumerSocket::ReadCallback {
    static constexpr std::size_t read_size = 16 * 1024;

  public:
    KeyCallback(HIperfClient &hiperf_client)
        : client_(hiperf_client), key_(nullptr) {}

    bool isBufferMovable() noexcept override { return true; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {}

    void readDataAvailable(std::size_t length) noexcept override {}

    void readBufferAvailable(
        std::unique_ptr<utils::MemBuf> &&buffer) noexcept override {
      key_ = std::make_unique<std::string>((const char *)buffer->data(),
                                           buffer->length());
      std::cout << "Key: " << *key_ << std::endl;
    }

    size_t maxBufferSize() const override { return read_size; }

    void readError(const std::error_code ec) noexcept override {
      std::cerr << "Error " << ec.message() << " while reading from socket"
                << std::endl;
      client_.io_service_.stop();
    }

    bool verifyKey() { return !key_->empty(); }

    void readSuccess(std::size_t total_size) noexcept override {
      std::cout << "Key size: " << total_size << " bytes" << std::endl;
    }

    void afterRead() override {
      std::shared_ptr<utils::Verifier> verifier =
          std::make_shared<utils::Verifier>();
      verifier->addKeyFromPassphrase(*key_, utils::CryptoSuite::HMAC_SHA256);

      if (consumer_socket_) {
        consumer_socket_->setSocketOption(GeneralTransportOptions::KEY_CONTENT,
                                          false);
        consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                          verifier);
      } else {
        std::cout << "Could not set verifier" << std::endl;
        return;
      }

      if (consumer_socket_->verifyKeyPackets()) {
        std::cout << "Verification of packet signatures successful"
                  << std::endl;
      } else {
        std::cout << "Could not verify packet signatures" << std::endl;
        return;
      }

      std::cout << "Key retrieval done" << std::endl;
    }

    void setConsumer(std::shared_ptr<ConsumerSocket> consumer_socket) {
      consumer_socket_ = consumer_socket;
    }

  private:
    HIperfClient &client_;
    std::unique_ptr<std::string> key_;
    std::shared_ptr<ConsumerSocket> consumer_socket_;
  };

  ClientConfiguration configuration_;
  Time t_stats_;
  Time t_download_;
  uint32_t total_duration_milliseconds_;
  uint64_t old_bytes_value_;
  asio::io_service io_service_;
  asio::signal_set signals_;
  std::shared_ptr<ConsumerSocket> consumer_socket_;
  uint32_t expected_seg_;
  std::unordered_set<uint32_t> lost_packets_;
  RTCCallback *rtc_callback_;
  Callback *callback_;
  KeyCallback *key_callback_;
};

/**
 * Hiperf server class: configure and setup an hicn producer following the
 * ServerConfiguration.
 */
class HIperfServer {
  const std::size_t log2_content_object_buffer_size = 8;

public:
  HIperfServer(ServerConfiguration &conf)
      : configuration_(conf), signals_(io_service_, SIGINT),
        rtc_timer_(io_service_), unsatisfied_interests_(),
        content_objects_((std::uint16_t)(1 << log2_content_object_buffer_size)),
        content_objects_index_(0),
        mask_((std::uint16_t)(1 << log2_content_object_buffer_size) - 1),
        last_segment_(0), ptr_last_segment_(&last_segment_),
#ifndef _WIN32
        input_(io_service_), rtc_running_(false)
#endif
  {
    std::string buffer(configuration_.payload_size_, 'X');
    std::cout << "Producing contents under name " << conf.name.getName()
              << std::endl;
#ifndef _WIN32
    if (configuration_.interactive_) {
      input_.assign(::dup(STDIN_FILENO));
    }
#endif

    for (int i = 0; i < (1 << log2_content_object_buffer_size); i++) {
      content_objects_[i] = std::make_shared<ContentObject>(
          conf.name.getName(), HF_INET6_TCP, (const uint8_t *)buffer.data(),
          buffer.size());
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
                      (ProducerInterestCallback)bind(
                          &HIperfServer::cacheMiss, this, std::placeholders::_1,
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

  void produceContent(ProducerSocket &p, Name content_name, uint32_t suffix) {
    auto b = utils::MemBuf::create(configuration_.download_size);
    std::memset(b->writableData(), '?', configuration_.download_size);
    b->append(configuration_.download_size);
    uint32_t total;

    utils::TimePoint t0 = utils::SteadyClock::now();
    total = p.produce(content_name, std::move(b),
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
    /* std::string passphrase = "hunter2"; */
    /* auto b = utils::MemBuf::create(passphrase.length() + 1); */
    /* std::memcpy(b->writableData(), passphrase.c_str(), passphrase.length() +
     * 1); */
    /* b->append(passphrase.length() + 1); */

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
                          &HIperfServer::asyncProcessInterest, this,
                          std::placeholders::_1, std::placeholders::_2));
  }

  std::shared_ptr<utils::Identity>
  getProducerIdentity(std::string &keystore_name,
                      std::string &keystore_password,
                      HashAlgorithm &hash_algorithm) {
    if (access(keystore_name.c_str(), F_OK) != -1) {
      return std::make_shared<utils::Identity>(keystore_name, keystore_password,
                                               hash_algorithm);
    } else {
      return std::make_shared<utils::Identity>(keystore_name, keystore_password,
                                               utils::CryptoSuite::RSA_SHA256,
                                               1024, 365, "producer-test");
    }
  }

  int setup() {
    int ret;

    if (configuration_.secure_) {
      auto identity = getProducerIdentity(configuration_.keystore_name,
                                          configuration_.keystore_password,
                                          configuration_.hash_algorithm);
      producer_socket_ = std::make_unique<P2PSecureProducerSocket>(
          configuration_.rtc_, identity);
    } else {
      if (configuration_.rtc_) {
        producer_socket_ = std::make_unique<RTCProducerSocket>();
      } else {
        producer_socket_ = std::make_unique<ProducerSocket>();
      }
    }

    if (configuration_.sign) {
      std::shared_ptr<utils::Signer> signer;

      if (!configuration_.passphrase.empty()) {
        signer = std::make_shared<utils::Signer>(
            configuration_.passphrase, utils::CryptoSuite::HMAC_SHA256);
      } else if (!configuration_.keystore_name.empty()) {
        auto identity = getProducerIdentity(configuration_.keystore_name,
                                            configuration_.keystore_password,
                                            configuration_.hash_algorithm);
        signer = identity->getSigner();
      } else {
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(GeneralTransportOptions::SIGNER,
                                            signer) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

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
              GeneralTransportOptions::MAKE_MANIFEST,
              configuration_.manifest) == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (producer_socket_->setSocketOption(
              GeneralTransportOptions::DATA_PACKET_SIZE,
              (uint32_t)(configuration_.payload_size_)) ==
          SOCKET_OPTION_NOT_SET) {
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
            (ProducerInterestCallback)bind(&HIperfServer::asyncProcessInterest,
                                           this, std::placeholders::_1,
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
          (ProducerInterestCallback)bind(&HIperfServer::virtualProcessInterest,
                                         this, std::placeholders::_1,
                                         std::placeholders::_2));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    ret = producer_socket_->setSocketOption(
        ProducerCallbacksOptions::CONTENT_PRODUCED,
        (ProducerContentCallback)bind(
            &HIperfServer::onContentProduced, this, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3));

    return ERROR_SUCCESS;
  }

  void sendRTCContentObjectCallback(std::error_code ec) {
    if (ec)
      return;
    rtc_timer_.expires_from_now(
        configuration_.production_rate_.getMicrosecondsForPacket(
            configuration_.payload_size_));
    rtc_timer_.async_wait(std::bind(&HIperfServer::sendRTCContentObjectCallback,
                                    this, std::placeholders::_1));
    auto payload =
        content_objects_[content_objects_index_++ & mask_]->getPayload();
    producer_socket_->produce(payload->data(), payload->length());
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
      rtc_timer_.async_wait(
          std::bind(&HIperfServer::sendRTCContentObjectCallback, this,
                    std::placeholders::_1));
    }

    input_buffer_.consume(length); // Remove newline from input.
    asio::async_read_until(input_, input_buffer_, '\n',
                           std::bind(&HIperfServer::handleInput, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  }
#endif

  int run() {
    std::cerr << "Starting to serve consumers" << std::endl;

    signals_.async_wait([this](const std::error_code &, const int &) {
      std::cout << "STOPPING!!" << std::endl;
      producer_socket_->stop();
      io_service_.stop();
    });

    if (configuration_.rtc_) {
#ifndef _WIN32
      if (configuration_.interactive_) {
        asio::async_read_until(input_, input_buffer_, '\n',
                               std::bind(&HIperfServer::handleInput, this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));
      } else {
        rtc_running_ = true;
        rtc_timer_.expires_from_now(
            configuration_.production_rate_.getMicrosecondsForPacket(
                configuration_.payload_size_));
        rtc_timer_.async_wait(
            std::bind(&HIperfServer::sendRTCContentObjectCallback, this,
                      std::placeholders::_1));
      }
#else
      rtc_timer_.expires_from_now(
          configuration_.production_rate_.getMicrosecondsForPacket(
              configuration_.payload_size_));
      rtc_timer_.async_wait(
          std::bind(&HIperfServer::sendRTCContentObjectCallback, this,
                    std::placeholders::_1));
#endif
    }

    io_service_.run();

    return ERROR_SUCCESS;
  }

private:
  ServerConfiguration configuration_;
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
#endif
};

void usage() {
  std::cerr << "HIPERF - A tool for performing network throughput "
               "measurements with hICN"
            << std::endl;
  std::cerr << "usage: hiperf [-S|-C] [options] [prefix|name]" << std::endl;
  std::cerr << std::endl;
  std::cerr << "SERVER OR CLIENT:" << std::endl;
#ifndef _WIN32
  std::cerr << "-D\t\t\t\t\t"
            << "Run as a daemon" << std::endl;
  std::cerr << "-R\t\t\t\t\t"
            << "Run RTC protocol (client or server)" << std::endl;
  std::cerr << "-f\t<filename>\t\t\t"
            << "Log file" << std::endl;
#endif
  std::cerr << std::endl;
  std::cerr << "SERVER SPECIFIC:" << std::endl;
  std::cerr << "-A\t<content_size>\t\t\t"
               "Size of the content to publish. This "
               "is not the size of the packet (see -s for it)."
            << std::endl;
  std::cerr << "-s\t<packet_size>\t\t\tSize of the payload of each data packet."
            << std::endl;
  std::cerr << "-r\t\t\t\t\t"
            << "Produce real content of <content_size> bytes" << std::endl;
  std::cerr << "-m\t\t\t\t\t"
            << "Produce transport manifest" << std::endl;
  std::cerr << "-l\t\t\t\t\t"
            << "Start producing content upon the reception of the "
               "first interest"
            << std::endl;
  std::cerr << "-K\t<keystore_path>\t\t\t"
            << "Path of p12 file containing the "
               "crypto material used for signing packets"
            << std::endl;
  std::cerr << "-k\t<passphrase>\t\t\t"
            << "String from which a 128-bit symmetric key will be "
               "derived for signing packets"
            << std::endl;
  std::cerr << "-y\t<hash_algorithm>\t\t"
            << "Use the selected hash algorithm for "
               "calculating manifest digests"
            << std::endl;
  std::cerr << "-p\t<password>\t\t\t"
            << "Password for p12 keystore" << std::endl;
  std::cerr << "-x\t\t\t\t\t"
            << "Produce a content of <content_size>, then after downloading "
               "it produce a new content of"
            << "\n\t\t\t\t\t<content_size> without resetting "
               "the suffix to 0."
            << std::endl;
  std::cerr << "-B\t<bitrate>\t\t\t"
            << "Bitrate for RTC producer, to be used with the -R option."
            << std::endl;
#ifndef _WIN32
  std::cerr << "-I\t\t\t\t\t"
               "Interactive mode, start/stop real time content production "
               "by pressing return. To be used with the -R option"
            << std::endl;
  std::cerr << "-E\t\t\t\t\t"
            << "Enable encrypted communication. Requires the path to a p12 "
               "file containing the "
               "crypto material used for the TLS handshake"
            << std::endl;
#endif
  std::cerr << std::endl;
  std::cerr << "CLIENT SPECIFIC:" << std::endl;
  std::cerr << "-b\t<beta_parameter>\t\t"
            << "RAAQM beta parameter" << std::endl;
  std::cerr << "-d\t<drop_factor_parameter>\t\t"
            << "RAAQM drop factor "
               "parameter"
            << std::endl;
  std::cerr << "-L\t<interest lifetime>\t\t"
            << "Set interest lifetime." << std::endl;
  std::cerr << "-M\t<Download for real>\t\t"
            << "Store the content downloaded." << std::endl;
  std::cerr << "-W\t<window_size>\t\t\t"
            << "Use a fixed congestion window "
               "for retrieving the data."
            << std::endl;
  std::cerr << "-i\t<stats_interval>\t\t"
            << "Show the statistics every <stats_interval> milliseconds."
            << std::endl;
  std::cerr << "-v\t\t\t\t\t"
            << "Enable verification of received data" << std::endl;
  std::cerr << "-c\t<certificate_path>\t\t"
            << "Path of the producer certificate to be used for verifying the "
               "origin of the packets received. Must be used with -v."
            << std::endl;
  std::cerr << "-k\t<passphrase>\t\t\t"
            << "String from which is derived the symmetric key used by the "
               "producer to sign packets and by the consumer to verify them. "
               "Must be used with -v."
            << std::endl;
  std::cerr << "-t\t\t\t\t\t"
               "Test mode, check if the client is receiving the "
               "correct data. This is an RTC specific option, to be "
               "used with the -R (default false)"
            << std::endl;
  std::cerr << "-P\t\t\t\t\t"
            << "Prefix of the producer where to do the handshake" << std::endl;
}

int main(int argc, char *argv[]) {
#ifndef _WIN32
  // Common
  bool daemon = false;
#else
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  // -1 server, 0 undefined, 1 client
  int role = 0;
  int options = 0;

  char *log_file = nullptr;

  // Consumer
  ClientConfiguration client_configuration;

  // Producer
  ServerConfiguration server_configuration;

  int opt;
#ifndef _WIN32
  while ((opt = getopt(argc, argv,
                       "DSCf:b:d:W:RMc:vA:s:rmlK:k:y:p:hi:xE:P:B:ItL:")) !=
         -1) {
    switch (opt) {
    // Common
    case 'D': {
      daemon = true;
      break;
    }
    case 'I': {
      server_configuration.interactive_ = true;
      break;
    }
#else
  while ((opt = getopt(argc, argv,
                       "SCf:b:d:W:RMc:vA:s:rmlK:k:y:p:hi:xB:E:P:tL:")) != -1) {
    switch (opt) {
#endif
    case 'f': {
      log_file = optarg;
      break;
    }
    case 'R': {
      client_configuration.rtc_ = true;
      server_configuration.rtc_ = true;
      break;
    }

    // Server or Client
    case 'S': {
      role -= 1;
      break;
    }
    case 'C': {
      role += 1;
      break;
    }
    case 'k': {
      server_configuration.passphrase = std::string(optarg);
      client_configuration.passphrase = std::string(optarg);
      server_configuration.sign = true;
      options = -1;
      break;
    }

    // Client specifc
    case 'b': {
      client_configuration.beta = std::stod(optarg);
      options = 1;
      break;
    }
    case 'd': {
      client_configuration.drop_factor = std::stod(optarg);
      options = 1;
      break;
    }
    case 'W': {
      client_configuration.window = std::stod(optarg);
      options = 1;
      break;
    }
    case 'M': {
      client_configuration.virtual_download = false;
      options = 1;
      break;
    }
    case 'P': {
      client_configuration.producer_prefix_ = Prefix(optarg);
      client_configuration.secure_ = true;
      break;
    }
    case 'c': {
      client_configuration.producer_certificate = std::string(optarg);
      options = 1;
      break;
    }
    case 'v': {
      client_configuration.verify = true;
      options = 1;
      break;
    }
    case 'i': {
      client_configuration.report_interval_milliseconds_ = std::stoul(optarg);
      options = 1;
      break;
    }
    case 't': {
      client_configuration.test_mode_ = true;
      options = 1;
      break;
    }
    case 'L': {
      client_configuration.interest_lifetime_ = std::stoul(optarg);
      options = 1;
      break;
    }
    // Server specific
    case 'A': {
      server_configuration.download_size = std::stoul(optarg);
      options = -1;
      break;
    }
    case 's': {
      server_configuration.payload_size_ = std::stoul(optarg);
      options = -1;
      break;
    }
    case 'r': {
      server_configuration.virtual_producer = false;
      options = -1;
      break;
    }
    case 'm': {
      server_configuration.manifest = true;
      options = -1;
      break;
    }
    case 'l': {
      server_configuration.live_production = true;
      options = -1;
      break;
    }
    case 'K': {
      server_configuration.keystore_name = std::string(optarg);
      server_configuration.sign = true;
      options = -1;
      break;
    }
    case 'y': {
      if (strncasecmp(optarg, "sha256", 6) == 0) {
        server_configuration.hash_algorithm = HashAlgorithm::SHA_256;
      } else if (strncasecmp(optarg, "sha512", 6) == 0) {
        server_configuration.hash_algorithm = HashAlgorithm::SHA_512;
      } else if (strncasecmp(optarg, "crc32", 5) == 0) {
        server_configuration.hash_algorithm = HashAlgorithm::CRC32C;
      } else {
        std::cerr << "Ignored unknown hash algorithm. Using SHA 256."
                  << std::endl;
      }
      options = -1;
      break;
    }
    case 'p': {
      server_configuration.keystore_password = std::string(optarg);
      options = -1;
      break;
    }
    case 'x': {
      server_configuration.multiphase_produce_ = true;
      options = -1;
      break;
    }
    case 'B': {
      auto str = std::string(optarg);
      std::transform(str.begin(), str.end(), str.begin(), ::tolower);
      std::cout << "---------------------------------------------------------"
                   "---------------------->"
                << str << std::endl;
      server_configuration.production_rate_ = str;
      options = -1;
      break;
    }
    case 'E': {
      server_configuration.keystore_name = std::string(optarg);
      server_configuration.secure_ = true;
      break;
    }
    case 'h':
    default:
      usage();
      return EXIT_FAILURE;
    }
  }

  if (options > 0 && role < 0) {
    std::cerr << "Client options cannot be used when using the "
                 "software in server mode"
              << std::endl;
    usage();
    return EXIT_FAILURE;

  } else if (options < 0 && role > 0) {
    std::cerr << "Server options cannot be used when using the "
                 "software in client mode"
              << std::endl;
    usage();
    return EXIT_FAILURE;
  } else if (!role) {
    std::cerr << "Please specify if running hiperf as client "
                 "or server."
              << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  if (argv[optind] == 0) {
    std::cerr << "Please specify the name/prefix to use." << std::endl;
    usage();
    return EXIT_FAILURE;
  } else {
    if (role > 0) {
      client_configuration.name = Name(argv[optind]);
    } else {
      server_configuration.name = Prefix(argv[optind]);
    }
  }

  if (log_file) {
#ifndef _WIN32
    int fd = open(log_file, O_WRONLY | O_APPEND | O_CREAT, S_IWUSR | S_IRUSR);
    dup2(fd, STDOUT_FILENO);
    dup2(STDOUT_FILENO, STDERR_FILENO);
    close(fd);
#else
    int fd =
        _open(log_file, _O_WRONLY | _O_APPEND | _O_CREAT, _S_IWRITE | _S_IREAD);
    _dup2(fd, _fileno(stdout));
    _dup2(_fileno(stdout), _fileno(stderr));
    _close(fd);
#endif
  }

#ifndef _WIN32
  if (daemon) {
    utils::Daemonizator::daemonize(false);
  }
#endif

  if (role > 0) {
    HIperfClient c(client_configuration);
    if (c.setup() != ERROR_SETUP) {
      c.run();
    }
  } else if (role < 0) {
    HIperfServer s(server_configuration);
    if (s.setup() != ERROR_SETUP) {
      s.run();
    }
  } else {
    usage();
    return EXIT_FAILURE;
  }

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

} // end namespace interface

} // end namespace transport

int main(int argc, char *argv[]) {
  return transport::interface::main(argc, argv);
}
