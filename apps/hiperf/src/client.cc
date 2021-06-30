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
#include <forwarder_config.h>
#include <forwarder_interface.h>

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
class HIperfClient::Impl
#ifdef FORWARDER_INTERFACE
    : ForwarderInterface::ICallback
#endif
{
  typedef std::chrono::time_point<std::chrono::steady_clock> Time;
  typedef std::chrono::microseconds TimeDuration;

  friend class Callback;
  friend class RTCCallback;

  struct nack_packet_t {
    uint64_t timestamp;
    uint32_t prod_rate;
    uint32_t prod_seg;

    inline uint64_t getTimestamp() const { return _ntohll(&timestamp); }
    inline void setTimestamp(uint64_t time) { timestamp = _htonll(&time); }

    inline uint32_t getProductionRate() const { return ntohl(prod_rate); }
    inline void setProductionRate(uint32_t rate) { prod_rate = htonl(rate); }

    inline uint32_t getProductionSegement() const { return ntohl(prod_seg); }
    inline void setProductionSegement(uint32_t seg) { prod_seg = htonl(seg); }
  };

 public:
  Impl(const hiperf::ClientConfiguration &conf)
      : configuration_(conf),
        total_duration_milliseconds_(0),
        old_bytes_value_(0),
        old_interest_tx_value_(0),
        old_fec_interest_tx_value_(0),
        old_fec_data_rx_value_(0),
        old_lost_data_value_(0),
        old_bytes_recovered_value_(0),
        old_definitely_lost_data_value_(0),
        old_retx_value_(0),
        old_sent_int_value_(0),
        old_received_nacks_value_(0),
        old_fec_pkt_(0),
        avg_data_delay_(0),
        delay_sample_(0),
        received_bytes_(0),
        received_data_pkt_(0),
        data_delays_(""),
        signals_(io_service_),
        rtc_callback_(*this),
        callback_(*this),
        socket_(io_service_),
        done_(false),
        switch_threshold_(~0)
#ifdef FORWARDER_INTERFACE
        ,
        forwarder_interface_(io_service_, this)
#endif
  {
  }

  ~Impl() {}

  void checkReceivedRtcContent(ConsumerSocket &c,
                               const ContentObject &contentObject) {}

  void processLeavingInterest(ConsumerSocket &c, const Interest &interest) {}

  void addFace(const std::string &local_address, uint16_t local_port,
               const std::string &remote_address, uint16_t remote_port,
               std::string interface);

  void handleTimerExpiration(ConsumerSocket &c,
                             const TransportStatistics &stats) {
    const char separator = ' ';
    const int width = 15;

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
                      << std::setfill(separator) << "[MB]";

    std::stringstream bandwidth;
    bandwidth << ((stats.getBytesRecv() - old_bytes_value_) * 8) /
                     (exact_duration.count()) / 1000.0
              << std::setfill(separator) << "[Mbps]";

    std::stringstream window;
    window << stats.getAverageWindowSize() << std::setfill(separator)
           << "[Int]";

    std::stringstream avg_rtt;
    avg_rtt << stats.getAverageRtt() << std::setfill(separator) << "[ms]";

    if (configuration_.rtc_) {
      // we get rtc stats more often, thus we need ms in the interval
      std::stringstream interval_ms;
      interval_ms << total_duration_milliseconds_ << "-"
                  << total_duration_milliseconds_ + exact_duration.count();

      std::stringstream lost_data;
      lost_data << stats.getLostData() - old_lost_data_value_
                << std::setfill(separator) << "[pkt]";

      std::stringstream bytes_recovered_data;
      bytes_recovered_data << stats.getBytesRecoveredData() -
                                  old_bytes_recovered_value_
                           << std::setfill(separator) << "[pkt]";

      std::stringstream definitely_lost_data;
      definitely_lost_data << stats.getDefinitelyLostData() -
                                  old_definitely_lost_data_value_
                           << std::setfill(separator) << "[pkt]";

      std::stringstream data_delay;
      data_delay << avg_data_delay_ << std::setfill(separator) << "[ms]";

      std::stringstream received_data_pkt;
      received_data_pkt << received_data_pkt_ << std::setfill(separator)
                        << "[pkt]";

      std::stringstream goodput;
      goodput << (received_bytes_ * 8.0) / (exact_duration.count()) / 1000.0
              << std::setfill(separator) << "[Mbps]";

      std::stringstream loss_rate;
      loss_rate << std::fixed << std::setprecision(2)
                << stats.getLossRatio() * 100.0 << std::setfill(separator)
                << "[%]";

      std::stringstream retx_sent;
      retx_sent << stats.getRetxCount() - old_retx_value_
                << std::setfill(separator) << "[pkt]";

      std::stringstream interest_sent;
      interest_sent << stats.getInterestTx() - old_sent_int_value_
                    << std::setfill(separator) << "[pkt]";

      std::stringstream nacks;
      nacks << stats.getReceivedNacks() - old_received_nacks_value_
            << std::setfill(separator) << "[pkt]";

      std::stringstream fec_pkt;
      fec_pkt << stats.getReceivedFEC() - old_fec_pkt_
              << std::setfill(separator) << "[pkt]";

      std::stringstream queuing_delay;
      queuing_delay << stats.getQueuingDelay() << std::setfill(separator)
                    << "[ms]";

#ifdef FORWARDER_INTERFACE
      if (!done_ && stats.getQueuingDelay() >= switch_threshold_ &&
          total_duration_milliseconds_ > 1000) {
        std::cout << "Switching due to queuing delay" << std::endl;
        forwarder_interface_.createFaceAndRoutes(backup_routes_);
        forwarder_interface_.deleteFaceAndRoutes(main_routes_);
        std::swap(backup_routes_, main_routes_);
        done_ = true;
      }
#endif

      // statistics not yet available in the transport
      // std::stringstream interest_fec_tx;
      // interest_fec_tx << stats.getInterestFecTxCount() -
      //    old_fec_interest_tx_value_ << std::setfill(separator) << "[pkt]";
      // std::stringstream bytes_fec_recv;
      // bytes_fec_recv << stats.getBytesFecRecv() - old_fec_data_rx_value_
      //              << std::setfill(separator) << "[bytes]";
      std::cout << std::left << std::setw(width) << "Interval";
      std::cout << std::left << std::setw(width) << "RecvData";
      std::cout << std::left << std::setw(width) << "Bandwidth";
      std::cout << std::left << std::setw(width) << "Goodput";
      std::cout << std::left << std::setw(width) << "LossRate";
      std::cout << std::left << std::setw(width) << "Retr";
      std::cout << std::left << std::setw(width) << "InterestSent";
      std::cout << std::left << std::setw(width) << "ReceivedNacks";
      std::cout << std::left << std::setw(width) << "SyncWnd";
      std::cout << std::left << std::setw(width) << "MinRtt";
      std::cout << std::left << std::setw(width) << "QueuingDelay";
      std::cout << std::left << std::setw(width) << "LostData";
      std::cout << std::left << std::setw(width) << "RecoveredData";
      std::cout << std::left << std::setw(width) << "DefinitelyLost";
      std::cout << std::left << std::setw(width) << "State";
      std::cout << std::left << std::setw(width) << "DataDelay";
      std::cout << std::left << std::setw(width) << "FecPkt" << std::endl;

      std::cout << std::left << std::setw(width) << interval_ms.str();
      std::cout << std::left << std::setw(width) << received_data_pkt.str();
      std::cout << std::left << std::setw(width) << bandwidth.str();
      std::cout << std::left << std::setw(width) << goodput.str();
      std::cout << std::left << std::setw(width) << loss_rate.str();
      std::cout << std::left << std::setw(width) << retx_sent.str();
      std::cout << std::left << std::setw(width) << interest_sent.str();
      std::cout << std::left << std::setw(width) << nacks.str();
      std::cout << std::left << std::setw(width) << window.str();
      std::cout << std::left << std::setw(width) << avg_rtt.str();
      std::cout << std::left << std::setw(width) << queuing_delay.str();
      std::cout << std::left << std::setw(width) << lost_data.str();
      std::cout << std::left << std::setw(width) << bytes_recovered_data.str();
      std::cout << std::left << std::setw(width) << definitely_lost_data.str();
      std::cout << std::left << std::setw(width) << stats.getCCStatus();
      std::cout << std::left << std::setw(width) << data_delay.str();
      std::cout << std::left << std::setw(width) << fec_pkt.str();
      std::cout << std::endl;

      if (configuration_.test_mode_) {
        if (data_delays_.size() > 0) data_delays_.pop_back();

        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        std::cout << now << " DATA-DELAYS:[" << data_delays_ << "]"
                  << std::endl;
      }

      // statistics not yet available in the transport
      // std::cout << std::left << std::setw(width) << interest_fec_tx.str();
      // std::cout << std::left << std::setw(width) << bytes_fec_recv.str();
    } else {
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
    }
    total_duration_milliseconds_ += (uint32_t)exact_duration.count();
    old_bytes_value_ = stats.getBytesRecv();
    old_lost_data_value_ = stats.getLostData();
    old_bytes_recovered_value_ = stats.getBytesRecoveredData();
    old_definitely_lost_data_value_ = stats.getDefinitelyLostData();
    old_fec_interest_tx_value_ = stats.getInterestFecTxCount();
    old_fec_data_rx_value_ = stats.getBytesFecRecv();
    old_retx_value_ = stats.getRetxCount();
    old_sent_int_value_ = stats.getInterestTx();
    old_received_nacks_value_ = stats.getReceivedNacks();
    old_fec_pkt_ = stats.getReceivedFEC();
    delay_sample_ = 0;
    avg_data_delay_ = 0;
    received_bytes_ = 0;
    received_data_pkt_ = 0;
    data_delays_ = "";

    t_stats_ = utils::SteadyClock::now();
  }

  bool parseConfig(const char *conf_file) {
    using namespace libconfig;
    Config cfg;

    try {
      cfg.readFile(conf_file);
    } catch (const FileIOException &fioex) {
      std::cerr << "I/O error while reading file." << std::endl;
      return false;
    } catch (const ParseException &pex) {
      std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
                << " - " << pex.getError() << std::endl;
      return false;
    }

    Setting &config = cfg.getRoot();

    if (config.exists("switch_threshold")) {
      unsigned threshold;
      config.lookupValue("switch_threshold", threshold);
      switch_threshold_ = threshold;
    }

    // listeners
    if (config.exists("listeners")) {
      // get path where looking for modules
      const Setting &listeners = config.lookup("listeners");
      auto count = listeners.getLength();

      for (int i = 0; i < count; i++) {
        const Setting &listener = listeners[i];
        ListenerConfig list;
        unsigned port;
        std::string interface;

        list.name = listener.getName();
        listener.lookupValue("local_address", list.address);
        listener.lookupValue("local_port", port);
        listener.lookupValue("interface", list.interface);
        list.port = (uint16_t)(port);

        std::cout << "Adding listener " << list.name << ", ( " << list.address
                  << ":" << list.port << ")" << std::endl;
        config_.addListener(std::move(list));
      }
    }

    // connectors
    if (config.exists("connectors")) {
      // get path where looking for modules
      const Setting &connectors = config.lookup("connectors");
      auto count = connectors.getLength();

      for (int i = 0; i < count; i++) {
        const Setting &connector = connectors[i];
        ConnectorConfig conn;

        conn.name = connector.getName();
        unsigned port = 0;

        if (!connector.lookupValue("local_address", conn.local_address)) {
          conn.local_address = "";
        }

        if (!connector.lookupValue("local_port", port)) {
          port = 0;
        }

        conn.local_port = (uint16_t)(port);

        if (!connector.lookupValue("remote_address", conn.remote_address)) {
          std::cerr
              << "Error in configuration file: remote_address is a mandatory "
                 "field of Connectors."
              << std::endl;
          return false;
        }

        if (!connector.lookupValue("remote_port", port)) {
          std::cerr << "Error in configuration file: remote_port is a "
                       "mandatory field of Connectors."
                    << std::endl;
          return false;
        }

        if (!connector.lookupValue("interface", conn.interface)) {
          std::cerr << "Error in configuration file: interface is a "
                       "mandatory field of Connectors."
                    << std::endl;
          return false;
        }

        conn.remote_port = (uint16_t)(port);

        std::cout << "Adding connector " << conn.name << ", ("
                  << conn.local_address << ":" << conn.local_port << " "
                  << conn.remote_address << ":" << conn.remote_port << ")"
                  << std::endl;
        config_.addConnector(conn.name, std::move(conn));
      }
    }

    // Routes
    if (config.exists("routes")) {
      const Setting &routes = config.lookup("routes");
      auto count = routes.getLength();

      for (int i = 0; i < count; i++) {
        const Setting &route = routes[i];
        RouteConfig r;
        unsigned weight;

        r.name = route.getName();
        route.lookupValue("prefix", r.prefix);
        route.lookupValue("weight", weight);
        route.lookupValue("main_connector", r.main_connector);
        route.lookupValue("backup_connector", r.backup_connector);
        r.weight = (uint16_t)(weight);

        std::cout << "Adding route " << r.name << " " << r.prefix << " ("
                  << r.main_connector << " " << r.backup_connector << " "
                  << r.weight << ")" << std::endl;
        config_.addRoute(std::move(r));
      }
    }

    std::cout << "Ok" << std::endl;

    return true;
  }

  bool splitRoute(std::string route, std::string &prefix,
                  uint8_t &prefix_length) {
    std::string delimiter = "/";

    size_t pos = 0;
    if ((pos = route.find(delimiter)) != std::string::npos) {
      prefix = route.substr(0, pos);
      route.erase(0, pos + delimiter.length());
    } else {
      return false;
    }

    prefix_length = std::stoul(route.substr(0));
    return true;
  }

#ifdef FORWARDER_INTERFACE
  void onHicnServiceReady() override {
    std::cout << "Successfully connected to local forwarder!" << std::endl;

    std::cout << "Setting up listeners" << std::endl;
    const char *config = getenv("FORWARDER_CONFIG");

    if (config) {
      if (!parseConfig(config)) {
        return;
      }

      // Create faces and route using first face in the list.
      auto &routes = config_.getRoutes();
      auto &connectors = config_.getConnectors();

      if (routes.size() == 0 || connectors.size() == 0) {
        std::cerr << "Nothing to configure" << std::endl;
        return;
      }

      for (auto &route : routes) {
        auto the_connector_it = connectors.find(route.main_connector);
        if (the_connector_it == connectors.end()) {
          std::cerr << "No valid main connector found for route " << route.name
                    << std::endl;
          continue;
        }

        auto &the_connector = the_connector_it->second;
        auto route_info = std::make_shared<ForwarderInterface::RouteInfo>();
        route_info->family = AF_INET;
        route_info->local_addr = the_connector.local_address;
        route_info->local_port = the_connector.local_port;
        route_info->remote_addr = the_connector.remote_address;
        route_info->remote_port = the_connector.remote_port;
        route_info->interface = the_connector.interface;
        route_info->name = the_connector.name;

        std::string prefix;
        uint8_t prefix_length;
        auto ret = splitRoute(route.prefix, prefix, prefix_length);

        if (!ret) {
          std::cerr << "Error parsing route" << std::endl;
          return;
        }

        route_info->route_addr = prefix;
        route_info->route_len = prefix_length;

        main_routes_.emplace_back(route_info);

        if (!route.backup_connector.empty()) {
          // Add also the backup route
          auto the_backup_connector_it =
              connectors.find(route.backup_connector);
          if (the_backup_connector_it == connectors.end()) {
            std::cerr << "No valid backup connector found for route "
                      << route.name << std::endl;
            continue;
          }

          auto &the_backup_connector = the_backup_connector_it->second;
          auto backup_route_info =
              std::make_shared<ForwarderInterface::RouteInfo>();
          backup_route_info->family = AF_INET;
          backup_route_info->local_addr = the_backup_connector.local_address;
          backup_route_info->local_port = the_backup_connector.local_port;
          backup_route_info->remote_addr = the_backup_connector.remote_address;
          backup_route_info->remote_port = the_backup_connector.remote_port;
          backup_route_info->interface = the_backup_connector.interface;
          backup_route_info->name = the_backup_connector.name;

          std::string prefix;
          uint8_t prefix_length;
          auto ret = splitRoute(route.prefix, prefix, prefix_length);

          if (!ret) {
            std::cerr << "Error parsing route" << std::endl;
            return;
          }

          backup_route_info->route_addr = prefix;
          backup_route_info->route_len = prefix_length;

          backup_routes_.emplace_back(backup_route_info);
        }
      }

      // Create main routes
      std::cout << "Creating main routes" << std::endl;
      forwarder_interface_.createFaceAndRoutes(main_routes_);
    }
  }

  void onRouteConfigured(
      std::vector<ForwarderInterface::RouteInfoPtr> &route_info) override {
    std::cout << "Routes successfully configured!" << std::endl;
  }
#endif

  int setup() {
    int ret;

    if (configuration_.rtc_) {
      configuration_.transport_protocol_ = RTC;
    } else if (configuration_.window < 0) {
      configuration_.transport_protocol_ = RAAQM;
    } else {
      configuration_.transport_protocol_ = CBR;
    }

    if (configuration_.relay_ && configuration_.rtc_) {
      int production_protocol = ProductionProtocolAlgorithms::RTC_PROD;
      producer_socket_ = std::make_unique<ProducerSocket>(production_protocol);
      producer_socket_->registerPrefix(configuration_.relay_name_);
      producer_socket_->connect();
    }

    if (configuration_.output_stream_mode_ && configuration_.rtc_) {
      remote_ = asio::ip::udp::endpoint(
          asio::ip::address::from_string("127.0.0.1"), configuration_.port_);
      socket_.open(asio::ip::udp::v4());
    }

    if (configuration_.secure_) {
      consumer_socket_ = std::make_unique<P2PSecureConsumerSocket>(
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
          std::make_unique<ConsumerSocket>(configuration_.transport_protocol_);
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

    if (!configuration_.producer_certificate.empty()) {
      std::shared_ptr<Verifier> verifier = std::make_shared<AsymmetricVerifier>(
          configuration_.producer_certificate);
      if (consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                            verifier) == SOCKET_OPTION_NOT_SET)
        return ERROR_SETUP;
    }

    if (!configuration_.passphrase.empty()) {
      std::shared_ptr<Verifier> verifier =
          std::make_shared<SymmetricVerifier>(configuration_.passphrase);
      if (consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                            verifier) == SOCKET_OPTION_NOT_SET)
        return ERROR_SETUP;
    }

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::INTEREST_OUTPUT,
        (ConsumerInterestCallback)std::bind(&Impl::processLeavingInterest, this,
                                            std::placeholders::_1,
                                            std::placeholders::_2));

    if (ret == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (!configuration_.rtc_) {
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::READ_CALLBACK, &callback_);
    } else {
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::READ_CALLBACK, &rtc_callback_);
    }

    if (ret == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (configuration_.rtc_) {
      ret = consumer_socket_->setSocketOption(
          ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
          (ConsumerContentObjectCallback)std::bind(
              &Impl::checkReceivedRtcContent, this, std::placeholders::_1,
              std::placeholders::_2));
      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (configuration_.rtc_) {
      std::shared_ptr<TransportStatistics> transport_stats;
      consumer_socket_->getSocketOption(
          OtherOptions::STATISTICS, (TransportStatistics **)&transport_stats);
      transport_stats->setAlpha(0.0);
    }

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::STATS_SUMMARY,
        (ConsumerTimerCallback)std::bind(&Impl::handleTimerExpiration, this,
                                         std::placeholders::_1,
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

    signals_.add(SIGINT);
    signals_.async_wait(
        [this](const std::error_code &, const int &) { io_service_.stop(); });

    t_download_ = t_stats_ = std::chrono::steady_clock::now();
    consumer_socket_->asyncConsume(configuration_.name);
    io_service_.run();

    consumer_socket_->stop();

    return ERROR_SUCCESS;
  }

 private:
  class RTCCallback : public ConsumerSocket::ReadCallback {
    static constexpr std::size_t mtu = 1500;

   public:
    RTCCallback(Impl &hiperf_client) : client_(hiperf_client) {
      client_.configuration_.receive_buffer = utils::MemBuf::create(mtu);
    }

    bool isBufferMovable() noexcept override { return false; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {
      *application_buffer =
          client_.configuration_.receive_buffer->writableData();
      *max_length = mtu;
    }

    void readDataAvailable(std::size_t length) noexcept override {
      client_.received_bytes_ += length;
      client_.received_data_pkt_++;

      // collecting delay stats. Just for performance testing
      uint64_t *senderTimeStamp =
          (uint64_t *)client_.configuration_.receive_buffer->writableData();

      uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
      double new_delay = (double)(now - *senderTimeStamp);

      if (*senderTimeStamp > now)
        new_delay = -1 * (double)(*senderTimeStamp - now);

      client_.delay_sample_++;
      client_.avg_data_delay_ =
          client_.avg_data_delay_ +
          (new_delay - client_.avg_data_delay_) / client_.delay_sample_;

      if (client_.configuration_.test_mode_) {
        client_.data_delays_ += std::to_string(int(new_delay));
        client_.data_delays_ += ",";
      }

      if (client_.configuration_.relay_) {
        client_.producer_socket_->produceDatagram(
            client_.configuration_.relay_name_.getName(),
            client_.configuration_.receive_buffer->writableData(),
            length < 1400 ? length : 1400);
      }
      if (client_.configuration_.output_stream_mode_) {
        uint8_t *start =
            (uint8_t *)client_.configuration_.receive_buffer->writableData();
        start += sizeof(uint64_t);
        std::size_t pkt_len = length - sizeof(uint64_t);
        client_.socket_.send_to(asio::buffer(start, pkt_len), client_.remote_);
      }
    }

    size_t maxBufferSize() const override { return mtu; }

    void readError(const std::error_code ec) noexcept override {
      std::cerr << "Error while reading from RTC socket" << std::endl;
      client_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      std::cout << "Data successfully read" << std::endl;
    }

   private:
    Impl &client_;
  };

  class Callback : public ConsumerSocket::ReadCallback {
   public:
    Callback(Impl &hiperf_client) : client_(hiperf_client) {
      client_.configuration_.receive_buffer =
          utils::MemBuf::create(client_.configuration_.receive_buffer_size_);
    }

    bool isBufferMovable() noexcept override { return false; }

    void getReadBuffer(uint8_t **application_buffer,
                       size_t *max_length) override {
      *application_buffer =
          client_.configuration_.receive_buffer->writableData();
      *max_length = client_.configuration_.receive_buffer_size_;
    }

    void readDataAvailable(std::size_t length) noexcept override {}

    void readBufferAvailable(
        std::unique_ptr<utils::MemBuf> &&buffer) noexcept override {}

    size_t maxBufferSize() const override {
      return client_.configuration_.receive_buffer_size_;
    }

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
    Impl &client_;
  };

  hiperf::ClientConfiguration configuration_;
  Time t_stats_;
  Time t_download_;
  uint32_t total_duration_milliseconds_;
  uint64_t old_bytes_value_;
  uint64_t old_interest_tx_value_;
  uint64_t old_fec_interest_tx_value_;
  uint64_t old_fec_data_rx_value_;
  uint64_t old_lost_data_value_;
  uint64_t old_bytes_recovered_value_;
  uint64_t old_definitely_lost_data_value_;
  uint32_t old_retx_value_;
  uint32_t old_sent_int_value_;
  uint32_t old_received_nacks_value_;
  uint32_t old_fec_pkt_;

  // IMPORTANT: to be used only for performance testing, when consumer and
  // producer are synchronized. Used for rtc only at the moment
  double avg_data_delay_;
  uint32_t delay_sample_;

  uint32_t received_bytes_;
  uint32_t received_data_pkt_;

  std::string data_delays_;

  asio::io_service io_service_;
  asio::signal_set signals_;
  RTCCallback rtc_callback_;
  Callback callback_;
  std::unique_ptr<ConsumerSocket> consumer_socket_;
  std::unique_ptr<ProducerSocket> producer_socket_;
  asio::ip::udp::socket socket_;
  asio::ip::udp::endpoint remote_;

  ForwarderConfiguration config_;
  uint16_t switch_threshold_; /* ms */
  bool done_;
  std::vector<ForwarderInterface::RouteInfoPtr> main_routes_;
  std::vector<ForwarderInterface::RouteInfoPtr> backup_routes_;
#ifdef FORWARDER_INTERFACE
  ForwarderInterface forwarder_interface_;
#endif
};

HIperfClient::HIperfClient(const ClientConfiguration &conf) {
  impl_ = new Impl(conf);
}

HIperfClient::~HIperfClient() { delete impl_; }

int HIperfClient::setup() { return impl_->setup(); }

void HIperfClient::run() { impl_->run(); }

}  // namespace hiperf
