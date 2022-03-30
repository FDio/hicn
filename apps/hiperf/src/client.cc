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
class HIperfClient::Impl : ForwarderInterface::ICallback {
  friend class Callback;
  friend class RTCCallback;

  static const constexpr uint16_t log2_header_counter = 4;

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
        auth_alerts_(0),
        data_delays_(""),
        signals_(io_service_),
        rtc_callback_(*this),
        callback_(*this),
        socket_(io_service_),
        // switch_threshold_(~0),
        fwd_connected_(false),
        use_bestpath_(false),
        rtt_threshold_(~0),
        loss_threshold_(~0),
        prefix_name_(""),
        prefix_len_(0),
        // done_(false),
        header_counter_mask_((1 << log2_header_counter) - 1),
        header_counter_(0),
        print_headers_(configuration_.print_headers_),
        first_(true),
        forwarder_interface_(io_service_) {
    setForwarderConnection(conf.forwarder_type_);
  }

  virtual ~Impl() {}

  void checkReceivedRtcContent(ConsumerSocket &c,
                               const ContentObject &contentObject) {}

  void processLeavingInterest(ConsumerSocket &c, const Interest &interest) {}

  void addFace(const std::string &local_address, uint16_t local_port,
               const std::string &remote_address, uint16_t remote_port,
               std::string interface);

  void handleTimerExpiration(ConsumerSocket &c,
                             const TransportStatistics &stats) {
    const char separator = ' ';
    const int width = 18;

    utils::SteadyTime::TimePoint t2 = utils::SteadyTime::Clock::now();
    auto exact_duration = utils::SteadyTime::getDurationMs(t_stats_, t2);

    std::stringstream interval_ms;
    interval_ms << total_duration_milliseconds_ << "-"
                << total_duration_milliseconds_ + exact_duration.count();

    std::stringstream bytes_transferred;
    bytes_transferred << std::fixed << std::setprecision(3)
                      << (stats.getBytesRecv() - old_bytes_value_) / 1000000.0
                      << std::setfill(separator);

    std::stringstream bandwidth;
    bandwidth << ((stats.getBytesRecv() - old_bytes_value_) * 8) /
                     (exact_duration.count()) / 1000.0
              << std::setfill(separator);

    std::stringstream window;
    window << stats.getAverageWindowSize() << std::setfill(separator);

    std::stringstream avg_rtt;
    avg_rtt << stats.getAverageRtt() << std::setfill(separator);

    if (configuration_.rtc_) {
      std::stringstream lost_data;
      lost_data << stats.getLostData() - old_lost_data_value_
                << std::setfill(separator);

      std::stringstream bytes_recovered_data;
      bytes_recovered_data << stats.getBytesRecoveredData() -
                                  old_bytes_recovered_value_
                           << std::setfill(separator);

      std::stringstream definitely_lost_data;
      definitely_lost_data << stats.getDefinitelyLostData() -
                                  old_definitely_lost_data_value_
                           << std::setfill(separator);

      std::stringstream data_delay;
      data_delay << std::fixed << std::setprecision(3) << avg_data_delay_
                 << std::setfill(separator);

      std::stringstream received_data_pkt;
      received_data_pkt << received_data_pkt_ << std::setfill(separator);

      std::stringstream goodput;
      goodput << std::fixed << std::setprecision(3)
              << (received_bytes_ * 8.0) / (exact_duration.count()) / 1000.0
              << std::setfill(separator);

      std::stringstream loss_rate;
      loss_rate << std::fixed << std::setprecision(2)
                << stats.getLossRatio() * 100.0 << std::setfill(separator);

      std::stringstream retx_sent;
      retx_sent << stats.getRetxCount() - old_retx_value_
                << std::setfill(separator);

      std::stringstream interest_sent;
      interest_sent << stats.getInterestTx() - old_sent_int_value_
                    << std::setfill(separator);

      std::stringstream nacks;
      nacks << stats.getReceivedNacks() - old_received_nacks_value_
            << std::setfill(separator);

      std::stringstream fec_pkt;
      fec_pkt << stats.getReceivedFEC() - old_fec_pkt_
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
      auth_alerts << auth_alerts_ << std::setfill(separator);

      if (fwd_connected_ && use_bestpath_ &&
          ((stats.getAverageRtt() > rtt_threshold_) ||
           ((stats.getResidualLossRate() * 100) > loss_threshold_))) {
        forwarder_interface_.setStrategy(prefix_name_, prefix_len_, "bestpath");
      }

      if ((header_counter_ == 0 && print_headers_) || first_) {
        std::cout << std::right << std::setw(width) << "Interval[ms]";
        std::cout << std::right << std::setw(width) << "RecvData[pkt]";
        std::cout << std::right << std::setw(width) << "Bandwidth[Mbps]";
        std::cout << std::right << std::setw(width) << "Goodput[Mbps]";
        std::cout << std::right << std::setw(width) << "LossRate[%]";
        std::cout << std::right << std::setw(width) << "Retr[pkt]";
        std::cout << std::right << std::setw(width) << "InterestSent";
        std::cout << std::right << std::setw(width) << "ReceivedNacks";
        std::cout << std::right << std::setw(width) << "SyncWnd[pkt]";
        std::cout << std::right << std::setw(width) << "MinRtt[ms]";
        std::cout << std::right << std::setw(width) << "QueuingDelay[ms]";
        std::cout << std::right << std::setw(width) << "LostData[pkt]";
        std::cout << std::right << std::setw(width) << "RecoveredData";
        std::cout << std::right << std::setw(width) << "DefinitelyLost";
        std::cout << std::right << std::setw(width) << "State";
        std::cout << std::right << std::setw(width) << "DataDelay[ms]";
        std::cout << std::right << std::setw(width) << "FecPkt";
        std::cout << std::right << std::setw(width) << "Congestion";
        std::cout << std::right << std::setw(width) << "ResidualLosses";
        std::cout << std::right << std::setw(width) << "QualityScore";
        std::cout << std::right << std::setw(width) << "Alerts";
        std::cout << std::right << std::setw(width) << "AuthAlerts"
                  << std::endl;

        first_ = false;
      }

      std::cout << std::right << std::setw(width) << interval_ms.str();
      std::cout << std::right << std::setw(width) << received_data_pkt.str();
      std::cout << std::right << std::setw(width) << bandwidth.str();
      std::cout << std::right << std::setw(width) << goodput.str();
      std::cout << std::right << std::setw(width) << loss_rate.str();
      std::cout << std::right << std::setw(width) << retx_sent.str();
      std::cout << std::right << std::setw(width) << interest_sent.str();
      std::cout << std::right << std::setw(width) << nacks.str();
      std::cout << std::right << std::setw(width) << window.str();
      std::cout << std::right << std::setw(width) << avg_rtt.str();
      std::cout << std::right << std::setw(width) << queuing_delay.str();
      std::cout << std::right << std::setw(width) << lost_data.str();
      std::cout << std::right << std::setw(width) << bytes_recovered_data.str();
      std::cout << std::right << std::setw(width) << definitely_lost_data.str();
      std::cout << std::right << std::setw(width) << stats.getCCStatus();
      std::cout << std::right << std::setw(width) << data_delay.str();
      std::cout << std::right << std::setw(width) << fec_pkt.str();
      std::cout << std::right << std::setw(width) << stats.isCongested();
      std::cout << std::right << std::setw(width) << residual_losses.str();
      std::cout << std::right << std::setw(width) << quality_score.str();
      std::cout << std::right << std::setw(width) << alerts.str();
      std::cout << std::right << std::setw(width) << auth_alerts.str();
      std::cout << std::endl;

      if (configuration_.test_mode_) {
        if (data_delays_.size() > 0) data_delays_.pop_back();

        auto now = utils::SteadyTime::nowMs();
        std::cout << std::fixed << std::setprecision(0) << now.count()
                  << " DATA-DELAYS:[" << data_delays_ << "]" << std::endl;
      }

      // statistics not yet available in the transport
      // std::cout << std::right << std::setw(width) << interest_fec_tx.str();
      // std::cout << std::right << std::setw(width) << bytes_fec_recv.str();
    } else {
      if ((header_counter_ == 0 && print_headers_) || first_) {
        std::cout << std::right << std::setw(width) << "Interval[ms]";
        std::cout << std::right << std::setw(width) << "Transfer[MB]";
        std::cout << std::right << std::setw(width) << "Bandwidth[Mbps]";
        std::cout << std::right << std::setw(width) << "Retr[pkt]";
        std::cout << std::right << std::setw(width) << "Cwnd[Int]";
        std::cout << std::right << std::setw(width) << "AvgRtt[ms]"
                  << std::endl;

        first_ = false;
      }

      std::cout << std::right << std::setw(width) << interval_ms.str();
      std::cout << std::right << std::setw(width) << bytes_transferred.str();
      std::cout << std::right << std::setw(width) << bandwidth.str();
      std::cout << std::right << std::setw(width) << stats.getRetxCount();
      std::cout << std::right << std::setw(width) << window.str();
      std::cout << std::right << std::setw(width) << avg_rtt.str() << std::endl;
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

    t_stats_ = utils::SteadyTime::Clock::now();

    header_counter_ = (header_counter_ + 1) & header_counter_mask_;

    if (--configuration_.nb_iterations_ == 0) {
      // We reached the maximum nb of runs. Stop now.
      io_service_.stop();
    }
  }

  bool setForwarderConnection(forwarder_type_t forwarder_type) {
    using namespace libconfig;
    Config cfg;

    const char *conf_file = getenv("FORWARDER_CONFIG");
    if (!conf_file) return false;

    if ((forwarder_type != HICNLIGHT) && (forwarder_type != HICNLIGHT_NG))
      return false;

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

    /* conf file example
     *
     * use_bestpath = "ON | OFF"
     * rtt_threshold = 200 //ms
     * loss_threshold = 20 //%
     * name = "b001::/16"
     */

    if (config.exists("use_bestpath")) {
      std::string val;
      config.lookupValue("use_bestpath", val);
      if (val.compare("ON") == 0) use_bestpath_ = true;
    }

    if (config.exists("rtt_threshold")) {
      unsigned val;
      config.lookupValue("rtt_threshold", val);
      rtt_threshold_ = val;
    }

    if (config.exists("loss_threshold")) {
      unsigned val;
      config.lookupValue("loss_threshold", val);
      loss_threshold_ = val;
    }

    if (config.exists("name")) {
      std::string route;
      config.lookupValue("name", route);

      std::string delimiter = "/";
      size_t pos = 0;

      if ((pos = route.find(delimiter)) != std::string::npos) {
        prefix_name_ = route.substr(0, pos);
        route.erase(0, pos + delimiter.length());
        prefix_len_ = std::stoul(route.substr(0));
      }
    }

    forwarder_interface_.initForwarderInterface(this, forwarder_type);

    return true;
  }

  void onHicnServiceReady() override {
    std::cout << "Successfully connected to local forwarder!" << std::endl;
    fwd_connected_ = true;
  }

  void onRouteConfigured(
      std::vector<ForwarderInterface::RouteInfoPtr> &route_info) override {
    std::cout << "Routes successfully configured!" << std::endl;
  }

#ifdef FORWARDER_INTERFACE
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

  transport::auth::VerificationPolicy onAuthFailed(
      transport::auth::Suffix suffix,
      transport::auth::VerificationPolicy policy) {
    auth_alerts_++;
    return transport::auth::VerificationPolicy::ACCEPT;
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

    if (configuration_.relay_ && configuration_.rtc_) {
      int production_protocol = ProductionProtocolAlgorithms::RTC_PROD;
      producer_socket_ = std::make_unique<ProducerSocket>(production_protocol);
      producer_socket_->registerPrefix(configuration_.relay_name_);
      producer_socket_->connect();
      producer_socket_->start();
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

    consumer_socket_->setSocketOption(
        GeneralTransportOptions::MAX_UNVERIFIED_TIME,
        configuration_.unverified_delay_);

    if (consumer_socket_->setSocketOption(
            GeneralTransportOptions::PACKET_FORMAT,
            configuration_.packet_format_) == SOCKET_OPTION_NOT_SET) {
      std::cerr << "ERROR -- Impossible to set the packet format." << std::endl;
      return ERROR_SETUP;
    }

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

    std::shared_ptr<Verifier> verifier = std::make_shared<VoidVerifier>();

    if (!configuration_.producer_certificate.empty()) {
      verifier = std::make_shared<AsymmetricVerifier>(
          configuration_.producer_certificate);
    }

    if (!configuration_.passphrase.empty()) {
      verifier = std::make_shared<SymmetricVerifier>(configuration_.passphrase);
    }

    verifier->setVerificationFailedCallback(
        std::bind(&HIperfClient::Impl::onAuthFailed, this,
                  std::placeholders::_1, std::placeholders::_2));

    if (consumer_socket_->setSocketOption(GeneralTransportOptions::VERIFIER,
                                          verifier) == SOCKET_OPTION_NOT_SET) {
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
      if (configuration_.recovery_strategy_ == 1) {  // unreliable
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::RECOVERY_OFF);
      } else if (configuration_.recovery_strategy_ == 2) {  // rtx only
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::RTX_ONLY);
      } else if (configuration_.recovery_strategy_ == 3) {  // fec only
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::FEC_ONLY);
      } else if (configuration_.recovery_strategy_ == 4) {  // delay based
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::DELAY_BASED);
      } else if (configuration_.recovery_strategy_ == 5) {  // low rate flow
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::LOW_RATE);
      } else if (configuration_.recovery_strategy_ ==
                 6) {  // low rate + bestpath
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::LOW_RATE_AND_BESTPATH);
      } else if (configuration_.recovery_strategy_ ==
                 7) {  // low rate + replication
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::LOW_RATE_AND_REPLICATION);
      } else if (configuration_.recovery_strategy_ ==
                 8) {  // low rate + bestpath or replication
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::
                LOW_RATE_AND_ALL_FWD_STRATEGIES);
      } else {
        // default
        ret = consumer_socket_->setSocketOption(
            RtcTransportOptions::RECOVERY_STRATEGY,
            (uint32_t)RtcTransportRecoveryStrategies::RTX_ONLY);
      }

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (configuration_.rtc_) {
      ret = consumer_socket_->setSocketOption(
          RtcTransportOptions::AGGREGATED_DATA,
          configuration_.aggregated_data_);

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
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
      ret = consumer_socket_->setSocketOption(GeneralTransportOptions::FEC_TYPE,
                                              configuration_.fec_type_);

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

    t_download_ = t_stats_ = utils::SteadyTime::now();
    consumer_socket_->consume(configuration_.name);

    io_service_.run();
    consumer_socket_->stop();

    return ERROR_SUCCESS;
  }

 private:
  class RTCCallback : public ConsumerSocket::ReadCallback {
    static constexpr std::size_t mtu = HIPERF_MTU;

   public:
    RTCCallback(Impl &hiperf_client) : client_(hiperf_client) {
      client_.configuration_.receive_buffer = utils::MemBuf::create(mtu);
      Packet::Format format =
          PayloadSize::getFormatFromName(client_.configuration_.name, false);
      payload_size_max_ =
          PayloadSize(format).getPayloadSizeMax(RTC_HEADER_SIZE);
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

      auto now = utils::SystemTime::nowMs().count();
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
            length < payload_size_max_ ? length : payload_size_max_);
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

    void readError(const std::error_code &ec) noexcept override {
      std::cerr << "Error while reading from RTC socket" << std::endl;
      client_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      std::cout << "Data successfully read" << std::endl;
    }

   private:
    Impl &client_;
    std::size_t payload_size_max_;
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

    void readError(const std::error_code &ec) noexcept override {
      std::cerr << "Error " << ec.message() << " while reading from socket"
                << std::endl;
      client_.io_service_.stop();
    }

    void readSuccess(std::size_t total_size) noexcept override {
      auto t2 = utils::SteadyTime::now();
      auto dt = utils::SteadyTime::getDurationUs(client_.t_download_, t2);
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
  utils::SteadyTime::TimePoint t_stats_;
  utils::SteadyTime::TimePoint t_download_;
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
  uint32_t auth_alerts_;

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
  // uint16_t switch_threshold_; /* ms */
  bool fwd_connected_;
  bool use_bestpath_;
  uint32_t rtt_threshold_;   /* ms */
  uint32_t loss_threshold_;  /* ms */
  std::string prefix_name_;  // bestpath route
  uint32_t prefix_len_;
  // bool done_;

  std::vector<ForwarderInterface::RouteInfoPtr> main_routes_;
  std::vector<ForwarderInterface::RouteInfoPtr> backup_routes_;
  uint16_t header_counter_mask_;
  uint16_t header_counter_;

  bool print_headers_;
  bool first_;

  ForwarderInterface forwarder_interface_;
};

HIperfClient::HIperfClient(const ClientConfiguration &conf) {
  impl_ = new Impl(conf);
}

HIperfClient::HIperfClient(HIperfClient &&other) {
  impl_ = other.impl_;
  other.impl_ = nullptr;
}

HIperfClient &HIperfClient::operator=(HIperfClient &&other) {
  if (this != &other) {
    impl_ = other.impl_;
    other.impl_ = nullptr;
  }

  return *this;
}

HIperfClient::~HIperfClient() { delete impl_; }

int HIperfClient::setup() { return impl_->setup(); }

void HIperfClient::run() { impl_->run(); }

}  // namespace hiperf
