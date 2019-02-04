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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#ifndef _WIN32
#include <hicn/transport/utils/daemonizator.h>
#endif
#include <hicn/transport/utils/literals.h>

#include <fstream>
#include <iomanip>

#ifdef __linux__
#include <mcheck.h>
#endif

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

namespace transport {

namespace interface {

#define ERROR_SUCCESS 0
#define ERROR_SETUP -5

using CryptoSuite = utils::CryptoSuite;
using Identity = utils::Identity;

struct ClientConfiguration {
  ClientConfiguration()
      : name("b001::abcd", 0),
        verify(false),
        beta(-1.f),
        drop_factor(-1.f),
        window(-1),
        virtual_download(true),
        producer_certificate("/tmp/rsa_certificate.pem"),
        receive_buffer(std::make_shared<std::vector<uint8_t>>()),
        download_size(0),
        report_interval_milliseconds_(1000),
        rtc_(false) {}

  Name name;
  bool verify;
  double beta;
  double drop_factor;
  double window;
  bool virtual_download;
  std::string producer_certificate;
  std::shared_ptr<std::vector<uint8_t>> receive_buffer;
  std::size_t download_size;
  std::uint32_t report_interval_milliseconds_;
  TransportProtocolAlgorithms transport_protocol_;
  bool rtc_;
};

struct ServerConfiguration {
  ServerConfiguration()
      : name("b001::abcd/64"),
        virtual_producer(true),
        manifest(false),
        live_production(false),
        sign(false),
        content_lifetime(600000000_U32),
        content_object_size(1440),
        download_size(20 * 1024 * 1024),
        hash_algorithm(HashAlgorithm::SHA_256),
        keystore_name("/tmp/rsa_crypto_material.p12"),
        keystore_password("cisco"),
        multiphase_produce_(false) {}

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
  std::string keystore_password;
  bool multiphase_produce_;
};

class HIperfClient {
  typedef std::chrono::time_point<std::chrono::steady_clock> Time;
  typedef std::chrono::microseconds TimeDuration;

 public:
  HIperfClient(const ClientConfiguration &conf)
      : configuration_(conf),
        total_duration_milliseconds_(0),
        old_bytes_value_(0) {}

  void processPayload(ConsumerSocket &c, std::size_t bytes_transferred,
                      const std::error_code &ec) {
    Time t2 = std::chrono::steady_clock::now();
    TimeDuration dt = std::chrono::duration_cast<TimeDuration>(t2 - t_download_);
    long usec = dt.count();

    std::cout << "Content retrieved. Size: " << bytes_transferred << " [Bytes]"
              << std::endl;

    std::cerr << "Elapsed Time: " << usec / 1000000.0 << " seconds -- "
              << (bytes_transferred * 8) * 1.0 / usec * 1.0 << " [Mbps]"
              << std::endl;
  }

  bool verifyData(ConsumerSocket &c, const ContentObject &contentObject) {
    if (contentObject.getPayloadType() == PayloadType::CONTENT_OBJECT) {
      std::cout << "VERIFY CONTENT" << std::endl;
    } else if (contentObject.getPayloadType() == PayloadType::MANIFEST) {
      std::cout << "VERIFY MANIFEST" << std::endl;
    }

    return true;
  }

  void processLeavingInterest(ConsumerSocket &c, const Interest &interest) {
    //    std::cout << "LEAVES " << interest.getName().toUri() << std::endl;
  }

  void handleTimerExpiration(ConsumerSocket &c, const protocol::TransportStatistics &stats) {
    const char separator = ' ';
    const int width = 20;

    utils::TimePoint t2 = utils::SteadyClock::now();
    auto exact_duration = std::chrono::duration_cast<utils::Milliseconds>(t2 - t_stats_);

    std::stringstream interval;
    interval << total_duration_milliseconds_ / 1000 << "-"
             << total_duration_milliseconds_ / 1000 + exact_duration.count() / 1000;

    std::stringstream bytes_transferred;
    bytes_transferred << std::fixed << std::setprecision(3)
                      << (stats.getBytesRecv() - old_bytes_value_) / 1000000.0
                      << std::setfill(separator) << "[MBytes]";

    std::stringstream bandwidth;
    bandwidth << ((stats.getBytesRecv() - old_bytes_value_) * 8) /
                     (exact_duration.count()) / 1000.0
              << std::setfill(separator) << "[Mbps]";

    std::stringstream window;
    window << stats.getAverageWindowSize() << std::setfill(separator) << "[Interest]";

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

    total_duration_milliseconds_ += exact_duration.count();
    old_bytes_value_ = stats.getBytesRecv();
    t_stats_ = utils::SteadyClock::now();
  }

  int setup() {
    int ret;

    // Set the transport algorithm
    TransportProtocolAlgorithms transport_protocol;

    if (configuration_.rtc_) {
      transport_protocol = RTC;
    } else if (configuration_.window < 0) {
      transport_protocol = RAAQM;
    } else {
      transport_protocol = CBR;
    }

    consumer_socket_ = std::make_unique<ConsumerSocket>(transport_protocol);

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

    if (transport_protocol == RAAQM && configuration_.beta != -1.f) {
      if (consumer_socket_->setSocketOption(RaaqmTransportOptions::BETA_VALUE,
                                            configuration_.beta) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (transport_protocol == RAAQM && configuration_.drop_factor != -1.f) {
      if (consumer_socket_->setSocketOption(RaaqmTransportOptions::DROP_FACTOR,
                                            configuration_.drop_factor) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    if (consumer_socket_->setSocketOption(OtherOptions::VIRTUAL_DOWNLOAD,
                                          configuration_.virtual_download) == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    if (configuration_.verify) {
      if (consumer_socket_->setSocketOption(
              GeneralTransportOptions::CERTIFICATE,
              configuration_.producer_certificate) == SOCKET_OPTION_NOT_SET) {
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

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::CONTENT_RETRIEVED,
        (ConsumerContentCallback)std::bind(
            &HIperfClient::processPayload, this, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3));

    if (ret == SOCKET_OPTION_NOT_SET) {
      return ERROR_SETUP;
    }

    ret = consumer_socket_->setSocketOption(
        ConsumerCallbacksOptions::STATS_SUMMARY,
        (ConsumerTimerCallback)std::bind(
            &HIperfClient::handleTimerExpiration, this, std::placeholders::_1,
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

    do {
      t_stats_ = t_download_ = std::chrono::steady_clock::now();
      consumer_socket_->consume(configuration_.name, configuration_.receive_buffer);
    } while (configuration_.virtual_download);

    return ERROR_SUCCESS;
  }

 private:
  ClientConfiguration configuration_;
  std::unique_ptr<ConsumerSocket> consumer_socket_;
  Time t_stats_;
  Time t_download_;
  uint32_t total_duration_milliseconds_;
  uint64_t old_bytes_value_;
  // std::unique_ptr<asio::signal_set> signals_;
};

class HIperfServer {
  const std::size_t log2_content_object_buffer_size = 8;

 public:
  HIperfServer(ServerConfiguration &conf)
      : configuration_(conf),
        // signals_(io_service_, SIGINT, SIGQUIT),
        content_objects_((1 << log2_content_object_buffer_size)),
        content_objects_index_(0),
        mask_((1 << log2_content_object_buffer_size) - 1) {
    // signals_.async_wait([this] (const std::error_code&, const int&)
    // {std::cout << "STOPPING!!" << std::endl; io_service_.stop();});

    std::string buffer(1200, 'X');

    std::cout << "Producing contents under name " << conf.name.getName()
              << std::endl;

    for (int i = 0; i < (1 << log2_content_object_buffer_size); i++) {
      content_objects_[i] = std::make_shared<ContentObject>(
          conf.name.getName(), HF_INET6_TCP, (const uint8_t *)buffer.data(),
          buffer.size());
      content_objects_[i]->setLifetime(
          default_values::content_object_expiry_time);
    }
  }

  void processInterest(ProducerSocket &p, const Interest &interest) {
    content_objects_[content_objects_index_ & mask_]->setName(
        interest.getName());

    //    if (final_chunk_number_ > 0 && interest.getName().getSuffix() == 0) {
    //      auto name = interest.getName();
    //      manifest_ = std::make_shared<ContentObjectManifest>(name);
    //      // manifest_->setFinalChunkNumber(final_chunk_number_);
    //      manifest_->encode();
    //      p.produce(*manifest_);
    //      return;
    //    }

    producer_socket_->produce(
        *content_objects_[content_objects_index_++ & mask_]);
  }

  void processInterest2(ProducerSocket &p, const Interest &interest) {
    producer_socket_->setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                                      (ProducerInterestCallback)VOID_HANDLER);
    producer_socket_->setSocketOption(
        GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME, 5000_U32);
    produceContent(interest.getName().getSuffix());
    producer_socket_->setSocketOption(
        ProducerCallbacksOptions::CACHE_MISS,
        (ProducerInterestCallback)bind(&HIperfServer::processInterest2, this,
                                       std::placeholders::_1,
                                       std::placeholders::_2));
  }

  void produceContent(uint32_t suffix) {
    core::Name name = configuration_.name.getName();

    std::string content(configuration_.download_size, '?');
    uint32_t total;

    total = producer_socket_->produce(
        name, reinterpret_cast<const uint8_t *>(content.data()), content.size(),
        !configuration_.multiphase_produce_, suffix);

    std::cout << "Written " << total << "pieces of data in output buffer"
              << std::endl;
  }

  std::shared_ptr<utils::Identity> setProducerIdentity(std::string &keystore_name,
                                      std::string &keystore_password,
                                      HashAlgorithm &hash_algorithm) {
    if (access(keystore_name.c_str(), F_OK) != -1) {
      return std::make_shared<utils::Identity>(keystore_name, keystore_password, hash_algorithm);
    } else {
      return std::make_shared<utils::Identity>(keystore_name, keystore_password,
                             CryptoSuite::RSA_SHA256, 1024, 365,
                             "producer-test");
    }
  }

  int setup() {
    int ret;

    producer_socket_ = std::make_unique<ProducerSocket>();

    if (configuration_.sign) {
      auto identity = setProducerIdentity(configuration_.keystore_name,
                                              configuration_.keystore_password,
                                              configuration_.hash_algorithm);

      if (producer_socket_->setSocketOption(GeneralTransportOptions::IDENTITY,
                                            identity) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    producer_socket_->registerPrefix(configuration_.name);

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
              GeneralTransportOptions::OUTPUT_BUFFER_SIZE, 200000U) ==
          SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }

      if (!configuration_.live_production) {
        produceContent(0);
      } else {
        ret = producer_socket_->setSocketOption(
            ProducerCallbacksOptions::CACHE_MISS,
            (ProducerInterestCallback)bind(&HIperfServer::processInterest2,
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
          (ProducerInterestCallback)bind(&HIperfServer::processInterest, this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));

      if (ret == SOCKET_OPTION_NOT_SET) {
        return ERROR_SETUP;
      }
    }

    producer_socket_->connect();

    return ERROR_SUCCESS;
  }

  int run() {
    std::cerr << "Starting to serve consumers" << std::endl;
    producer_socket_->serveForever();

    return ERROR_SUCCESS;
  }

 private:
  ServerConfiguration configuration_;
  std::unique_ptr<ProducerSocket> producer_socket_;
  // asio::signal_set signals_;
  std::vector<std::shared_ptr<ContentObject>> content_objects_;
  std::uint16_t content_objects_index_;
  std::uint16_t mask_;
};

void usage() {
  std::cerr << std::endl;
  std::cerr << "HIPERF - A tool for performing network throughput "
               "measurements with hICN"
            << std::endl;
  std::cerr << "usage: hiperf [-S|-C] [options] [prefix|name]" << std::endl;
  std::cerr << "Server or Client:" << std::endl;
#ifndef _WIN32
  std::cerr << "-D\t\t\t\t\t"
            << "Run as a daemon" << std::endl;
#endif
  std::cerr << std::endl;
  std::cerr << "Server specific:" << std::endl;
  std::cerr << "-s\t<content_size>\t\t\tSize of the content to publish"
            << std::endl;
  std::cerr << "-r\t\t\t\t\t"
            << "Produce real content of content_size bytes" << std::endl;
  std::cerr << "-m\t\t\t\t\t"
            << "Produce transport manifest" << std::endl;
  std::cerr << "-l\t\t\t\t\t"
            << "Start producing content upon the reception of the "
               "first interest"
            << std::endl;
  std::cerr << "-k\t<keystore_path>\t\t\t"
            << "Path of p12 file containing the "
               "crypto material used for signing the packets"
            << std::endl;
  std::cerr << "-y\t<hash_algorithm>\t\t"
            << "Use the selected hash algorithm for "
               "calculating manifest digests"
            << std::endl;
  std::cerr << "-p\t<password>\t\t\t"
            << "Password for p12 keystore" << std::endl;
  std::cerr << std::endl;
  std::cerr << "Client specific:" << std::endl;
  std::cerr << "-b\t<beta_parameter>\t\t"
            << "RAAQM beta parameter" << std::endl;
  std::cerr << "-d\t<drop_factor_parameter>\t\t"
            << "RAAQM drop factor "
               "parameter"
            << std::endl;
  std::cerr << "-M\t<Download for real>\t\t"
            << "Store the content downloaded."
            << std::endl;
  std::cerr << "-W\t<window_size>\t\t\t"
            << "Use a fixed congestion window "
               "for retrieving the data."
            << std::endl;
  std::cerr << "-c\t<certificate_path>\t\t"
            << "Path of the producer certificate "
               "to be used for verifying the "
               "origin of the packets received"
            << std::endl;
  std::cout << "-v\t\t\t\t\t"
            << "Enable verification of received data" << std::endl;
}

int main(int argc, char *argv[]) {

#ifndef _WIN32
  // Common
  bool daemon = false;
#else
  WSADATA wsaData = { 0 };
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
  while ((opt = getopt(argc, argv, "DSCf:b:d:W:RMc:vs:rmlk:y:p:hi:x")) != -1) {
    switch (opt) {
      // Common
      case 'D':
        daemon = true;
        break;
#else
  while ((opt = getopt(argc, argv, "SCf:b:d:W:RMc:vs:rmlk:y:p:hi:x")) != -1) {
    switch (opt) {
#endif
      case 'f':
        log_file = optarg;
        break;

      // Server or Client
      case 'S':
        role -= 1;
        break;
      case 'C':
        role += 1;
        break;

      // Client specifc
      case 'b':
        client_configuration.beta = std::stod(optarg);
        options = 1;
        break;
      case 'd':
        client_configuration.drop_factor = std::stod(optarg);
        options = 1;
        break;
      case 'W':
        client_configuration.window = std::stod(optarg);
        options = 1;
        break;
      case 'M':
        client_configuration.virtual_download = false;
        options = 1;
        break;
      case 'c':
        client_configuration.producer_certificate = std::string(optarg);
        options = 1;
        break;
      case 'v':
        client_configuration.verify = true;
        options = 1;
        break;
      case 'i':
        client_configuration.report_interval_milliseconds_ = std::stoul(optarg);
        options = 1;
        break;
      case 'R':
        client_configuration.rtc_ = true;
        break;

      // Server specific
      case 's':
        server_configuration.download_size = std::stoul(optarg);
        options = -1;
        break;
      case 'r':
        server_configuration.virtual_producer = false;
        options = -1;
        break;
      case 'm':
        server_configuration.manifest = true;
        options = -1;
        break;
      case 'l':
        server_configuration.live_production = true;
        options = -1;
        break;
      case 'k':
        server_configuration.keystore_name = std::string(optarg);
        server_configuration.sign = true;
        options = -1;
        break;
      case 'y':
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
      case 'p':
        server_configuration.keystore_password = std::string(optarg);
        options = -1;
        break;
      case 'x':
        server_configuration.multiphase_produce_ = true;
        options = -1;
        break;
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
    int fd = _open(log_file, _O_WRONLY | _O_APPEND | _O_CREAT, _S_IWRITE | _S_IREAD);
    _dup2(fd, _fileno(stdout));
    _dup2(_fileno(stdout), _fileno(strerr));
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

  std::cout << "Bye bye" << std::endl;

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

}  // end namespace interface

}  // end namespace transport

int main(int argc, char *argv[]) {
  return transport::interface::main(argc, argv);
}
