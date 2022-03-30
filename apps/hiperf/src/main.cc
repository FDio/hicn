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
#include <forwarder_interface.h>
#include <server.h>

namespace hiperf {

void usage() {
  std::cerr << "HIPERF - Instrumentation tool for performing active network"
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
  std::cerr << "-z\t<io_module>\t\t\t"
            << "IO module to use. Default: hicnlightng_module" << std::endl;
  std::cerr << "-F\t<conf_file>\t\t\t"
            << "Path to optional configuration file for libtransport"
            << std::endl;
  std::cerr << "-a\t\t\t\t\t"
            << "Enables data packet aggregation. "
            << "Works only in RTC mode" << std::endl;
  std::cerr << "-X\t<param>\t\t\t\t"
            << "Set FEC params. Options are Rely_K#_N# or RS_K#_N#"
            << std::endl;
#endif
  std::cerr << std::endl;
  std::cerr << "SERVER SPECIFIC:" << std::endl;
  std::cerr << "-A\t<content_size>\t\t\t"
               "Sends an application data unit in bytes that is published once "
               "before exit"
            << std::endl;
  std::cerr << "-s\t<packet_size>\t\t\tData packet payload size." << std::endl;
  std::cerr << "-r\t\t\t\t\t"
            << "Produce real content of <content_size> bytes" << std::endl;
  std::cerr << "-m\t<manifest_capacity>\t\t"
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
  std::cerr << "-p\t<password>\t\t\t"
            << "Password for p12 keystore" << std::endl;
  std::cerr << "-y\t<hash_algorithm>\t\t"
            << "Use the selected hash algorithm for "
               "computing manifest digests (default: SHA256)"
            << std::endl;
  std::cerr << "-x\t\t\t\t\t"
            << "Produces application data units of size <content_size> "
            << "without resetting the name suffix to 0." << std::endl;
  std::cerr << "-B\t<bitrate>\t\t\t"
            << "RTC producer data bitrate, to be used with the -R option."
            << std::endl;
#ifndef _WIN32
  std::cerr << "-I\t\t\t\t\t"
               "Interactive mode, start/stop real time content production "
               "by pressing return. To be used with the -R option"
            << std::endl;
  std::cerr
      << "-T\t<filename>\t\t\t"
         "Trace based mode, hiperf takes as input a file with a trace. "
         "Each line of the file indicates the timestamp and the size of "
         "the packet to generate. To be used with the -R option. -B and -I "
         "will be ignored."
      << std::endl;
  std::cerr << "-E\t\t\t\t\t"
            << "Enable encrypted communication. Requires the path to a p12 "
               "file containing the "
               "crypto material used for the TLS handshake"
            << std::endl;
  std::cerr << "-G\t<port>\t\t\t\t"
            << "Input stream from localhost at the specified port" << std::endl;
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
  std::cerr << "-u\t<delay>\t\t\t\t"
            << "Set max lifetime of unverified packets." << std::endl;
  std::cerr << "-M\t<input_buffer_size>\t\t"
            << "Size of consumer input buffer. If 0, reassembly of packets "
               "will be disabled."
            << std::endl;
  std::cerr << "-W\t<window_size>\t\t\t"
            << "Use a fixed congestion window "
               "for retrieving the data."
            << std::endl;
  std::cerr << "-i\t<stats_interval>\t\t"
            << "Show the statistics every <stats_interval> milliseconds."
            << std::endl;
  std::cerr << "-c\t<certificate_path>\t\t"
            << "Path of the producer certificate to be used for verifying the "
               "origin of the packets received."
            << std::endl;
  std::cerr << "-k\t<passphrase>\t\t\t"
            << "String from which is derived the symmetric key used by the "
               "producer to sign packets and by the consumer to verify them."
            << std::endl;
  std::cerr << "-t\t\t\t\t\t"
               "Test mode, check if the client is receiving the "
               "correct data. This is an RTC specific option, to be "
               "used with the -R (default: false)"
            << std::endl;
  std::cerr << "-P\t\t\t\t\t"
            << "Prefix of the producer where to do the handshake" << std::endl;
  std::cerr << "-j\t<relay_name>\t\t\t"
            << "Publish received content under the name relay_name."
               "This is an RTC specific option, to be "
               "used with the -R (default: false)"
            << std::endl;
  std::cerr << "-g\t<port>\t\t\t\t"
            << "Output stream to localhost at the specified port" << std::endl;
  std::cerr << "-e\t<strategy>\t\t\t"
            << "Enance the network with a realiability strategy. Options 1:"
            << " unreliable, 2: rtx only, 3: fec only, "
            << "4: delay based, 5: low rate, 6: low rate and best path "
            << "7: low rate and replication, 8: low rate and best"
            << " path/replication"
            << "(default: 2 = rtx only) " << std::endl;
  std::cerr << "-H\t\t\t\t\t"
            << "Disable periodic print headers in stats report." << std::endl;
  std::cerr << "-n\t<nb_iterations>\t\t\t"
            << "Print the stats report <nb_iterations> times and exit.\n"
            << "\t\t\t\t\tThis option limits the duration of the run to "
               "<nb_iterations> * <stats_interval> milliseconds."
            << std::endl;
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
  transport::interface::global_config::IoModuleConfiguration config;
  std::string conf_file;
  config.name = "hicnlightng_module";

  // Consumer
  ClientConfiguration client_configuration;

  // Producer
  ServerConfiguration server_configuration;

  int opt;
#ifndef _WIN32
  while ((opt = getopt(argc, argv,
                       "DSCf:b:d:W:RM:c:vA:s:rm:lK:k:y:p:hi:xE:P:B:ItL:z:T:F:j:"
                       "g:G:e:awHn:X:u:")) != -1) {
    switch (opt) {
      // Common
      case 'D': {
        daemon = true;
        break;
      }
      case 'I': {
        server_configuration.interactive_ = true;
        server_configuration.trace_based_ = false;
        server_configuration.input_stream_mode_ = false;
        break;
      }
      case 'T': {
        server_configuration.interactive_ = false;
        server_configuration.trace_based_ = true;
        server_configuration.input_stream_mode_ = false;
        server_configuration.trace_file_ = optarg;
        break;
      }
      case 'G': {
        server_configuration.interactive_ = false;
        server_configuration.trace_based_ = false;
        server_configuration.input_stream_mode_ = true;
        server_configuration.port_ = std::stoul(optarg);
        break;
      }
      case 'g': {
        client_configuration.output_stream_mode_ = true;
        client_configuration.port_ = std::stoul(optarg);
        break;
      }
#else
  while (
      (opt = getopt(
           argc, argv,
           "SCf:b:d:W:RM:c:vA:s:rm:lK:k:y:p:hi:xB:E:P:tL:z:F:j:e:awHn:X:u:")) !=
      -1) {
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
      case 'a': {
        client_configuration.aggregated_data_ = true;
        server_configuration.aggregated_data_ = true;
        break;
      }
      case 'X': {
        client_configuration.fec_type_ = std::string(optarg);
        server_configuration.fec_type_ = std::string(optarg);
        break;
      }
      case 'w': {
        client_configuration.packet_format_ = Packet::Format::HF_INET6_UDP;
        server_configuration.packet_format_ = Packet::Format::HF_INET6_UDP;
        break;
      }
      case 'z': {
        config.name = optarg;
        break;
      }
      case 'F': {
        conf_file = optarg;
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
        client_configuration.receive_buffer_size_ = std::stoull(optarg);
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
      case 'u': {
        client_configuration.unverified_delay_ = std::stoul(optarg);
        options = 1;
        break;
      }
      case 'j': {
        client_configuration.relay_ = true;
        client_configuration.relay_name_ = Prefix(optarg);
        options = 1;
        break;
      }
      case 'H': {
        client_configuration.print_headers_ = false;
        options = 1;
        break;
      }
      case 'n': {
        client_configuration.nb_iterations_ = std::stoul(optarg);
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
        server_configuration.manifest = std::stoul(optarg);
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
        options = -1;
        break;
      }
      case 'y': {
        CryptoHashType hash_algorithm = CryptoHashType::SHA256;
        if (strncasecmp(optarg, "sha256", 6) == 0) {
          hash_algorithm = CryptoHashType::SHA256;
        } else if (strncasecmp(optarg, "sha512", 6) == 0) {
          hash_algorithm = CryptoHashType::SHA512;
        } else if (strncasecmp(optarg, "blake2b512", 10) == 0) {
          hash_algorithm = CryptoHashType::BLAKE2B512;
        } else if (strncasecmp(optarg, "blake2s256", 10) == 0) {
          hash_algorithm = CryptoHashType::BLAKE2S256;
        } else {
          std::cerr << "Unknown hash algorithm. Using SHA 256." << std::endl;
        }
        server_configuration.hash_algorithm_ = hash_algorithm;
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
        server_configuration.production_rate_ = str;
        options = -1;
        break;
      }
      case 'E': {
        server_configuration.keystore_name = std::string(optarg);
        server_configuration.secure_ = true;
        break;
      }
      case 'e': {
        client_configuration.recovery_strategy_ = std::stoul(optarg);
        options = 1;
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

  /**
   * IO module configuration
   */
  config.set();

  // Parse config file
  transport::interface::global_config::parseConfigurationFile(conf_file);

  if (role > 0) {
    // set forwarder type
    client_configuration.forwarder_type_ = UNDEFINED;
    if (config.name.compare("hicnlightng_module") == 0)
      client_configuration.forwarder_type_ = HICNLIGHT;
    else if (config.name.compare("hicnlightng_module") == 0)
      client_configuration.forwarder_type_ = HICNLIGHT_NG;

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

}  // namespace hiperf

int main(int argc, char *argv[]) { return hiperf::main(argc, argv); }
