/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "src/IcnReceiver.h"

using namespace transport;

int usage(char* program) {
  std::cerr << "ICN Plugin not loaded!" << std::endl;
  std::cerr << "USAGE: " << program << "\n"
            << "[HTTP_PREFIX] -a [SERVER_IP_ADDRESS] "
               "-p [SERVER_PORT] -c [CACHE_SIZE] -m [MTU] -l [DEFAULT_LIFETIME "
               "(seconds)] -P [FIRST_IPv6_WORD_HEX] -M (for enabling manifest)"
            << std::endl;
  return -1;
}

int main(int argc, char** argv) {
  std::string prefix("http://hicn-http-proxy");
  std::string ip_address("127.0.0.1");
  std::string port("80");
  std::string cache_size("50000");
  std::string mtu("1500");
  std::string first_ipv6_word("b001");
  std::string default_content_lifetime("7200");  // seconds
  bool manifest = false;

  int opt;
  while ((opt = getopt(argc, argv, "a:p:c:m:P:l:M")) != -1) {
    switch (opt) {
      case 'a':
        ip_address = optarg;
        break;
      case 'p':
        port = optarg;
        break;
      case 'c':
        cache_size = optarg;
        break;
      case 'm':
        mtu = optarg;
        break;
      case 'P':
        first_ipv6_word = optarg;
        break;
      case 'l':
        default_content_lifetime = optarg;
        break;
      case 'M':
        manifest = true;
        break;
      case 'h':
      default:
        return usage(argv[0]);
        break;
    }
  }

  if (argv[optind] == 0) {
    std::cerr << "Using default prefix " << prefix << std::endl;
  } else {
    prefix = argv[optind];
  }

  std::cout << "Connecting to " << ip_address << " port " << port
            << " Cache size " << cache_size << " Prefix " << prefix << " MTU "
            << mtu << " IPv6 first word " << first_ipv6_word << std::endl;
  transport::AsyncConsumerProducer proxy(
      prefix, ip_address, port, cache_size, mtu, first_ipv6_word,
      std::stoul(default_content_lifetime) * 1000, manifest);

  proxy.run();

  return 0;
}