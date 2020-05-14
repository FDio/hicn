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

#include "src/http_proxy.h"

using namespace transport;

int usage(char* program) {
  std::cerr << "ICN Plugin not loaded!" << std::endl;
  std::cerr << "USAGE: " << program << "\n"
            << "[HTTP_PREFIX] -a [SERVER_IP_ADDRESS] "
               "-p [SERVER_PORT] -c [CACHE_SIZE] -m [MTU] -l [DEFAULT_LIFETIME "
               "(seconds)] -P [FIRST_IPv6_WORD_HEX] -M (enable manifest)"
            << std::endl;
  return -1;
}

int main(int argc, char** argv) {
  transport::AsyncConsumerProducer::Params params;
  params.prefix = "http://hicn-http-proxy";
  params.ip_address = "127.0.0.1";
  params.port = "80";
  params.cache_size = "50000";
  params.mtu = "1500";
  params.first_ipv6_word = "b001";
  params.default_content_lifetime = 7200;  // seconds
  params.manifest = false;

  std::uint16_t tcp_listen_port = 8080;
  std::uint16_t n_thread = 1;

  int opt;
  while ((opt = getopt(argc, argv, "a:p:c:m:P:l:ML:t:")) != -1) {
    switch (opt) {
      case 'a':
        params.ip_address = optarg;
        break;
      case 'p':
        params.port = optarg;
        break;
      case 'c':
        params.cache_size = optarg;
        break;
      case 'm':
        params.mtu = optarg;
        break;
      case 'P':
        params.first_ipv6_word = optarg;
        break;
      case 'l':
        params.default_content_lifetime = std::stoul(optarg);
        break;
      case 'L':
        tcp_listen_port = std::stoul(optarg);
        break;
      case 'M':
        params.manifest = true;
        break;
      case 't':
        n_thread = std::stoul(optarg);
        break;
      case 'h':
      default:
        return usage(argv[0]);
        break;
    }
  }

  if (argv[optind] == 0) {
    std::cerr << "Using default prefix " << params.prefix << std::endl;
  } else {
    params.prefix = argv[optind];
  }

  std::cout << "Connecting to " << params.ip_address << " port " << params.port
            << " Cache size " << params.cache_size << " Prefix "
            << params.prefix << " MTU " << params.mtu << " IPv6 first word "
            << params.first_ipv6_word << std::endl;

  transport::HTTPProxy proxy(params, tcp_listen_port, n_thread);

  proxy.run();

  return 0;
}