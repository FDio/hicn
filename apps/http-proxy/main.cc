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
  std::cerr << "USAGE: " << program << "\n"
            << "[HTTP_PREFIX] -a [SERVER_IP_ADDRESS] "
               "-p [SERVER_PORT] -c [CACHE_SIZE] -m [MTU] -l [DEFAULT_LIFETIME "
               "(seconds)] -P [FIRST_IPv6_WORD_HEX] -M (enable manifest)"
            << std::endl;
  return -1;
}

struct Params : HTTPProxy::ClientParams, HTTPProxy::ServerParams {
  void printParams() override {
    if (client) {
      HTTPProxy::ClientParams::printParams();
    } else if (server) {
      HTTPProxy::ServerParams::printParams();
    } else {
      throw std::runtime_error(
          "Proxy configured as client and server at the same time.");
    }

    std::cout << "\t"
              << "N Threads: " << n_thread << std::endl;
  }

  HTTPProxy instantiateProxyAsValue() {
    if (client) {
      HTTPProxy::ClientParams* p = dynamic_cast<HTTPProxy::ClientParams*>(this);
      return transport::HTTPProxy(*p, n_thread);
    } else if (server) {
      HTTPProxy::ServerParams* p = dynamic_cast<HTTPProxy::ServerParams*>(this);
      return transport::HTTPProxy(*p, n_thread);
    } else {
      throw std::runtime_error(
          "Proxy configured as client and server at the same time.");
    }
  }

  bool client = false;
  bool server = false;
  std::uint16_t n_thread = 1;
};

int main(int argc, char** argv) {
  Params params;

  params.prefix = "http://hicn-http-proxy";
  params.origin_address = "127.0.0.1";
  params.origin_port = "80";
  params.cache_size = "50000";
  params.mtu = "1500";
  params.first_ipv6_word = "b001";
  params.content_lifetime = "7200;";  // seconds
  params.manifest = false;
  params.tcp_listen_port = 8080;

  int opt;
  while ((opt = getopt(argc, argv, "CSa:p:c:m:P:l:ML:t:")) != -1) {
    switch (opt) {
      case 'C':
        if (params.server) {
          std::cerr << "Cannot be both client and server (both -C anc -S "
                       "options specified.)."
                    << std::endl;
          return usage(argv[0]);
        }
        params.client = true;
        break;
      case 'S':
        if (params.client) {
          std::cerr << "Cannot be both client and server (both -C anc -S "
                       "options specified.)."
                    << std::endl;
          return usage(argv[0]);
        }
        params.server = true;
        break;
      case 'a':
        params.origin_address = optarg;
        break;
      case 'p':
        params.origin_port = optarg;
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
        params.content_lifetime = optarg;
        break;
      case 'L':
        params.tcp_listen_port = std::stoul(optarg);
        break;
      case 'M':
        params.manifest = true;
        break;
      case 't':
        params.n_thread = std::stoul(optarg);
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

  params.printParams();
  transport::HTTPProxy proxy = params.instantiateProxyAsValue();
  proxy.run();

  return 0;
}