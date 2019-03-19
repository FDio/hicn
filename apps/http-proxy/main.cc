/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
  std::cerr << "USAGE: " << program
            << "[HTTP_PREFIX] -a [SERVER_IP_ADDRESS] "
               "-p [SERVER_PORT] -c [CACHE_SIZE]"
            << std::endl;
  return -1;
}

int main(int argc, char** argv) {
  std::string prefix("http://hicn-http-proxy");
  std::string ip_address("127.0.0.1");
  std::string port("80");
  std::string cache_size("50000");

  int opt;
  while ((opt = getopt(argc, argv, "a:p:c:")) != -1) {
    switch (opt) {
      case 'a':
        prefix = optarg;
        break;
      case 'p':
        port = optarg;
        break;
      case 'c':
        cache_size = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        break;
    }
  }

  if (argv[optind] == 0) {
    std::cerr << "Using default prefix " << prefix << std::endl;
  } else {
    prefix = argv[optind];
  }

  transport::AsyncConsumerProducer proxy(prefix, ip_address, port, cache_size);

  proxy.run();

  return 0;
}