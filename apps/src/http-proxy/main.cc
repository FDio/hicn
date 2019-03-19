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

#include "plugin/IcnReceiver.h"

using namespace transport;

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "ICN Plugin not loaded!" << std::endl;
    std::cerr << "USAGE: icn_stack_plugin.so [HTTP_PREFIX] [SERVER_IP_ADDRESS] "
                 "[SERVER_PORT]"
              << std::endl;
    return -1;
  }

  std::string prefix(argv[1]);
  std::string ip_address(argv[2]);
  std::string port(argv[3]);

  transport::AsyncConsumerProducer plugin(prefix, ip_address, port);

  plugin.run();

  return 0;
}