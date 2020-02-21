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

#include <hicn/transport/core/raw_socket_interface.h>
#include <hicn/transport/utils/linux.h>

#include <fstream>

namespace transport {

namespace core {

static std::string config_folder_path = "/etc/transport/interface.conf.d";

RawSocketInterface::RawSocketInterface(RawSocketConnector &connector)
    : ForwarderInterface<RawSocketInterface, RawSocketConnector>(connector) {}

RawSocketInterface::~RawSocketInterface() {}

void RawSocketInterface::connect(bool is_consumer) {
  std::string complete_filename =
      config_folder_path + std::string("/") + output_interface_;

  std::ifstream is(complete_filename);
  std::string interface;

  if (is) {
    is >> remote_mac_address_;
  }

  // Get interface ip address
  struct sockaddr_in6 address = {0};
  utils::retrieveInterfaceAddress(output_interface_, &address);

  std::memcpy(&inet6_address_.v6.as_u8, &address.sin6_addr,
              sizeof(address.sin6_addr));
  connector_.connect(output_interface_, remote_mac_address_);
}

void RawSocketInterface::registerRoute(Prefix &prefix) { return; }

}  // namespace core

}  // namespace transport
