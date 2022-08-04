/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <core/global_configuration.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <implementation/socket.h>

namespace transport {
namespace implementation {

Socket::Socket(std::shared_ptr<core::Portal> &&portal)
    : portal_(std::move(portal)),
      is_async_(false),
      packet_format_(interface::default_values::packet_format),
      signer_(std::make_shared<auth::VoidSigner>()),
      verifier_(std::make_shared<auth::VoidVerifier>()) {}

int Socket::setSocketOption(int socket_option_key,
                            hicn_packet_format_t packet_format) {
  switch (socket_option_key) {
    case interface::GeneralTransportOptions::PACKET_FORMAT:
      packet_format_ = packet_format;
      break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int Socket::getSocketOption(int socket_option_key,
                            hicn_packet_format_t &packet_format) {
  switch (socket_option_key) {
    case interface::GeneralTransportOptions::PACKET_FORMAT:
      packet_format = packet_format_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

}  // namespace implementation
}  // namespace transport
