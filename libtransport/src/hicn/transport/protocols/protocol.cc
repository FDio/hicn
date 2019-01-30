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
#include <hicn/transport/protocols/protocol.h>

namespace transport {

namespace protocol {

TransportProtocol::TransportProtocol(interface::BaseSocket *icn_socket)
    : socket_(dynamic_cast<interface::ConsumerSocket *>(icn_socket)),
      is_running_(false),
      interest_pool_() {
  // Create pool of interests
  increasePoolSize();
}

TransportProtocol::~TransportProtocol() {}

void TransportProtocol::updatePortal() { portal_ = socket_->portal_; }

bool TransportProtocol::isRunning() { return is_running_; }

void TransportProtocol::increasePoolSize(std::size_t size) {
  for (std::size_t i = 0; i < size; i++) {
    interest_pool_.add(new Interest());
  }
}

}  // end namespace protocol

}  // end namespace transport
