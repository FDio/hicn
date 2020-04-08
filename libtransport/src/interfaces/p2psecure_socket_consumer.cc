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

#include <hicn/transport/interfaces/p2psecure_socket_consumer.h>

#include <implementation/p2psecure_socket_consumer.h>

namespace transport {
namespace interface {

P2PSecureConsumerSocket::P2PSecureConsumerSocket(int protocol)
    : ConsumerSocket() {
  socket_ = std::unique_ptr<implementation::ConsumerSocket>(
      new implementation::P2PSecureConsumerSocket(this, protocol));
}

void P2PSecureConsumerSocket::registerPrefix(const Prefix &producer_namespace) {
  implementation::P2PSecureConsumerSocket &secure_consumer_socket =
      *(static_cast<implementation::P2PSecureConsumerSocket *>(socket_.get()));
  secure_consumer_socket.registerPrefix(producer_namespace);
}

}  // namespace interface
}  // namespace transport
