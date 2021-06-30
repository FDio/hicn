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

#include <implementation/socket_consumer.h>
#include <protocols/indexer.h>

namespace transport {

namespace protocol {

using namespace interface;

const constexpr uint32_t Indexer::invalid_index;

Indexer::Indexer(implementation::ConsumerSocket *socket,
                 TransportProtocol *transport)
    : socket_(socket), transport_(transport) {
  setVerifier();
}

void Indexer::setVerifier() {
  if (socket_) {
    socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier_);
  }
}

}  // end namespace protocol

}  // end namespace transport
