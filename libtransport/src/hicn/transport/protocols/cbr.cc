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
#include <hicn/transport/protocols/cbr.h>

namespace transport {

namespace protocol {

using namespace interface;

CbrTransportProtocol::CbrTransportProtocol(BaseSocket *icnet_socket)
    : VegasTransportProtocol(icnet_socket) {}

void CbrTransportProtocol::start(
    utils::SharableVector<uint8_t> &receive_buffer) {
  current_window_size_ = socket_->current_window_size_;
  VegasTransportProtocol::start(receive_buffer);
}

void CbrTransportProtocol::changeInterestLifetime(uint64_t segment) { return; }

void CbrTransportProtocol::increaseWindow() {}

void CbrTransportProtocol::decreaseWindow() {}

void CbrTransportProtocol::afterDataUnsatisfied(uint64_t segment) {}

void CbrTransportProtocol::afterContentReception(
    const Interest &interest, const ContentObject &content_object) {}

}  // end namespace protocol

}  // end namespace transport
