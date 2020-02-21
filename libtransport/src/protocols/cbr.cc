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

#include <protocols/cbr.h>

namespace transport {

namespace protocol {

using namespace interface;

CbrTransportProtocol::CbrTransportProtocol(
    implementation::ConsumerSocket *icnet_socket)
    : RaaqmTransportProtocol(icnet_socket) {}

int CbrTransportProtocol::start() { return RaaqmTransportProtocol::start(); }

void CbrTransportProtocol::reset() {
  RaaqmTransportProtocol::reset();
  socket_->getSocketOption(GeneralTransportOptions::CURRENT_WINDOW_SIZE,
                           current_window_size_);
}

void CbrTransportProtocol::afterDataUnsatisfied(uint64_t segment) {}

void CbrTransportProtocol::afterContentReception(
    const Interest &interest, const ContentObject &content_object) {
  auto segment = content_object.getName().getSuffix();
  auto now = utils::SteadyClock::now();
  auto rtt = std::chrono::duration_cast<utils::Microseconds>(
      now - interest_timepoints_[segment & mask]);
  // Update stats
  updateStats(segment, rtt.count(), now);
}

}  // end namespace protocol

}  // end namespace transport
