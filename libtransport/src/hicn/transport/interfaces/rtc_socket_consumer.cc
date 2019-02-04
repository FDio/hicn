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

#include <hicn/transport/interfaces/rtc_socket_consumer.h>
#include <hicn/transport/protocols/rtc.h>

namespace transport {

namespace interface {

RTCConsumerSocket::RTCConsumerSocket(int protocol, asio::io_service &io_service)
    : ConsumerSocket(protocol, io_service) {}

RTCConsumerSocket::RTCConsumerSocket(int protocol) : ConsumerSocket(protocol) {}

RTCConsumerSocket::~RTCConsumerSocket() {}

void RTCConsumerSocket::handleRTCPPacket(uint8_t *packet, size_t len) {
  RTCTransportProtocol *transport = dynamic_cast<RTCTransportProtocol *>(
      ConsumerSocket::transport_protocol_.get());
  if (transport) transport->onRTCPPacket(packet, len);
}

}  // namespace interface

}  // end namespace transport
