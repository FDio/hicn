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

#include <protocols/datagram_reassembly.h>
#include <protocols/transport_protocol.h>

namespace transport {

namespace protocol {

DatagramReassembly::DatagramReassembly(
    implementation::ConsumerSocket* icn_socket,
    TransportProtocol* transport_protocol)
    : Reassembly(icn_socket, transport_protocol) {}

void DatagramReassembly::reassemble(core::ContentObject& content_object) {
  auto read_buffer = content_object.getPayload();
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Size of payload: " << read_buffer->length() << ". Trimming "
      << transport_protocol_->transportHeaderLength();
  read_buffer->trimStart(transport_protocol_->transportHeaderLength());
  Reassembly::read_buffer_ = std::move(read_buffer);
  Reassembly::notifyApplication();
}

void DatagramReassembly::reassemble(utils::MemBuf& buffer, uint32_t suffix) {
  read_buffer_ = buffer.cloneOne();
  Reassembly::notifyApplication();
}

void DatagramReassembly::reInitialize() {}

}  // namespace protocol

}  // namespace transport
