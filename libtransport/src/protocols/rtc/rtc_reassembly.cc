/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <implementation/socket_consumer.h>
#include <protocols/rtc/rtc_reassembly.h>
#include <protocols/transport_protocol.h>

namespace transport {

namespace protocol {

namespace rtc {

RtcReassembly::RtcReassembly(implementation::ConsumerSocket* icn_socket,
                             TransportProtocol* transport_protocol)
    : DatagramReassembly(icn_socket, transport_protocol) {
  is_setup_ = false;
}

void RtcReassembly::reassemble(core::ContentObject& content_object) {
  if (!is_setup_) {
    is_setup_ = true;
    reassembly_consumer_socket_->getSocketOption(
        interface::RtcTransportOptions::AGGREGATED_DATA, data_aggregation_);
  }

  auto read_buffer = content_object.getPayload();
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Size of payload: " << read_buffer->length();

  read_buffer->trimStart(transport_protocol_->transportHeaderLength(false));

  if (data_aggregation_) {
    rtc::AggrPktHeader hdr((uint8_t*)read_buffer->data());

    for (uint8_t i = 0; i < hdr.getNumberOfPackets(); i++) {
      std::unique_ptr<utils::MemBuf> segment = read_buffer->clone();

      uint16_t pkt_start = 0;
      uint16_t pkt_len = 0;
      int res = hdr.getPacketOffsets(i, &pkt_start, &pkt_len);
      if (res == -1) {
        // this should not happen
        break;
      }

      segment->trimStart(pkt_start);
      segment->trimEnd(segment->length() - pkt_len);

      Reassembly::read_buffer_ = std::move(segment);
      Reassembly::notifyApplication();
    }
  } else {
    Reassembly::read_buffer_ = std::move(read_buffer);
    Reassembly::notifyApplication();
  }
}

void RtcReassembly::reassemble(utils::MemBuf& buffer, uint32_t suffix) {
  if (!is_setup_) {
    is_setup_ = true;
    reassembly_consumer_socket_->getSocketOption(
        interface::RtcTransportOptions::AGGREGATED_DATA, data_aggregation_);
  }

  if (data_aggregation_) {
    rtc::AggrPktHeader hdr((uint8_t*)buffer.data());

    for (uint8_t i = 0; i < hdr.getNumberOfPackets(); i++) {
      std::unique_ptr<utils::MemBuf> segment = buffer.clone();

      uint16_t pkt_start = 0;
      uint16_t pkt_len = 0;
      int res = hdr.getPacketOffsets(i, &pkt_start, &pkt_len);
      if (res == -1) {
        // this should not happen
        break;
      }

      segment->trimStart(pkt_start);
      segment->trimEnd(segment->length() - pkt_len);

      Reassembly::read_buffer_ = std::move(segment);
      Reassembly::notifyApplication();
    }

  } else {
    Reassembly::read_buffer_ = buffer.cloneOne();
    Reassembly::notifyApplication();
  }
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
