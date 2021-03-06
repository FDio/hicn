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

#pragma once

#include <glog/logging.h>
#include <protocols/datagram_reassembly.h>
#include <protocols/rtc/rtc_consts.h>

namespace transport {

namespace protocol {

namespace rtc {

class RtcReassembly : public DatagramReassembly {
 public:
  RtcReassembly(implementation::ConsumerSocket *icn_socket,
                TransportProtocol *transport_protocol)
      : DatagramReassembly(icn_socket, transport_protocol) {}

  void reassemble(core::ContentObject &content_object) override {
    auto read_buffer = content_object.getPayload();
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Size of payload: " << read_buffer->length();
    read_buffer->trimStart(transport_protocol_->transportHeaderLength());
    Reassembly::read_buffer_ = std::move(read_buffer);
    Reassembly::notifyApplication();
  }
};

}  // namespace rtc
}  // namespace protocol
}  // end namespace transport
