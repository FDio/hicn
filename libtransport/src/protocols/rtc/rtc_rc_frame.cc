/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_rc_frame.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

RTCRateControlFrame::RTCRateControlFrame() : cc_detector_() {}

RTCRateControlFrame::~RTCRateControlFrame() {}

void RTCRateControlFrame::onNewRound(double round_len) {
  if (!rc_on_) return;

  CongestionState prev_congestion_state = congestion_state_;
  cc_detector_.updateStats();
  congestion_state_ = (CongestionState)cc_detector_.getState();

  if (congestion_state_ == CongestionState::Congested) {
    if (prev_congestion_state == CongestionState::Normal) {
      // congestion detected, notify app and init congestion win
      double prod_rate = protocol_state_->getReceivedRate();
      double rtt = (double)protocol_state_->getRTT() / MILLI_IN_A_SEC;
      double packet_size = protocol_state_->getAveragePacketSize();

      if (prod_rate == 0.0 || rtt == 0.0 || packet_size == 0.0) {
        // TODO do something
        return;
      }

      congestion_win_ = (uint32_t)ceil(prod_rate * rtt / packet_size);
    }
    uint32_t win = congestion_win_ * WIN_DECREASE_FACTOR;
    congestion_win_ = std::max(win, WIN_MIN);
    return;
  }
}

void RTCRateControlFrame::onDataPacketReceived(
    const core::ContentObject &content_object) {
  if (!rc_on_) return;

  uint32_t seq = content_object.getName().getSuffix();
  if (!protocol_state_->isPending(seq)) return;

  cc_detector_.addPacket(content_object);
}

void RTCRateControlFrame::receivedBwProbeTrain(uint64_t firts_probe_ts,
                                               uint64_t last_probe_ts,
                                               uint32_t total_probes) {
  // TODO
  return;
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
