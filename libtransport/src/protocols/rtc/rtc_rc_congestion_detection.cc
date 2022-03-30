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

#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_rc_congestion_detection.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

RTCRateControlCongestionDetection::RTCRateControlCongestionDetection()
    : rounds_without_congestion_(4), last_queue_(0) {}  // must be > 3

RTCRateControlCongestionDetection::~RTCRateControlCongestionDetection() {}

void RTCRateControlCongestionDetection::onNewRound(double round_len) {
  if (!rc_on_) return;

  double rtt = (double)protocol_state_->getMinRTT() / MILLI_IN_A_SEC;
  double queue = protocol_state_->getQueuing();

  if (rtt == 0.0) return;  // no info from the producer

  if (last_queue_ == queue) {
    // if last_queue == queue the consumer didn't receive any
    // packet from the producer. we do not change the current congestion state.
    // we just increase the counter of rounds whithout congestion if needed
    // (in case of congestion the counter is already set to 0)
    if (congestion_state_ == CongestionState::Normal)
      rounds_without_congestion_++;
  } else {
    if (queue > MAX_QUEUING_DELAY) {
      // here we detect congestion.
      congestion_state_ = CongestionState::Congested;
      rounds_without_congestion_ = 0;
    } else {
      // wait 3 rounds before switch back to no congestion
      if (rounds_without_congestion_ > 3) {
        // nothing bad is happening
        congestion_state_ = CongestionState::Normal;
      }
      rounds_without_congestion_++;
    }
    last_queue_ = queue;
  }
}

void RTCRateControlCongestionDetection::onDataPacketReceived(
    const core::ContentObject &content_object, bool compute_stats) {
  // nothing to do
  return;
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
