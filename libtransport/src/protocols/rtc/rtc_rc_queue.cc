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
#include <protocols/rtc/rtc_rc_queue.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

RTCRateControlQueue::RTCRateControlQueue()
    : rounds_since_last_drop_(0),
      rounds_without_congestion_(0),
      last_queue_(0) {}

RTCRateControlQueue::~RTCRateControlQueue() {}

void RTCRateControlQueue::onNewRound(double round_len) {
  if (!rc_on_) return;

  double received_rate = protocol_state_->getReceivedRate();
  double target_rate =
      protocol_state_->getProducerRate() * PRODUCTION_RATE_FRACTION;
  double rtt = (double)protocol_state_->getMinRTT() / MILLI_IN_A_SEC;
  double packet_size = protocol_state_->getAveragePacketSize();
  double queue = protocol_state_->getQueuing();

  if (rtt == 0.0) return;  // no info from the producer

  CongestionState prev_congestion_state = congestion_state_;

  if (prev_congestion_state == CongestionState::Normal &&
      received_rate >= target_rate) {
    // if the queue is high in this case we are most likelly fighting with
    // a TCP flow and there is enough bandwidth to match the producer rate
    congestion_state_ = CongestionState::Normal;
  } else if (queue > MAX_QUEUING_DELAY || last_queue_ == queue) {
    // here we detect congestion. in the case that last_queue == queue
    // the consumer didn't receive any packet from the producer so we
    // consider this case as congestion
    // TODO: wath happen in case of high loss rate?
    congestion_state_ = CongestionState::Congested;
  } else {
    // nothing bad is happening
    congestion_state_ = CongestionState::Normal;
  }

  last_queue_ = queue;

  if (congestion_state_ == CongestionState::Congested) {
    if (prev_congestion_state == CongestionState::Normal) {
      // init the congetion window using the received rate
      congestion_win_ = (uint32_t)ceil(received_rate * rtt / packet_size);
      rounds_since_last_drop_ = ROUNDS_BEFORE_TAKE_ACTION + 1;
    }

    if (rounds_since_last_drop_ >= ROUNDS_BEFORE_TAKE_ACTION) {
      uint32_t win = congestion_win_ * WIN_DECREASE_FACTOR;
      congestion_win_ = std::max(win, WIN_MIN);
      rounds_since_last_drop_ = 0;
      return;
    }

    rounds_since_last_drop_++;
  }

  if (congestion_state_ == CongestionState::Normal) {
    if (prev_congestion_state == CongestionState::Congested) {
      rounds_without_congestion_ = 0;
    }

    rounds_without_congestion_++;
    if (rounds_without_congestion_ < ROUNDS_BEFORE_TAKE_ACTION) return;

    congestion_win_ = congestion_win_ * WIN_INCREASE_FACTOR;
    congestion_win_ = std::min(congestion_win_, INITIAL_WIN_MAX);
  }
}

void RTCRateControlQueue::onDataPacketReceived(
    const core::ContentObject &content_object, bool compute_stats) {
  // nothing to do
  return;
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
