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

#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/rtc/rtc_data_path.h>
#include <stdlib.h>

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <cmath>

#define MAX_ROUNDS_WITHOUT_PKTS 10  // 2sec
#define AVG_RTT_TIME 1000           // (ms) 1sec

namespace transport {

namespace protocol {

namespace rtc {

RTCDataPath::RTCDataPath(uint32_t path_id)
    : path_id_(path_id),
      min_rtt(UINT_MAX),
      prev_min_rtt(UINT_MAX),
      max_rtt(0),
      prev_max_rtt(0),
      min_owd(INT_MAX),  // this is computed like in LEDBAT, so it is not the
                         // real OWD, but the measured one, that depends on the
                         // clock of sender and receiver. the only meaningful
                         // value is is the queueing delay. for this reason we
                         // keep both RTT (for the windowd calculation) and OWD
                         // (for congestion/quality control)
      prev_min_owd(INT_MAX),
      avg_owd(DBL_MAX),
      queuing_delay(DBL_MAX),
      jitter_(0.0),
      last_owd_(0),
      largest_recv_seq_(0),
      largest_recv_seq_time_(0),
      avg_inter_arrival_(DBL_MAX),
      rtt_sum_(0),
      last_avg_rtt_compute_(0),
      rtt_samples_(0),
      avg_rtt_(0.0),
      received_nacks_(false),
      received_packets_(0),
      rounds_without_packets_(0),
      last_received_data_packet_(0),
      min_RTT_history_(HISTORY_LEN),
      max_RTT_history_(HISTORY_LEN),
      OWD_history_(HISTORY_LEN){};

void RTCDataPath::insertRttSample(
    const utils::SteadyTime::Milliseconds& rtt_milliseconds, bool is_probe) {
  // compute min rtt
  uint64_t rtt = rtt_milliseconds.count();
  if (rtt < min_rtt) min_rtt = rtt;

  uint64_t now = utils::SteadyTime::nowMs().count();
  last_received_data_packet_ = now;

  // compute avg rtt
  if (is_probe) {
    // max rtt is computed only on probes to avoid to take into account the
    // production time at the server
    if (rtt > max_rtt) max_rtt = rtt;

    rtt_sum_ += rtt;
    rtt_samples_++;
  }

  if ((now - last_avg_rtt_compute_) >= AVG_RTT_TIME) {
    // compute a new avg rtt
    // if rtt_samples_ = 0 keep the same rtt
    if (rtt_samples_ != 0) avg_rtt_ = (double)rtt_sum_ / (double)rtt_samples_;

    rtt_sum_ = 0;
    rtt_samples_ = 0;
    last_avg_rtt_compute_ = now;
  }

  received_packets_++;
}

void RTCDataPath::insertOwdSample(int64_t owd) {
  // for owd we use both min and avg
  if (owd < min_owd) min_owd = owd;

  if (avg_owd != DBL_MAX)
    avg_owd = (avg_owd * (1 - ALPHA_RTC)) + (owd * ALPHA_RTC);
  else {
    avg_owd = owd;
  }

  int64_t queueVal = owd - std::min(getMinOwd(), min_owd);

  if (queuing_delay != DBL_MAX)
    queuing_delay = (queuing_delay * (1 - ALPHA_RTC)) + (queueVal * ALPHA_RTC);
  else {
    queuing_delay = queueVal;
  }

  // keep track of the jitter computed as for RTP (RFC 3550)
  int64_t diff = std::abs(owd - last_owd_);
  last_owd_ = owd;
  jitter_ += (1.0 / 16.0) * ((double)diff - jitter_);
}

void RTCDataPath::computeInterArrivalGap(uint32_t segment_number) {
  // got packet in sequence, compute gap
  if (largest_recv_seq_ == (segment_number - 1)) {
    uint64_t now = utils::SteadyTime::nowMs().count();
    uint64_t delta = now - largest_recv_seq_time_;
    largest_recv_seq_ = segment_number;
    largest_recv_seq_time_ = now;
    if (avg_inter_arrival_ == DBL_MAX)
      avg_inter_arrival_ = delta;
    else
      avg_inter_arrival_ =
          (avg_inter_arrival_ * (1 - ALPHA_RTC)) + (delta * ALPHA_RTC);
    return;
  }

  // ooo packet, update the stasts if needed
  if (largest_recv_seq_ <= segment_number) {
    largest_recv_seq_ = segment_number;
    largest_recv_seq_time_ = utils::SteadyTime::nowMs().count();
  }
}

void RTCDataPath::receivedNack() { received_nacks_ = true; }

double RTCDataPath::getInterArrivalGap() {
  if (avg_inter_arrival_ == DBL_MAX) return 0;
  return avg_inter_arrival_;
}

bool RTCDataPath::isValidProducer() {
  if (received_nacks_ && rounds_without_packets_ < MAX_ROUNDS_WITHOUT_PKTS)
    return true;
  return false;
}

bool RTCDataPath::isActive() {
  if (rounds_without_packets_ < MAX_ROUNDS_WITHOUT_PKTS) return true;
  return false;
}

bool RTCDataPath::pathToProducer() {
  if (received_nacks_) return true;
  return false;
}

void RTCDataPath::roundEnd() {
  // reset min_rtt and add it to the history
  if (min_rtt != UINT_MAX) {
    prev_min_rtt = min_rtt;
  } else {
    // this may happen if we do not receive any packet
    // from this path in the last round. in this case
    // we use the measure from the previuos round
    min_rtt = prev_min_rtt;
  }

  // same for max_rtt
  if (max_rtt != 0) {
    prev_max_rtt = max_rtt;
  } else {
    max_rtt = prev_max_rtt;
  }

  if (min_rtt == 0) min_rtt = 1;
  if (max_rtt == 0) max_rtt = 1;

  min_RTT_history_.pushBack(min_rtt);
  max_RTT_history_.pushBack(max_rtt);
  min_rtt = UINT_MAX;
  max_rtt = 0;

  // do the same for min owd
  if (min_owd != INT_MAX) {
    prev_min_owd = min_owd;
  } else {
    min_owd = prev_min_owd;
  }

  if (min_owd != INT_MAX) {
    OWD_history_.pushBack(min_owd);
    min_owd = INT_MAX;
  }

  if (received_packets_ == 0)
    rounds_without_packets_++;
  else
    rounds_without_packets_ = 0;
  received_packets_ = 0;
}

uint32_t RTCDataPath::getPathId() { return path_id_; }

double RTCDataPath::getQueuingDealy() {
  if (queuing_delay == DBL_MAX) return 0;
  return queuing_delay;
}

uint64_t RTCDataPath::getMinRtt() {
  if (min_RTT_history_.size() != 0) return min_RTT_history_.begin();
  return 0;
}

uint64_t RTCDataPath::getAvgRtt() { return std::round(avg_rtt_); }

uint64_t RTCDataPath::getMaxRtt() {
  if (max_RTT_history_.size() != 0) return max_RTT_history_.begin();
  return 0;
}

int64_t RTCDataPath::getMinOwd() {
  if (OWD_history_.size() != 0) return OWD_history_.begin();
  return INT_MAX;
}

double RTCDataPath::getJitter() { return jitter_; }

uint64_t RTCDataPath::getLastPacketTS() { return last_received_data_packet_; }

uint32_t RTCDataPath::getPacketsLastRound() { return received_packets_; }

void RTCDataPath::clearRtt() {
  min_RTT_history_.clear();
  max_RTT_history_.clear();
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
