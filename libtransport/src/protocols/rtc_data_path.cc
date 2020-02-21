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

#include <protocols/rtc_data_path.h>

#include <cfloat>
#include <chrono>

#define MAX_ROUNDS_WITHOUT_PKTS 10  // 2sec

namespace transport {

namespace protocol {

RTCDataPath::RTCDataPath()
    : min_rtt(UINT_MAX),
      prev_min_rtt(UINT_MAX),
      min_owd(INT_MAX),  // this is computed like in LEDBAT, so it is not the
                         // real OWD, but the measured one, that depends on the
                         // clock of sender and receiver. the only meaningful
                         // value is is the queueing delay. for this reason we
                         // keep both RTT (for the windowd calculation) and OWD
                         // (for congestion/quality control)
      prev_min_owd(INT_MAX),
      avg_owd(0.0),
      queuing_delay(DBL_MAX),
      lastRecvSeq_(0),
      lastRecvTime_(0),
      avg_inter_arrival_(DBL_MAX),
      received_nacks_(false),
      received_packets_(false),
      rounds_without_packets_(0),
      RTThistory_(HISTORY_LEN),
      OWDhistory_(HISTORY_LEN){};

void RTCDataPath::insertRttSample(uint64_t rtt) {
  // for the rtt we only keep track of the min one
  if (rtt < min_rtt) min_rtt = rtt;
}

void RTCDataPath::insertOwdSample(int64_t owd) {
  // for owd we use both min and avg
  if (owd < min_owd) min_owd = owd;

  if (avg_owd != DBL_MAX)
    avg_owd = (avg_owd * (1 - ALPHA_RTC)) + (owd * ALPHA_RTC);
  else {
    avg_owd = owd;
  }

  // owd is computed only for valid data packets so we count only
  // this for decide if we recevie traffic or not
  received_packets_ = true;
}

void RTCDataPath::computeInterArrivalGap(uint32_t segmentNumber) {
  // got packet in sequence, compute gap
  if (lastRecvSeq_ == (segmentNumber - 1)) {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();
    uint64_t delta = now - lastRecvTime_;
    lastRecvSeq_ = segmentNumber;
    lastRecvTime_ = now;
    if (avg_inter_arrival_ == DBL_MAX)
      avg_inter_arrival_ = delta;
    else
      avg_inter_arrival_ =
          (avg_inter_arrival_ * (1 - ALPHA_RTC)) + (delta * ALPHA_RTC);
    return;
  }

  // ooo packet, update the stasts if needed
  if (lastRecvSeq_ <= segmentNumber) {
    lastRecvSeq_ = segmentNumber;
    lastRecvTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count();
  }
}

void RTCDataPath::receivedNack() { received_nacks_ = true; }

double RTCDataPath::getInterArrivalGap() {
  if (avg_inter_arrival_ == DBL_MAX) return 0;
  return avg_inter_arrival_;
}

bool RTCDataPath::isActive() {
  if (received_nacks_ && rounds_without_packets_ < MAX_ROUNDS_WITHOUT_PKTS)
    return true;
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

  if (min_rtt == 0) min_rtt = 1;

  RTThistory_.pushBack(min_rtt);
  min_rtt = UINT_MAX;

  // do the same for min owd
  if (min_owd != INT_MAX) {
    prev_min_owd = min_owd;
  } else {
    min_owd = prev_min_owd;
  }

  if (min_owd != INT_MAX) {
    OWDhistory_.pushBack(min_owd);
    min_owd = INT_MAX;

    // compute queuing delay
    queuing_delay = avg_owd - getMinOwd();

  } else {
    queuing_delay = 0.0;
  }

  if (!received_packets_)
    rounds_without_packets_++;
  else
    rounds_without_packets_ = 0;
  received_packets_ = false;
}

double RTCDataPath::getQueuingDealy() { return queuing_delay; }

uint64_t RTCDataPath::getMinRtt() { return RTThistory_.begin(); }

int64_t RTCDataPath::getMinOwd() { return OWDhistory_.begin(); }

}  // end namespace protocol

}  // end namespace transport
