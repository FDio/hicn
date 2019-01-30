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

#include <hicn/transport/protocols/rtc_data_path.h>

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
      queuing_delay(0.0),
      RTThistory_(HISTORY_LEN),
      OWDhistory_(HISTORY_LEN){};

void RTCDataPath::insertRttSample(uint64_t rtt) {
  // for the rtt we only keep track of the min one
  if (rtt < min_rtt) min_rtt = rtt;
}

void RTCDataPath::insertOwdSample(int64_t owd) {
  // for owd we use both min and avg
  if (owd < min_owd) min_owd = owd;

  avg_owd = (avg_owd * (1 - ALPHA_RTC)) + (owd * ALPHA_RTC);
}

void RTCDataPath::roundEnd() {
  // compute queuing delay
  queuing_delay = avg_owd - getMinOwd();

  // reset min_rtt and add it to the history
  if (min_rtt != UINT_MAX) {
    prev_min_rtt = min_rtt;
  } else {
    // this may happen if we do not receive any packet
    // from this path in the last round. in this case
    // we use the measure from the previuos round
    min_rtt = prev_min_rtt;
  }

  RTThistory_.pushBack(min_rtt);
  min_rtt = UINT_MAX;

  // do the same for min owd
  if (min_owd != INT_MAX) {
    prev_min_owd = min_owd;
  } else {
    min_owd = prev_min_owd;
  }

  OWDhistory_.pushBack(min_owd);
  min_owd = INT_MAX;
}

double RTCDataPath::getQueuingDealy() { return queuing_delay; }

uint64_t RTCDataPath::getMinRtt() { return RTThistory_.begin(); }

int64_t RTCDataPath::getMinOwd() { return OWDhistory_.begin(); }

}  // end namespace protocol

}  // end namespace transport
