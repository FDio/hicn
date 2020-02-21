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

#include <stdint.h>
#include <climits>

#include <utils/min_filter.h>

#define ALPHA_RTC 0.125
#define HISTORY_LEN 20  // 4 sec

namespace transport {

namespace protocol {

class RTCDataPath {
 public:
  RTCDataPath();

 public:
  void insertRttSample(uint64_t rtt);
  void insertOwdSample(int64_t owd);
  void computeInterArrivalGap(uint32_t segmentNumber);
  void receivedNack();

  uint64_t getMinRtt();
  double getQueuingDealy();
  double getInterArrivalGap();
  bool isActive();

  void roundEnd();

 private:
  int64_t getMinOwd();

  uint64_t min_rtt;
  uint64_t prev_min_rtt;

  int64_t min_owd;
  int64_t prev_min_owd;

  double avg_owd;

  double queuing_delay;

  uint32_t lastRecvSeq_;
  uint64_t lastRecvTime_;
  double avg_inter_arrival_;

  // flags to check if a path is active
  // we considere a path active if it reaches a producer
  //(not a cache) --aka we got at least one nack on this path--
  // and if we receives packets
  bool received_nacks_;
  bool received_packets_;
  uint8_t rounds_without_packets_;  // if we don't get any packet
                                    // for MAX_ROUNDS_WITHOUT_PKTS
                                    // we consider the path inactive

  utils::MinFilter<uint64_t> RTThistory_;
  utils::MinFilter<int64_t> OWDhistory_;
};

}  // namespace protocol

}  // end namespace transport
