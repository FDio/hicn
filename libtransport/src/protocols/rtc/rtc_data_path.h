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

#pragma once

#include <hicn/transport/utils/chrono_typedefs.h>
#include <stdint.h>
#include <utils/max_filter.h>
#include <utils/min_filter.h>

#include <climits>

namespace transport {

namespace protocol {

namespace rtc {

const double ALPHA_RTC = 0.125;
const uint32_t HISTORY_LEN = 20;  // 4 sec

class RTCDataPath {
 public:
  RTCDataPath(uint32_t path_id);

 public:
  void insertRttSample(const utils::SteadyTime::Milliseconds &rtt,
                       bool is_probe);
  void insertOwdSample(int64_t owd);
  void computeInterArrivalGap(uint32_t segment_number);
  void receivedNack();

  uint32_t getPathId();
  uint64_t getMinRtt();
  uint64_t getAvgRtt();
  uint64_t getMaxRtt();
  double getQueuingDealy();
  double getInterArrivalGap();
  double getJitter();
  bool isActive();
  bool pathToProducer();
  uint64_t getLastPacketTS();
  uint32_t getPacketsLastRound();

  void clearRtt();

  void roundEnd();

 private:
  uint32_t path_id_;

  int64_t getMinOwd();

  uint64_t min_rtt;
  uint64_t prev_min_rtt;

  uint64_t max_rtt;
  uint64_t prev_max_rtt;

  int64_t min_owd;
  int64_t prev_min_owd;

  double avg_owd;

  double queuing_delay;

  double jitter_;
  int64_t last_owd_;

  uint32_t largest_recv_seq_;
  uint64_t largest_recv_seq_time_;
  double avg_inter_arrival_;

  // compute the avg rtt over one sec
  uint64_t rtt_sum_;
  uint64_t last_avg_rtt_compute_;
  uint32_t rtt_samples_;
  double avg_rtt_;

  // flags to check if a path is active
  // we considere a path active if it reaches a producer
  //(not a cache) --aka we got at least one nack on this path--
  // and if we receives packets
  bool received_nacks_;
  uint32_t received_packets_;
  uint32_t rounds_without_packets_;     // if we don't get any packet
                                        // for MAX_ROUNDS_WITHOUT_PKTS
                                        // we consider the path inactive
  uint64_t last_received_data_packet_;  // timestamp for the last data received
                                        // on this path

  utils::MinFilter<uint64_t> min_RTT_history_;
  utils::MaxFilter<uint64_t> max_RTT_history_;
  utils::MinFilter<int64_t> OWD_history_;
};

}  // namespace rtc

}  // namespace protocol

}  // end namespace transport
