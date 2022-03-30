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
#include <hicn/transport/utils/shared_ptr_utils.h>
#include <protocols/rtc/rtc_rc.h>

namespace transport {

namespace protocol {

namespace rtc {

const int ROUND_HISTORY_SIZE = 10;  // equivalent to two seconds
const int ROUND_TO_WAIT_FORCE_DECISION = 5;

// once congestion is gone, we need to wait for k rounds before changing the
// congestion cause in the case it appears again
const int ROUND_TO_RESET_CAUSE = 5;

const int MIN_IST_VALUE = 150;  // samples of ist larger than 150ms are
                                // discarded
const double CONGESTION_FREE_QUEUEING_DELAY = 10;

enum class CongestionCause : uint8_t {
  COMPETING_CROSS_TRAFFIC,
  FRIENDLY_CROSS_TRAFFIC,
  UNKNOWN_CROSS_TRAFFIC,
  LINK_CAPACITY,
  UNKNOWN
};

class RTCRateControlIAT : public RTCRateControl {
 public:
  RTCRateControlIAT();

  ~RTCRateControlIAT();

  void onNewRound(double round_len);
  void onDataPacketReceived(const core::ContentObject &content_object,
                            bool compute_stats);

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  void reset_congestion_statistics();

  double compute_iat_stdev(std::vector<double> v);

  CongestionCause apply_classification_tree(bool force_reply);

 private:
  uint32_t rounds_since_last_drop_;
  uint32_t rounds_without_congestion_;
  uint32_t rounds_with_congestion_;
  double last_queue_;
  uint64_t last_rcv_time_;
  uint64_t last_prod_time_;
  uint32_t last_seq_number_;
  double target_rate_avg_;

  // Iat values are not immediately added to the congestion free set of values
  std::array<std::vector<double>, ROUND_HISTORY_SIZE> iat_on_hold_;
  uint32_t round_index_;

  // with congestion statistics
  std::vector<double> iat_;
  std::vector<double> received_rate_;
  std::vector<double> target_rate_;

  // congestion free statistics
  std::vector<double> congestion_free_iat_;

  CongestionCause congestion_cause_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
