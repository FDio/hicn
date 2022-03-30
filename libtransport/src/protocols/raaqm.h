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
#include <protocols/byte_stream_reassembly.h>
#include <protocols/congestion_window_protocol.h>
#include <protocols/raaqm_data_path.h>
#include <protocols/rate_estimation.h>
#include <protocols/transport_protocol.h>

#include <queue>
#include <random>
#include <vector>

namespace transport {

namespace protocol {

class RaaqmTransportProtocol : public TransportProtocol,
                               public CWindowProtocol {
 public:
  RaaqmTransportProtocol(implementation::ConsumerSocket *icn_socket);

  ~RaaqmTransportProtocol();

  using TransportProtocol::start;
  using TransportProtocol::stop;

  void reset() override;

 protected:
  static constexpr uint32_t buffer_size =
      1 << interface::default_values::log_2_default_buffer_size;
  static constexpr uint16_t mask = buffer_size - 1;
  using PathTable =
      std::unordered_map<uint32_t, std::unique_ptr<RaaqmDataPath>>;

  void increaseWindow() override;
  void decreaseWindow() override;

  virtual void afterContentReception(const Interest &interest,
                                     const ContentObject &content_object);
  virtual void afterDataUnsatisfied(uint64_t segment);

  virtual void updateStats(uint32_t suffix,
                           const utils::SteadyTime::Milliseconds &rtt,
                           utils::SteadyTime::TimePoint &now);

 private:
  void init();

  void onContentObjectReceived(Interest &i, ContentObject &c,
                               std::error_code &ec) override;
  void onPacketDropped(Interest &interest, ContentObject &content_object,
                       const std::error_code &reason) override;
  void onReassemblyFailed(std::uint32_t missing_segment) override;
  void onInterestTimeout(Interest::Ptr &i, const Name &n) override;
  virtual void scheduleNextInterests() override;
  void sendInterest(const Name &interest_name,
                    std::array<uint32_t, MAX_AGGREGATED_INTEREST>
                        *additional_suffixes = nullptr,
                    uint32_t len = 0) override;

  void onContentReassembled(const std::error_code &ec) override;
  void updateRtt(uint64_t segment);
  void RAAQM();
  void updatePathTable(const ContentObject &content_object);
  void checkDropProbability();
  void checkForStalePaths();
  void printRtt();

  auto shared_from_this() { return utils::shared_from(this); }

 protected:
  // Congestion window management
  double current_window_size_;
  // Protocol management
  uint64_t interests_in_flight_;
  std::array<std::uint32_t, buffer_size> interest_retransmissions_;
  std::array<utils::SteadyTime::TimePoint, buffer_size> interest_timepoints_;
  std::queue<uint32_t> interest_to_retransmit_;

 private:
  /**
   * Current download path
   */
  RaaqmDataPath *cur_path_;

  /**
   * Hash table for path: each entry is a pair path ID(key) - path object
   */
  PathTable path_table_;

  // TimePoints for statistic
  utils::SteadyTime::TimePoint t0_;

  bool set_interest_filter_;

  // for rate-estimation at packet level
  IcnRateEstimator *rate_estimator_;

  // Real distribution
  std::uniform_real_distribution<> dis_;

  // params for autotuning
  bool raaqm_autotune_;
  double default_beta_;
  double default_drop_;
  double beta_wifi_;
  double drop_wifi_;
  double beta_lte_;
  double drop_lte_;
  unsigned int wifi_delay_;
  unsigned int lte_delay_;

  bool schedule_interests_;
};

}  // end namespace protocol

}  // end namespace transport
