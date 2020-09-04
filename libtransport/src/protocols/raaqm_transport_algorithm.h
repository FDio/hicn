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

#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/statistics.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/congestion_window_protocol.h>
#include <protocols/raaqm_data_path.h>
#include <protocols/rate_estimation.h>
#include <protocols/transport_algorithm.h>

#include <array>
#include <queue>
#include <unordered_map>
#include <vector>

namespace transport {

namespace protocol {

class RaaqmTransportAlgorithm : public TransportAlgorithm,
                                public CWindowProtocol {
 public:
  // TODO: Add windows size and other beta/drop parameters
  RaaqmTransportAlgorithm(interface::TransportStatistics *stats,
                          IcnRateEstimator *rate_estimator, double drop_factor,
                          double minimum_drop_probability, double gamma,
                          double beta, uint32_t sample_number,
                          uint32_t interest_lifetime, double beta_wifi,
                          double drop_wifi, double beta_lte, double drop_lte,
                          unsigned int wifi_delay, unsigned int lte_delay,
                          double max_window, double min_window);

  ~RaaqmTransportAlgorithm() override;

  void reset() override;

  uint32_t onContentObject(uint32_t suffix, uint32_t path_label) override;

  uint32_t onInterestTimeout(uint32_t suffix) override;

  void onInterestSent(uint32_t suffix) override;

  void sessionEnd() override;

 protected:
  static constexpr uint32_t buffer_size =
      1 << interface::default_values::log_2_default_buffer_size;
  static constexpr uint16_t mask = buffer_size - 1;
  using PathTable =
      std::unordered_map<uint32_t, std::unique_ptr<RaaqmDataPath>>;

  void increaseWindow() override;
  void decreaseWindow() override;

  virtual void updateStats(uint32_t suffix, uint64_t rtt,
                           utils::TimePoint &now);

 private:
  void init();

  void updateRtt(uint32_t suffix);

  void RAAQM();

  void updatePathTable(uint32_t path_label);

  void checkDropProbability();

  void checkForStalePaths();

 protected:
  // Congestion window management
  double current_window_size_;
  // Protocol management
  uint64_t interests_in_flight_;
  std::array<utils::TimePoint, buffer_size> interest_timepoints_;

 private:
  /**
   * Current download path
   */
  RaaqmDataPath *cur_path_;

  /**
   * Hash table for path: each entry is a pair path ID(key) - path object
   */
  PathTable path_table_;

  // for rate-estimation at packet level
  IcnRateEstimator *rate_estimator_;
  interface::TransportStatistics *stats_;

  bool set_interest_filter_;

  // Params
  double drop_factor_;
  double minimum_drop_probability_;
  double gamma_;
  double beta_;
  uint32_t sample_number_;
  uint32_t interest_lifetime_;

  bool raaqm_autotune_;
  double beta_wifi_;
  double drop_wifi_;
  double beta_lte_;
  double drop_lte_;
  unsigned int wifi_delay_;
  unsigned int lte_delay_;
  double max_window_;
  double min_window_;
};

}  // end namespace protocol

}  // end namespace transport
