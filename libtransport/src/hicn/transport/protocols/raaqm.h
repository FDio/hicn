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

#include <hicn/transport/protocols/byte_stream_reassembly.h>
#include <hicn/transport/protocols/congestion_window_protocol.h>
#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/protocols/raaqm_data_path.h>
#include <hicn/transport/protocols/rate_estimation.h>
#include <hicn/transport/utils/chrono_typedefs.h>

#include <queue>
#include <vector>

namespace transport {

namespace protocol {

class RaaqmTransportProtocol : public TransportProtocol,
                               public CWindowProtocol {
 public:
  RaaqmTransportProtocol(interface::ConsumerSocket *icnet_socket);

  ~RaaqmTransportProtocol();

  int start() override;

  void resume() override;

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

  virtual void updateStats(uint32_t suffix, uint64_t rtt,
                           utils::TimePoint &now);

 private:
  void init();

  void onContentObject(Interest::Ptr &&i, ContentObject::Ptr &&c) override;

  void onContentSegment(Interest::Ptr &&interest,
                        ContentObject::Ptr &&content_object);

  void onPacketDropped(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object) override;

  void onReassemblyFailed(std::uint32_t missing_segment) override;

  void onTimeout(Interest::Ptr &&i) override;

  virtual void scheduleNextInterests() override;

  void sendInterest(std::uint64_t next_suffix);

  void sendInterest(Interest::Ptr &&interest);

  void onContentReassembled(std::error_code ec) override;

  void updateRtt(uint64_t segment);

  void RAAQM();

  void updatePathTable(const ContentObject &content_object);

  void checkDropProbability();

  void checkForStalePaths();

  void printRtt();

 protected:
  // Congestion window management
  double current_window_size_;
  // Protocol management
  uint64_t interests_in_flight_;
  std::array<std::uint32_t, buffer_size> interest_retransmissions_;
  std::array<utils::TimePoint, buffer_size> interest_timepoints_;
  std::queue<Interest::Ptr> interest_to_retransmit_;

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
  utils::TimePoint t0_;

  bool set_interest_filter_;

  // for rate-estimation at packet level
  IcnRateEstimator *rate_estimator_;

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
};

}  // end namespace protocol

}  // end namespace transport