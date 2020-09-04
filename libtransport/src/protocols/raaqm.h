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

#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/byte_stream_reassembly.h>
#include <protocols/congestion_window_protocol.h>
#include <protocols/protocol.h>
#include <protocols/raaqm_data_path.h>
#include <protocols/raaqm_transport_algorithm.h>
#include <protocols/rate_estimation.h>

#include <queue>
#include <vector>

namespace transport {

namespace protocol {

class RaaqmTransportProtocol : public TransportProtocol {
 public:
  RaaqmTransportProtocol(implementation::ConsumerSocket *icnet_socket);

  ~RaaqmTransportProtocol();

  int start() override;

  void resume() override;

  void reset() override;

  virtual bool verifyKeyPackets() override;

 protected:
  static constexpr uint32_t buffer_size =
      1 << interface::default_values::log_2_default_buffer_size;
  static constexpr uint16_t mask = buffer_size - 1;
  using PathTable =
      std::unordered_map<uint32_t, std::unique_ptr<RaaqmDataPath>>;

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

  bool sendInterest(std::uint64_t next_suffix);

  void sendInterest(Interest::Ptr &&interest);

  void onContentReassembled(std::error_code ec) override;

  void updateRtt(uint64_t segment);

 protected:
  std::queue<Interest::Ptr> interest_to_retransmit_;
  std::array<std::uint32_t, buffer_size> interest_retransmissions_;
  uint32_t interests_in_flight_;
  double current_window_size_;

 private:
  std::unique_ptr<TransportAlgorithm> raaqm_algorithm_;
  std::unique_ptr<IcnRateEstimator> rate_estimator_;
  // TimePoints for statistic
  utils::TimePoint t0_;

  // Temporary placeholder for RAAQM algorithm
  // parameters
  bool raaqm_autotune_;
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
