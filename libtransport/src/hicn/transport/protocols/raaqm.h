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

#include <hicn/transport/protocols/raaqm_data_path.h>
#include <hicn/transport/protocols/rate_estimation.h>
#include <hicn/transport/protocols/vegas.h>
#include <hicn/transport/protocols/vegas_rto_estimator.h>

namespace transport {

namespace protocol {

class RaaqmTransportProtocol : public VegasTransportProtocol {
 public:
  RaaqmTransportProtocol(interface::BaseSocket *icnet_socket);

  ~RaaqmTransportProtocol();

  void start(utils::SharableVector<uint8_t> &content_buffer) override;

 protected:
  void copyContent(const ContentObject &content_object) override;

 private:
  void init();

  void afterContentReception(const Interest &interest,
                             const ContentObject &content_object) override;

  void afterDataUnsatisfied(uint64_t segment) override;

  void increaseWindow() override;

  void updateRtt(uint64_t segment);

  void decreaseWindow() override;

  void changeInterestLifetime(uint64_t segment) override;

  void onTimeout(Interest::Ptr &&interest) override;

  void RAAQM();

  void updatePathTable(const ContentObject &content_object);

  void check_drop_probability();

  void check_for_stale_paths();

  void printRtt();

  /**
   * Current download path
   */
  std::shared_ptr<RaaqmDataPath> cur_path_;

  /**
   * Hash table for path: each entry is a pair path ID(key) - path object
   */
  std::unordered_map<uint32_t, std::shared_ptr<RaaqmDataPath>> path_table_;

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