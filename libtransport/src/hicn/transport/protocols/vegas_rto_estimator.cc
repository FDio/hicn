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

#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/protocols/vegas_rto_estimator.h>

#include <algorithm>
#include <cmath>

namespace transport {

namespace protocol {

using namespace interface;

RtoEstimator::RtoEstimator(Duration min_rto)
    : smoothed_rtt_((double)RtoEstimator::getInitialRtt().count()),
      rtt_variation_(0),
      first_measurement_(true),
      last_rto_((double)min_rto.count()) {}

void RtoEstimator::addMeasurement(Duration rtt) {
  double duration = static_cast<double>(rtt.count());
  if (first_measurement_) {
    smoothed_rtt_ = duration;
    rtt_variation_ = duration / 2;
    first_measurement_ = false;
  } else {
    rtt_variation_ = (1 - default_values::beta) * rtt_variation_ +
                     default_values::beta * std::abs(smoothed_rtt_ - duration);
    smoothed_rtt_ = (1 - default_values::alpha) * smoothed_rtt_ +
                    default_values::alpha * duration;
  }
}

RtoEstimator::Duration RtoEstimator::computeRto() const {
  double rto = smoothed_rtt_ +
               std::max(double(default_values::clock_granularity.count()),
                        default_values::k* rtt_variation_);
  return Duration(static_cast<Duration::rep>(rto));
}

}  // end namespace protocol

}  // end namespace transport