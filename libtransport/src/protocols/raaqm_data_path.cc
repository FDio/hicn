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

#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/raaqm_data_path.h>

namespace transport {

namespace protocol {

RaaqmDataPath::RaaqmDataPath(double drop_factor,
                             double minimum_drop_probability,
                             unsigned new_timer, unsigned int samples,
                             const utils::SteadyTime::Milliseconds &new_rtt,
                             const utils::SteadyTime::Milliseconds &new_rtt_min,
                             const utils::SteadyTime::Milliseconds &new_rtt_max,
                             unsigned new_pd)

    : drop_factor_(drop_factor),
      minimum_drop_probability_(minimum_drop_probability),
      timer_(new_timer),
      samples_(samples),
      rtt_(new_rtt.count()),
      rtt_min_(new_rtt_min.count()),
      rtt_max_(new_rtt_max.count()),
      prop_delay_(new_pd),
      new_prop_delay_(false),
      drop_prob_(0),
      packets_received_(0),
      last_packets_received_(0),
      m_packets_bytes_received_(0),
      last_packets_bytes_received_(0),
      raw_data_bytes_received_(0),
      last_raw_data_bytes_received_(0),
      rtt_samples_(samples_),
      last_received_pkt_(utils::SteadyTime::Clock::now()),
      average_rtt_(0),
      alpha_(ALPHA) {}

RaaqmDataPath &RaaqmDataPath::insertNewRtt(
    const utils::SteadyTime::Milliseconds &new_rtt,
    const utils::SteadyTime::TimePoint &now) {
  rtt_ = new_rtt.count();
  rtt_samples_.pushBack(rtt_);

  rtt_max_ = rtt_samples_.rBegin();
  rtt_min_ = rtt_samples_.begin();

  if (rtt_min_ < prop_delay_) {
    new_prop_delay_ = true;
    prop_delay_ = rtt_min_;
  }

  last_received_pkt_ = now;

  return *this;
}

RaaqmDataPath &RaaqmDataPath::updateReceivedStats(std::size_t packet_size,
                                                  std::size_t data_size) {
  packets_received_++;
  m_packets_bytes_received_ += packet_size;
  raw_data_bytes_received_ += data_size;

  return *this;
}

double RaaqmDataPath::getDropFactor() { return drop_factor_; }

double RaaqmDataPath::getDropProb() { return drop_prob_; }

RaaqmDataPath &RaaqmDataPath::setDropProb(double dropProb) {
  drop_prob_ = dropProb;

  return *this;
}

double RaaqmDataPath::getMinimumDropProbability() {
  return minimum_drop_probability_;
}

double RaaqmDataPath::getTimer() { return timer_; }

RaaqmDataPath &RaaqmDataPath::smoothTimer() {
  timer_ = (1 - TIMEOUT_SMOOTHER) * timer_ +
           (TIMEOUT_SMOOTHER)*rtt_ * (TIMEOUT_RATIO);

  return *this;
}

double RaaqmDataPath::getRtt() { return (double)rtt_; }

double RaaqmDataPath::getAverageRtt() { return average_rtt_; }

double RaaqmDataPath::getRttMax() { return (double)rtt_max_; }

double RaaqmDataPath::getRttMin() { return (double)rtt_min_; }

unsigned RaaqmDataPath::getSampleValue() { return samples_; }

unsigned RaaqmDataPath::getRttQueueSize() {
  return static_cast<unsigned>(rtt_samples_.size());
}

RaaqmDataPath &RaaqmDataPath::updateDropProb() {
  drop_prob_ = 0.0;

  if (getSampleValue() == getRttQueueSize()) {
    if (rtt_max_ == rtt_min_) {
      drop_prob_ = minimum_drop_probability_;
    } else {
      drop_prob_ = minimum_drop_probability_ +
                   drop_factor_ * (rtt_ - rtt_min_) / (rtt_max_ - rtt_min_);
    }
  }

  return *this;
}

void RaaqmDataPath::setAlpha(double alpha) {
  if (alpha >= 0 && alpha <= 1) {
    alpha_ = alpha;
  }
}

bool RaaqmDataPath::newPropagationDelayAvailable() {
  bool r = new_prop_delay_;
  new_prop_delay_ = false;
  return r;
}

unsigned int RaaqmDataPath::getPropagationDelay() {
  return (unsigned int)prop_delay_;
}

bool RaaqmDataPath::isStale() {
  utils::SteadyTime::TimePoint now = utils::SteadyTime::Clock::now();
  auto time = utils::SteadyTime::getDurationUs(last_received_pkt_, now).count();
  if (time > 2000000) {
    return true;
  }
  return false;
}

}  // end namespace protocol

}  // end namespace transport
