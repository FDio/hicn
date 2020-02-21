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

#include <hicn/transport/portability/c_portability.h>

#include <cstdint>

namespace transport {

namespace interface {

class IcnObserver {
 public:
  virtual ~IcnObserver(){};

  virtual void notifyStats(double throughput) = 0;
  virtual void notifyDownloadTime(double downloadTime) = 0;
};

class TransportStatistics {
  static constexpr double default_alpha = 0.7;

 public:
  TransportStatistics(double alpha = default_alpha)
      : retx_count_(0),
        bytes_received_(0),
        average_rtt_(0),
        avg_window_size_(0),
        interest_tx_(0),
        alpha_(alpha),
        loss_ratio_(0.0),
        queuing_delay_(0.0) {}

  TRANSPORT_ALWAYS_INLINE void updateRetxCount(uint64_t retx) {
    retx_count_ += retx;
  }

  TRANSPORT_ALWAYS_INLINE void updateBytesRecv(uint64_t bytes) {
    bytes_received_ += bytes;
  }

  TRANSPORT_ALWAYS_INLINE void updateAverageRtt(uint64_t rtt) {
    average_rtt_ = (alpha_ * average_rtt_) + ((1. - alpha_) * double(rtt));
  }

  TRANSPORT_ALWAYS_INLINE void updateAverageWindowSize(double current_window) {
    avg_window_size_ =
        (alpha_ * avg_window_size_) + ((1. - alpha_) * current_window);
  }

  TRANSPORT_ALWAYS_INLINE void updateInterestTx(uint64_t int_tx) {
    interest_tx_ += int_tx;
  }

  TRANSPORT_ALWAYS_INLINE void updateLossRatio(double loss_ratio) {
    loss_ratio_ = loss_ratio;
  }

  TRANSPORT_ALWAYS_INLINE void updateQueuingDelay(double queuing_delay) {
    queuing_delay_ = queuing_delay;
  }

  TRANSPORT_ALWAYS_INLINE uint64_t getRetxCount() const { return retx_count_; }

  TRANSPORT_ALWAYS_INLINE uint64_t getBytesRecv() const {
    return bytes_received_;
  }

  TRANSPORT_ALWAYS_INLINE double getAverageRtt() const { return average_rtt_; }

  TRANSPORT_ALWAYS_INLINE double getAverageWindowSize() const {
    return avg_window_size_;
  }

  TRANSPORT_ALWAYS_INLINE uint64_t getInterestTx() const {
    return interest_tx_;
  }

  TRANSPORT_ALWAYS_INLINE double getLossRatio() const { return loss_ratio_; }

  TRANSPORT_ALWAYS_INLINE double getQueuingDelay() const {
    return queuing_delay_;
  }

  TRANSPORT_ALWAYS_INLINE void reset() {
    retx_count_ = 0;
    bytes_received_ = 0;
    average_rtt_ = 0;
    avg_window_size_ = 0;
    interest_tx_ = 0;
    loss_ratio_ = 0;
  }

 private:
  uint64_t retx_count_;
  uint64_t bytes_received_;
  double average_rtt_;
  double avg_window_size_;
  uint64_t interest_tx_;
  double alpha_;
  double loss_ratio_;
  double queuing_delay_;
};

}  // namespace interface

}  // end namespace transport
