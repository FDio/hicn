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

#include <utils/min_filter.h>

#include <chrono>
#include <climits>
#include <iostream>

#define TIMEOUT_SMOOTHER 0.1
#define TIMEOUT_RATIO 10
#define ALPHA 0.8

namespace transport {

namespace protocol {

class RaaqmDataPath {
 public:
  RaaqmDataPath(double drop_factor, double minimum_drop_probability,
                unsigned new_timer, unsigned int samples,
                uint64_t new_rtt = 1000, uint64_t new_rtt_min = 1000,
                uint64_t new_rtt_max = 1000, unsigned new_pd = UINT_MAX);

 public:
  /*
   * @brief Add a new RTT to the RTT queue of the path, check if RTT queue is
   * full, and thus need overwrite. Also it maintains the validity of min and
   * max of RTT.
   * @param new_rtt is the value of the new RTT
   */
  RaaqmDataPath &insertNewRtt(uint64_t new_rtt);

  /**
   * @brief Update the path statistics
   * @param packet_size the size of the packet received, including the ICN
   * header
   * @param data_size the size of the data received, without the ICN header
   */
  RaaqmDataPath &updateReceivedStats(std::size_t packet_size,
                                     std::size_t data_size);

  /**
   * @brief Get the value of the drop factor parameter
   */
  double getDropFactor();

  /**
   * @brief Get the value of the drop probability
   */
  double getDropProb();

  /**
   * @brief Set the value pf the drop probability
   * @param drop_prob is the value of the drop probability
   */
  RaaqmDataPath &setDropProb(double drop_prob);

  /**
   * @brief Get the minimum drop probability
   */
  double getMinimumDropProbability();

  /**
   * @brief Get last RTT
   */
  double getRtt();

  /**
   * @brief Get average RTT
   */
  double getAverageRtt();

  /**
   * @brief Get the current m_timer value
   */
  double getTimer();

  /**
   * @brief Smooth he value of the m_timer accordingly with the last RTT
   * measured
   */
  RaaqmDataPath &smoothTimer();

  /**
   * @brief Get the maximum RTT among the last samples
   */
  double getRttMax();

  /**
   * @brief Get the minimum RTT among the last samples
   */
  double getRttMin();

  /**
   * @brief Get the number of saved samples
   */
  unsigned getSampleValue();

  /**
   * @brief Get the size og the RTT queue
   */
  unsigned getRttQueueSize();

  /*
   * @brief Change drop probability according to RTT statistics
   *        Invoked in RAAQM(), before control window size update.
   */
  RaaqmDataPath &updateDropProb();

  void setAlpha(double alpha);

  /**
   * @brief Returns the smallest RTT registered so far for this path
   */

  unsigned int getPropagationDelay();

  bool newPropagationDelayAvailable();

  bool isStale();

 private:
  /**
   * The value of the drop factor
   */
  double drop_factor_;

  /**
   * The minumum drop probability
   */
  double minimum_drop_probability_;

  /**
   * The timer, expressed in milliseconds
   */
  double timer_;

  /**
   * The number of samples to store for computing the protocol measurements
   */
  const unsigned int samples_;

  /**
   * The last, the minimum and the maximum value of the RTT (among the last
   * m_samples samples)
   */
  uint64_t rtt_, rtt_min_, rtt_max_, prop_delay_;

  bool new_prop_delay_;

  /**
   * The current drop probability
   */
  double drop_prob_;

  /**
   * The number of packets received in this path
   */
  intmax_t packets_received_;

  /**
   * The first packet received after the statistics print
   */
  intmax_t last_packets_received_;

  /**
   * Total number of bytes received including the ICN header
   */
  intmax_t m_packets_bytes_received_;

  /**
   * The amount of packet bytes received at the last path summary computation
   */
  intmax_t last_packets_bytes_received_;

  /**
   * Total number of bytes received without including the ICN header
   */
  intmax_t raw_data_bytes_received_;

  /**
   * The amount of raw dat bytes received at the last path summary computation
   */
  intmax_t last_raw_data_bytes_received_;

  class byArrival;

  class byOrder;

  /**
   * Double ended queue for the RTTs
   */

  typedef utils::MinFilter<uint64_t> RTTQueue;

  RTTQueue rtt_samples_;

  /**
   * Time of the last call to the path reporter method
   */
  utils::TimePoint last_received_pkt_;

  double average_rtt_;
  double alpha_;
};

}  // end namespace protocol

}  // end namespace transport
