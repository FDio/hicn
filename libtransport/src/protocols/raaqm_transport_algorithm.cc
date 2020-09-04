/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <protocols/raaqm_transport_algorithm.h>

namespace transport {
namespace protocol {

RaaqmTransportAlgorithm::RaaqmTransportAlgorithm(
    interface::TransportStatistics *stats, IcnRateEstimator *rate_estimator,
    double drop_factor, double minimum_drop_probability, double gamma,
    double beta, uint32_t sample_number, uint32_t interest_lifetime,
    double beta_wifi, double drop_wifi, double beta_lte, double drop_lte,
    unsigned int wifi_delay, unsigned int lte_delay, double max_window,
    double min_window)
    : current_window_size_(1),
      cur_path_(nullptr),
      rate_estimator_(rate_estimator),
      stats_(stats),
      drop_factor_(drop_factor),
      minimum_drop_probability_(minimum_drop_probability),
      gamma_(gamma),
      beta_(beta),
      sample_number_(sample_number),
      interest_lifetime_(interest_lifetime),
      beta_wifi_(beta_wifi),
      drop_wifi_(drop_wifi),
      beta_lte_(beta_lte),
      drop_lte_(drop_lte),
      wifi_delay_(wifi_delay),
      lte_delay_(lte_delay),
      max_window_(max_window),
      min_window_(min_window) {}

RaaqmTransportAlgorithm::~RaaqmTransportAlgorithm() {}

void RaaqmTransportAlgorithm::reset() {
  if (rate_estimator_) {
    rate_estimator_->onStart();
  }

  if (!cur_path_) {
    // Current path
    auto cur_path = std::make_unique<RaaqmDataPath>(
        drop_factor_, minimum_drop_probability_, interest_lifetime_ * 1000,
        sample_number_);
    cur_path_ = cur_path.get();
    path_table_[interface::default_values::path_id] = std::move(cur_path);
  }
}

void RaaqmTransportAlgorithm::increaseWindow() {
  if (current_window_size_ < max_window_) {
    current_window_size_ += gamma_ / current_window_size_;
  }

  if (rate_estimator_) {
    rate_estimator_->onWindowIncrease(current_window_size_);
  }
}

void RaaqmTransportAlgorithm::decreaseWindow() {
  if (current_window_size_ > min_window_) {
    current_window_size_ = current_window_size_ * beta_;
    if (current_window_size_ < min_window_) {
      current_window_size_ = min_window_;
    }
  }

  if (rate_estimator_) {
    rate_estimator_->onWindowDecrease(current_window_size_);
  }
}

void RaaqmTransportAlgorithm::updateRtt(uint32_t suffix) {
  if (TRANSPORT_EXPECT_FALSE(!cur_path_)) {
    throw std::runtime_error("RAAQM ERROR: no current path found, exit");
  } else {
    auto now = utils::SteadyClock::now();
    utils::Microseconds rtt = std::chrono::duration_cast<utils::Microseconds>(
        now - interest_timepoints_[suffix & mask]);

    updateStats(suffix, rtt.count(), now);

    if (rate_estimator_) {
      rate_estimator_->onRttUpdate((double)rtt.count());
    }

    cur_path_->insertNewRtt(rtt.count(), now);
    cur_path_->smoothTimer();

    if (cur_path_->newPropagationDelayAvailable()) {
      checkDropProbability();
    }
  }
}

void RaaqmTransportAlgorithm::RAAQM() {
  if (!cur_path_) {
    throw errors::RuntimeException("ERROR: no current path found, exit");
    exit(EXIT_FAILURE);
  } else {
    // Change drop probability according to RTT statistics
    cur_path_->updateDropProb();

    double coin = ((double)rand() / (RAND_MAX));
    if (coin <= cur_path_->getDropProb()) {
      decreaseWindow();
    }
  }
}

void RaaqmTransportAlgorithm::updatePathTable(uint32_t path_label) {
  uint32_t path_id = path_label;

  if (path_table_.find(path_id) == path_table_.end()) {
    if (TRANSPORT_EXPECT_TRUE(cur_path_ != nullptr)) {
      // Create a new path with some default param

      if (TRANSPORT_EXPECT_FALSE(path_table_.empty())) {
        throw errors::RuntimeException(
            "[RAAQM] No path initialized for path table, error could be in "
            "default path initialization.");
      }

      // Initiate the new path default param
      auto new_path = std::make_unique<RaaqmDataPath>(
          *(path_table_.at(interface::default_values::path_id)));

      // Insert the new path into hash table
      path_table_[path_id] = std::move(new_path);
    } else {
      throw errors::RuntimeException(
          "UNEXPECTED ERROR: when running,current path not found.");
    }
  }

  cur_path_ = path_table_[path_id].get();
}

void RaaqmTransportAlgorithm::checkDropProbability() {
  if (!raaqm_autotune_) {
    return;
  }

  unsigned int max_pd = 0;
  PathTable::iterator it;
  for (auto it = path_table_.begin(); it != path_table_.end(); ++it) {
    if (it->second->getPropagationDelay() > max_pd &&
        it->second->getPropagationDelay() != UINT_MAX &&
        !it->second->isStale()) {
      max_pd = it->second->getPropagationDelay();
    }
  }

  double drop_prob = 0;
  double beta = 0;
  if (max_pd < wifi_delay_) {  // only ethernet paths
    drop_prob = drop_factor_;
    beta = beta_;
  } else if (max_pd < lte_delay_) {  // at least one wifi path
    drop_prob = drop_wifi_;
    beta = beta_wifi_;
  } else {  // at least one lte path
    drop_prob = drop_lte_;
    beta = beta_lte_;
  }

  double old_drop_prob = 0;
  double old_beta = 0;
  //   socket_->getSocketOption(RaaqmTransportOptions::BETA_VALUE, old_beta);
  //   socket_->getSocketOption(RaaqmTransportOptions::DROP_FACTOR,
  //   old_drop_prob);

  if (drop_prob == old_drop_prob && beta == old_beta) {
    return;
  }

  //   socket_->setSocketOption(RaaqmTransportOptions::BETA_VALUE, beta);
  //   socket_->setSocketOption(RaaqmTransportOptions::DROP_FACTOR, drop_prob);

  for (it = path_table_.begin(); it != path_table_.end(); it++) {
    it->second->setDropProb(drop_prob);
  }
}

void RaaqmTransportAlgorithm::checkForStalePaths() {
  if (!raaqm_autotune_) {
    return;
  }

  bool stale = false;
  PathTable::iterator it;
  for (it = path_table_.begin(); it != path_table_.end(); ++it) {
    if (it->second->isStale()) {
      stale = true;
      break;
    }
  }
  if (stale) {
    checkDropProbability();
  }
}

void RaaqmTransportAlgorithm::updateStats(uint32_t suffix, uint64_t rtt,
                                          utils::TimePoint &now) {
  // Update RTT statistics
  if (stats_) {
    stats_->updateAverageRtt(rtt);
    stats_->updateAverageWindowSize(current_window_size_);
  }
}

uint32_t RaaqmTransportAlgorithm::onContentObject(uint32_t suffix,
                                                  uint32_t path_label) {
  updatePathTable(path_label);
  increaseWindow();
  updateRtt(suffix);

  // Set drop probablility and window size accordingly
  RAAQM();

  return current_window_size_;
}

uint32_t RaaqmTransportAlgorithm::onInterestTimeout(uint32_t suffix) {
  checkForStalePaths();
  // Decrease the window because the timeout happened
  decreaseWindow();

  return current_window_size_;
}

void RaaqmTransportAlgorithm::onInterestSent(uint32_t suffix) {
  interest_timepoints_[suffix & mask] = utils::SteadyClock::now();
}

void RaaqmTransportAlgorithm::sessionEnd() {
  rate_estimator_->onDownloadFinished();
}

}  // namespace protocol
}  // namespace transport