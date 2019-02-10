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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/raaqm.h>

#include <fstream>

namespace transport {

namespace protocol {

using namespace interface;

RaaqmTransportProtocol::RaaqmTransportProtocol(BaseSocket *icnet_socket)
    : VegasTransportProtocol(icnet_socket), rate_estimator_(NULL) {
  init();
}

RaaqmTransportProtocol::~RaaqmTransportProtocol() {
  if (this->rate_estimator_) {
    delete this->rate_estimator_;
  }
}

void RaaqmTransportProtocol::init() {
  std::ifstream is(RAAQM_CONFIG_PATH);

  std::string line;

  socket_->beta_ = default_values::beta_value;
  socket_->drop_factor_ = default_values::drop_factor;
  socket_->interest_lifetime_ = default_values::interest_lifetime;
  socket_->max_retransmissions_ =
      default_values::transport_protocol_max_retransmissions;
  raaqm_autotune_ = false;
  default_beta_ = default_values::beta_value;
  default_drop_ = default_values::drop_factor;
  beta_wifi_ = default_values::beta_value;
  drop_wifi_ = default_values::drop_factor;
  beta_lte_ = default_values::beta_value;
  drop_lte_ = default_values::drop_factor;
  wifi_delay_ = 1000;
  lte_delay_ = 15000;

  if (!is) {
    TRANSPORT_LOGW("WARNING: RAAQM parameters not found, set default values");
    return;
  }

  while (getline(is, line)) {
    std::string command;
    std::istringstream line_s(line);

    line_s >> command;

    if (command == ";") {
      continue;
    }

    if (command == "autotune") {
      std::string tmp;
      std::string val;
      line_s >> tmp >> val;
      if (val == "yes") {
        raaqm_autotune_ = true;
      } else {
        raaqm_autotune_ = false;
      }
      continue;
    }

    if (command == "lifetime") {
      std::string tmp;
      uint32_t lifetime;
      line_s >> tmp >> lifetime;
      socket_->interest_lifetime_ = lifetime;
      continue;
    }

    if (command == "retransmissions") {
      std::string tmp;
      uint32_t rtx;
      line_s >> tmp >> rtx;
      socket_->max_retransmissions_ = rtx;
      continue;
    }

    if (command == "beta") {
      std::string tmp;
      line_s >> tmp >> default_beta_;
      socket_->beta_ = default_beta_;
      continue;
    }

    if (command == "drop") {
      std::string tmp;
      line_s >> tmp >> default_drop_;
      socket_->drop_factor_ = default_drop_;
      continue;
    }

    if (command == "beta_wifi_") {
      std::string tmp;
      line_s >> tmp >> beta_wifi_;
      continue;
    }

    if (command == "drop_wifi_") {
      std::string tmp;
      line_s >> tmp >> drop_wifi_;
      continue;
    }

    if (command == "beta_lte_") {
      std::string tmp;
      line_s >> tmp >> beta_lte_;
      continue;
    }

    if (command == "drop_lte_") {
      std::string tmp;
      line_s >> tmp >> drop_lte_;
      continue;
    }

    if (command == "wifi_delay_") {
      std::string tmp;
      line_s >> tmp >> wifi_delay_;
      continue;
    }

    if (command == "lte_delay_") {
      std::string tmp;
      line_s >> tmp >> lte_delay_;
      continue;
    }
    if (command == "alpha") {
      std::string tmp;
      double rate_alpha = 0.0;
      line_s >> tmp >> rate_alpha;
      socket_->rate_estimation_alpha_ = rate_alpha;
      continue;
    }

    if (command == "batching_parameter") {
      std::string tmp;
      uint32_t batching_param = 0;
      line_s >> tmp >> batching_param;
      socket_->rate_estimation_batching_parameter_ = batching_param;
      continue;
    }

    if (command == "rate_estimator") {
      std::string tmp;
      uint32_t choice_param = 0;
      line_s >> tmp >> choice_param;
      socket_->rate_estimation_choice_ = choice_param;
      continue;
    }
  }
  is.close();
}

void RaaqmTransportProtocol::start(
    utils::SharableVector<uint8_t> &content_buffer) {
  if (this->rate_estimator_) {
    this->rate_estimator_->onStart();
  }

  if (!cur_path_) {
    double drop_factor;
    double minimum_drop_probability;
    uint32_t sample_number;
    uint32_t interest_lifetime;
    // double beta;

    drop_factor = socket_->drop_factor_;
    minimum_drop_probability = socket_->minimum_drop_probability_;
    sample_number = socket_->sample_number_;
    interest_lifetime = socket_->interest_lifetime_;
    // beta = socket_->beta_;

    double alpha = 0.0;
    uint32_t batching_param = 0;
    uint32_t choice_param = 0;
    alpha = socket_->rate_estimation_alpha_;
    batching_param = socket_->rate_estimation_batching_parameter_;
    choice_param = socket_->rate_estimation_choice_;

    if (choice_param == 1) {
      this->rate_estimator_ = new ALaTcpEstimator();
    } else {
      this->rate_estimator_ = new SimpleEstimator(alpha, batching_param);
    }

    this->rate_estimator_->observer_ = socket_->rate_estimation_observer_;

    cur_path_ = std::make_shared<RaaqmDataPath>(
        drop_factor, minimum_drop_probability, interest_lifetime * 1000,
        sample_number);
    path_table_[default_values::path_id] = cur_path_;
  }

  VegasTransportProtocol::start(content_buffer);
}

void RaaqmTransportProtocol::copyContent(const ContentObject &content_object) {
  if (TRANSPORT_EXPECT_FALSE(
          (content_object.getName().getSuffix() == final_block_number_) ||
          !(is_running_))) {
    this->rate_estimator_->onDownloadFinished();
  }
  VegasTransportProtocol::copyContent(content_object);
}

void RaaqmTransportProtocol::updatePathTable(
    const ContentObject &content_object) {
  uint32_t path_id = content_object.getPathLabel();

  if (path_table_.find(path_id) == path_table_.end()) {
    if (cur_path_) {
      // Create a new path with some default param
      if (path_table_.empty()) {
        throw errors::RuntimeException(
            "No path initialized for path table, error could be in default "
            "path initialization.");
      } else {
        // Initiate the new path default param
        std::shared_ptr<RaaqmDataPath> new_path =
            std::make_shared<RaaqmDataPath>(
                *(path_table_.at(default_values::path_id)));
        // Insert the new path into hash table
        path_table_[path_id] = new_path;
      }
    } else {
      throw errors::RuntimeException(
          "UNEXPECTED ERROR: when running,current path not found.");
    }
  }

  cur_path_ = path_table_[path_id];

  size_t header_size = content_object.headerSize();
  size_t data_size = content_object.payloadSize();

  // Update measurements for path
  cur_path_->updateReceivedStats(header_size + data_size, data_size);
}

void RaaqmTransportProtocol::updateRtt(uint64_t segment) {
  if (TRANSPORT_EXPECT_FALSE(!cur_path_)) {
    throw std::runtime_error("ERROR: no current path found, exit");
  } else {
    std::chrono::microseconds rtt;

    std::chrono::steady_clock::duration duration =
        std::chrono::steady_clock::now() -
        interest_timepoints_[segment & mask_];
    rtt = std::chrono::duration_cast<std::chrono::microseconds>(duration);

    if (this->rate_estimator_) {
      this->rate_estimator_->onRttUpdate((double) rtt.count());
    }
    cur_path_->insertNewRtt(rtt.count());
    cur_path_->smoothTimer();

    if (cur_path_->newPropagationDelayAvailable()) {
      check_drop_probability();
    }
  }
}

void RaaqmTransportProtocol::changeInterestLifetime(uint64_t segment) {
  return;
}

void RaaqmTransportProtocol::check_drop_probability() {
  if (!raaqm_autotune_) {
    return;
  }

  unsigned int max_pd = 0;
  std::unordered_map<uint32_t, std::shared_ptr<RaaqmDataPath>>::iterator it;
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
    drop_prob = default_drop_;
    beta = default_beta_;
  } else if (max_pd < lte_delay_) {  // at least one wifi path
    drop_prob = drop_wifi_;
    beta = beta_wifi_;
  } else {  // at least one lte path
    drop_prob = drop_lte_;
    beta = beta_lte_;
  }

  double old_drop_prob = 0;
  double old_beta = 0;
  old_beta = socket_->beta_;
  old_drop_prob = socket_->drop_factor_;

  if (drop_prob == old_drop_prob && beta == old_beta) {
    return;
  }

  socket_->beta_ = beta;
  socket_->drop_factor_ = drop_prob;

  for (it = path_table_.begin(); it != path_table_.end(); it++) {
    it->second->setDropProb(drop_prob);
  }
}

void RaaqmTransportProtocol::check_for_stale_paths() {
  if (!raaqm_autotune_) {
    return;
  }

  bool stale = false;
  std::unordered_map<uint32_t, std::shared_ptr<RaaqmDataPath>>::iterator it;
  for (it = path_table_.begin(); it != path_table_.end(); ++it) {
    if (it->second->isStale()) {
      stale = true;
      break;
    }
  }
  if (stale) {
    check_drop_probability();
  }
}

void RaaqmTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  check_for_stale_paths();
  VegasTransportProtocol::onTimeout(std::move(interest));
}

void RaaqmTransportProtocol::increaseWindow() {
  double max_window_size = socket_->max_window_size_;
  if (current_window_size_ < max_window_size) {
    double gamma = socket_->gamma_;

    current_window_size_ += gamma / current_window_size_;
    socket_->current_window_size_ = current_window_size_;
  }
  this->rate_estimator_->onWindowIncrease(current_window_size_);
}

void RaaqmTransportProtocol::decreaseWindow() {
  double min_window_size = socket_->min_window_size_;
  if (current_window_size_ > min_window_size) {
    double beta = socket_->beta_;

    current_window_size_ = current_window_size_ * beta;
    if (current_window_size_ < min_window_size) {
      current_window_size_ = min_window_size;
    }

    socket_->current_window_size_ = current_window_size_;
  }
  this->rate_estimator_->onWindowDecrease(current_window_size_);
}

void RaaqmTransportProtocol::RAAQM() {
  if (!cur_path_) {
    throw errors::RuntimeException("ERROR: no current path found, exit");
    exit(EXIT_FAILURE);
  } else {
    // Change drop probability according to RTT statistics
    cur_path_->updateDropProb();

    if (rand() % 10000 <= cur_path_->getDropProb() * 10000) {
      decreaseWindow();
    }
  }
}

void RaaqmTransportProtocol::afterDataUnsatisfied(uint64_t segment) {
  // Decrease the window because the timeout happened
  decreaseWindow();
}

void RaaqmTransportProtocol::afterContentReception(
    const Interest &interest, const ContentObject &content_object) {
  updatePathTable(content_object);
  increaseWindow();
  updateRtt(interest.getName().getSuffix());
  this->rate_estimator_->onDataReceived((int) (content_object.payloadSize() +
                                        content_object.headerSize()));
  // Set drop probablility and window size accordingly
  RAAQM();
}

}  // end namespace protocol

}  // end namespace transport
