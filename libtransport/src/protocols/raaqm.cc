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

#include <implementation/socket_consumer.h>
#include <protocols/errors.h>
#include <protocols/indexer.h>
#include <protocols/raaqm.h>

#include <cstdlib>
#include <fstream>

namespace transport {

namespace protocol {

using namespace interface;

RaaqmTransportProtocol::RaaqmTransportProtocol(
    implementation::ConsumerSocket *icn_socket)
    : TransportProtocol(icn_socket, new ByteStreamReassembly(icn_socket, this)),
      current_window_size_(1),
      interests_in_flight_(0),
      cur_path_(nullptr),
      t0_(utils::SteadyClock::now()),
      rate_estimator_(nullptr) {
  init();
}

RaaqmTransportProtocol::~RaaqmTransportProtocol() {
  if (rate_estimator_) {
    delete rate_estimator_;
  }
}

int RaaqmTransportProtocol::start() {
  if (rate_estimator_) {
    rate_estimator_->onStart();
  }

  if (!cur_path_) {
    // RAAQM
    double drop_factor;
    double minimum_drop_probability;
    uint32_t sample_number;
    uint32_t interest_lifetime;

    socket_->getSocketOption(RaaqmTransportOptions::DROP_FACTOR, drop_factor);
    socket_->getSocketOption(RaaqmTransportOptions::MINIMUM_DROP_PROBABILITY,
                             minimum_drop_probability);
    socket_->getSocketOption(RaaqmTransportOptions::SAMPLE_NUMBER,
                             sample_number);
    socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                             interest_lifetime);

    // Rate Estimation
    double alpha = 0.0;
    uint32_t batching_param = 0;
    uint32_t choice_param = 0;
    socket_->getSocketOption(RateEstimationOptions::RATE_ESTIMATION_ALPHA,
                             alpha);
    socket_->getSocketOption(
        RateEstimationOptions::RATE_ESTIMATION_BATCH_PARAMETER, batching_param);
    socket_->getSocketOption(RateEstimationOptions::RATE_ESTIMATION_CHOICE,
                             choice_param);

    if (choice_param == 1) {
      rate_estimator_ = new ALaTcpEstimator();
    } else {
      rate_estimator_ = new SimpleEstimator(alpha, batching_param);
    }

    socket_->getSocketOption(RateEstimationOptions::RATE_ESTIMATION_OBSERVER,
                             &rate_estimator_->observer_);

    // Current path
    auto cur_path = std::make_unique<RaaqmDataPath>(
        drop_factor, minimum_drop_probability, interest_lifetime * 1000,
        sample_number);
    cur_path_ = cur_path.get();
    path_table_[default_values::path_id] = std::move(cur_path);
  }

  portal_->setConsumerCallback(this);
  return TransportProtocol::start();
}

void RaaqmTransportProtocol::resume() { return TransportProtocol::resume(); }

void RaaqmTransportProtocol::reset() {
  // Set first segment to retrieve
  core::Name *name;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME, &name);
  index_manager_->reset();
  index_manager_->setFirstSuffix(name->getSuffix());
  std::queue<Interest::Ptr> empty;
  std::swap(interest_to_retransmit_, empty);
  stats_->reset();

  // Reset reassembly component
  reassembly_protocol_->reInitialize();

  // Reset protocol variables
  interests_in_flight_ = 0;
  t0_ = utils::SteadyClock::now();
}

bool RaaqmTransportProtocol::verifyKeyPackets() {
  return index_manager_->onKeyToVerify();
}

void RaaqmTransportProtocol::increaseWindow() {
  // return;
  double max_window_size = 0.;
  socket_->getSocketOption(GeneralTransportOptions::MAX_WINDOW_SIZE,
                           max_window_size);
  if (current_window_size_ < max_window_size) {
    double gamma = 0.;
    socket_->getSocketOption(RaaqmTransportOptions::GAMMA_VALUE, gamma);

    current_window_size_ += gamma / current_window_size_;
    socket_->setSocketOption(GeneralTransportOptions::CURRENT_WINDOW_SIZE,
                             current_window_size_);
  }
  rate_estimator_->onWindowIncrease(current_window_size_);
}

void RaaqmTransportProtocol::decreaseWindow() {
  // return;
  double min_window_size = 0.;
  socket_->getSocketOption(GeneralTransportOptions::MIN_WINDOW_SIZE,
                           min_window_size);
  if (current_window_size_ > min_window_size) {
    double beta = 0.;
    socket_->getSocketOption(RaaqmTransportOptions::BETA_VALUE, beta);

    current_window_size_ = current_window_size_ * beta;
    if (current_window_size_ < min_window_size) {
      current_window_size_ = min_window_size;
    }

    socket_->setSocketOption(GeneralTransportOptions::CURRENT_WINDOW_SIZE,
                             current_window_size_);
  }
  rate_estimator_->onWindowDecrease(current_window_size_);
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
  rate_estimator_->onDataReceived((int)content_object.payloadSize() +
                                  (int)content_object.headerSize());
  // Set drop probablility and window size accordingly
  RAAQM();
}

void RaaqmTransportProtocol::init() {
  std::ifstream is(RAAQM_CONFIG_PATH);

  std::string line;
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
    TRANSPORT_LOGW(
        "WARNING: RAAQM parameters not found at %s, set default values",
        RAAQM_CONFIG_PATH);
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
      socket_->setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                               lifetime);
      continue;
    }

    if (command == "retransmissions") {
      std::string tmp;
      uint32_t rtx;
      line_s >> tmp >> rtx;
      socket_->setSocketOption(GeneralTransportOptions::MAX_INTEREST_RETX, rtx);
      continue;
    }

    if (command == "beta") {
      std::string tmp;
      line_s >> tmp >> default_beta_;
      socket_->setSocketOption(RaaqmTransportOptions::BETA_VALUE,
                               default_beta_);
      continue;
    }

    if (command == "drop") {
      std::string tmp;
      line_s >> tmp >> default_drop_;
      socket_->setSocketOption(RaaqmTransportOptions::DROP_FACTOR,
                               default_drop_);
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
      socket_->setSocketOption(RateEstimationOptions::RATE_ESTIMATION_ALPHA,
                               rate_alpha);
      continue;
    }

    if (command == "batching_parameter") {
      std::string tmp;
      uint32_t batching_param = 0;
      line_s >> tmp >> batching_param;
      socket_->setSocketOption(
          RateEstimationOptions::RATE_ESTIMATION_BATCH_PARAMETER,
          batching_param);
      continue;
    }

    if (command == "rate_estimator") {
      std::string tmp;
      uint32_t choice_param = 0;
      line_s >> tmp >> choice_param;
      socket_->setSocketOption(RateEstimationOptions::RATE_ESTIMATION_CHOICE,
                               choice_param);
      continue;
    }
  }

  is.close();
}

void RaaqmTransportProtocol::onContentObject(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  // Check whether makes sense to continue
  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  // Call application-defined callbacks
  if (*on_content_object_input_) {
    (*on_content_object_input_)(*socket_->getInterface(), *content_object);
  }

  if (*on_interest_satisfied_) {
    (*on_interest_satisfied_)(*socket_->getInterface(), *interest);
  }

  if (content_object->getPayloadType() == PayloadType::CONTENT_OBJECT) {
    stats_->updateBytesRecv(content_object->payloadSize());
  }

  onContentSegment(std::move(interest), std::move(content_object));
  scheduleNextInterests();
}

void RaaqmTransportProtocol::onContentSegment(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  uint32_t incremental_suffix = content_object->getName().getSuffix();

  // Decrease in-flight interests
  interests_in_flight_--;

  // Update stats
  if (!interest_retransmissions_[incremental_suffix & mask]) {
    afterContentReception(*interest, *content_object);
  }

  index_manager_->onContentObject(std::move(interest),
                                  std::move(content_object));
}

void RaaqmTransportProtocol::onPacketDropped(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  uint32_t max_rtx = 0;
  socket_->getSocketOption(GeneralTransportOptions::MAX_INTEREST_RETX, max_rtx);

  uint64_t segment = interest->getName().getSuffix();

  if (TRANSPORT_EXPECT_TRUE(interest_retransmissions_[segment & mask] <
                            max_rtx)) {
    stats_->updateRetxCount(1);

    if (*on_interest_retransmission_) {
      (*on_interest_retransmission_)(*socket_->getInterface(), *interest);
    }

    if (*on_interest_output_) {
      (*on_interest_output_)(*socket_->getInterface(), *interest);
    }

    if (!is_running_) {
      return;
    }

    interest_retransmissions_[segment & mask]++;
    interest_to_retransmit_.push(std::move(interest));
  } else {
    TRANSPORT_LOGE(
        "Stop: received not trusted packet %llu times",
        (unsigned long long)interest_retransmissions_[segment & mask]);
    onContentReassembled(
        make_error_code(protocol_error::max_retransmissions_error));
  }
}

void RaaqmTransportProtocol::onReassemblyFailed(std::uint32_t missing_segment) {

}

void RaaqmTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  checkForStalePaths();

  const Name &n = interest->getName();

  TRANSPORT_LOGW("Timeout on content %s", n.toString().c_str());

  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  interests_in_flight_--;

  uint64_t segment = n.getSuffix();

  // Do not retransmit interests asking contents that do not exist.
  if (segment > index_manager_->getFinalSuffix()) {
    return;
  }

  if (*on_interest_timeout_) {
    (*on_interest_timeout_)(*socket_->getInterface(), *interest);
  }

  afterDataUnsatisfied(segment);

  uint32_t max_rtx = 0;
  socket_->getSocketOption(GeneralTransportOptions::MAX_INTEREST_RETX, max_rtx);

  if (TRANSPORT_EXPECT_TRUE(interest_retransmissions_[segment & mask] <
                            max_rtx)) {
    stats_->updateRetxCount(1);

    if (*on_interest_retransmission_) {
      (*on_interest_retransmission_)(*socket_->getInterface(), *interest);
    }

    if (*on_interest_output_) {
      (*on_interest_output_)(*socket_->getInterface(), *interest);
    }

    if (!is_running_) {
      return;
    }

    interest_retransmissions_[segment & mask]++;
    interest_to_retransmit_.push(std::move(interest));

    scheduleNextInterests();
  } else {
    TRANSPORT_LOGE("Stop: reached max retx limit.");
    onContentReassembled(std::make_error_code(std::errc(std::errc::io_error)));
  }
}

void RaaqmTransportProtocol::scheduleNextInterests() {
  if (TRANSPORT_EXPECT_FALSE(!is_running_ && !is_first_)) {
    return;
  }

  if (TRANSPORT_EXPECT_FALSE(interests_in_flight_ >= current_window_size_ &&
                             interest_to_retransmit_.size() > 0)) {
    // send at least one interest if there are retransmissions to perform and
    // there is no space left in the window
    sendInterest(std::move(interest_to_retransmit_.front()));
    TRANSPORT_LOGD("Window full, retransmit one content interest");
    interest_to_retransmit_.pop();
  }

  uint32_t index = IndexManager::invalid_index;

  // Send the interest needed for filling the window
  while (interests_in_flight_ < current_window_size_) {
    if (interest_to_retransmit_.size() > 0) {
      sendInterest(std::move(interest_to_retransmit_.front()));
      TRANSPORT_LOGD("Retransmit content interest");
      interest_to_retransmit_.pop();
    } else {
      index = index_manager_->getNextSuffix();
      if (index == IndexManager::invalid_index) {
        break;
      }

      sendInterest(index);
    }
  }
}

bool RaaqmTransportProtocol::sendInterest(std::uint64_t next_suffix) {
  auto interest = getPacket();
  core::Name *name;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME, &name);
  name->setSuffix((uint32_t)next_suffix);
  interest->setName(*name);

  uint32_t interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           interest_lifetime);
  interest->setLifetime(interest_lifetime);

  if (*on_interest_output_) {
    on_interest_output_->operator()(*socket_->getInterface(), *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_ && !is_first_)) {
    return false;
  }

  // This is set to ~0 so that the next interest_retransmissions_ + 1,
  // performed by sendInterest, will result in 0
  interest_retransmissions_[next_suffix & mask] = ~0;
  interest_timepoints_[next_suffix & mask] = utils::SteadyClock::now();

  TRANSPORT_LOGD("Send content interest %s", name->toString().c_str());
  sendInterest(std::move(interest));

  return true;
}

void RaaqmTransportProtocol::sendInterest(Interest::Ptr &&interest) {
  interests_in_flight_++;
  interest_retransmissions_[interest->getName().getSuffix() & mask]++;

  portal_->sendInterest(std::move(interest));
}

void RaaqmTransportProtocol::onContentReassembled(std::error_code ec) {
  rate_estimator_->onDownloadFinished();
  TransportProtocol::onContentReassembled(ec);
}

void RaaqmTransportProtocol::updateRtt(uint64_t segment) {
  if (TRANSPORT_EXPECT_FALSE(!cur_path_)) {
    throw std::runtime_error("RAAQM ERROR: no current path found, exit");
  } else {
    auto now = utils::SteadyClock::now();
    utils::Microseconds rtt = std::chrono::duration_cast<utils::Microseconds>(
        now - interest_timepoints_[segment & mask]);

    // Update stats
    updateStats((uint32_t)segment, rtt.count(), now);

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

void RaaqmTransportProtocol::RAAQM() {
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

void RaaqmTransportProtocol::updateStats(uint32_t suffix, uint64_t rtt,
                                         utils::TimePoint &now) {
  // Update RTT statistics
  stats_->updateAverageRtt(rtt);
  stats_->updateAverageWindowSize(current_window_size_);

  // Call statistics callback
  if (*stats_summary_) {
    auto dt = std::chrono::duration_cast<utils::Milliseconds>(now - t0_);

    uint32_t timer_interval_milliseconds = 0;
    socket_->getSocketOption(GeneralTransportOptions::STATS_INTERVAL,
                             timer_interval_milliseconds);
    if (dt.count() > timer_interval_milliseconds) {
      (*stats_summary_)(*socket_->getInterface(), *stats_);
      t0_ = now;
    }
  }
}

void RaaqmTransportProtocol::updatePathTable(
    const ContentObject &content_object) {
  uint32_t path_id = content_object.getPathLabel();

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
          *(path_table_.at(default_values::path_id)));

      // Insert the new path into hash table
      path_table_[path_id] = std::move(new_path);
    } else {
      throw errors::RuntimeException(
          "UNEXPECTED ERROR: when running,current path not found.");
    }
  }

  cur_path_ = path_table_[path_id].get();

  size_t header_size = content_object.headerSize();
  size_t data_size = content_object.payloadSize();

  // Update measurements for path
  cur_path_->updateReceivedStats(header_size + data_size, data_size);
}

void RaaqmTransportProtocol::checkDropProbability() {
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
  socket_->getSocketOption(RaaqmTransportOptions::BETA_VALUE, old_beta);
  socket_->getSocketOption(RaaqmTransportOptions::DROP_FACTOR, old_drop_prob);

  if (drop_prob == old_drop_prob && beta == old_beta) {
    return;
  }

  socket_->setSocketOption(RaaqmTransportOptions::BETA_VALUE, beta);
  socket_->setSocketOption(RaaqmTransportOptions::DROP_FACTOR, drop_prob);

  for (it = path_table_.begin(); it != path_table_.end(); it++) {
    it->second->setDropProb(drop_prob);
  }
}

void RaaqmTransportProtocol::checkForStalePaths() {
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

}  // end namespace protocol

}  // namespace transport
