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

#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_rc_iat.h>

namespace transport {

namespace protocol {

namespace rtc {

RTCRateControlIAT::RTCRateControlIAT()
    : rounds_since_last_drop_(0),
      rounds_without_congestion_(0),
      rounds_with_congestion_(0),
      last_queue_(0),
      last_rcv_time_(0),
      last_prod_time_(0),
      last_seq_number_(0),
      target_rate_avg_(0),
      round_index_(0),
      congestion_cause_(CongestionCause::UNKNOWN) {}

RTCRateControlIAT::~RTCRateControlIAT() {}

void RTCRateControlIAT::onNewRound(double round_len) {
  if (!rc_on_) return;

  double received_rate = protocol_state_->getReceivedRate() +
                         protocol_state_->getRecoveredFecRate();

  double target_rate =
      protocol_state_->getProducerRate();  // * PRODUCTION_RATE_FRACTION;
  double rtt = (double)protocol_state_->getMinRTT() / MILLI_IN_A_SEC;
  // double packet_size = protocol_state_->getAveragePacketSize();
  double queue = protocol_state_->getQueuing();

  if (rtt == 0.0) return;  // no info from the producer

  CongestionState prev_congestion_state = congestion_state_;

  target_rate_avg_ = target_rate_avg_ * (1 - MOVING_AVG_ALPHA) +
                     target_rate * MOVING_AVG_ALPHA;

  if (prev_congestion_state == CongestionState::Congested) {
    if (queue > MAX_QUEUING_DELAY || last_queue_ == queue) {
      congestion_state_ = CongestionState::Congested;

      received_rate_.push_back(received_rate);
      target_rate_.push_back(target_rate);

      // We assume the cause does not change
      // Note that the first assumption about the cause could be wrong
      // the cause of congestion could change
      if (congestion_cause_ == CongestionCause::UNKNOWN)
        if (rounds_with_congestion_ >= 1)
          congestion_cause_ = apply_classification_tree(
              rounds_with_congestion_ > ROUND_TO_WAIT_FORCE_DECISION);

      rounds_with_congestion_++;
    } else {
      congestion_state_ = CongestionState::Normal;

      // clear past history
      reset_congestion_statistics();

      // TODO maybe we can use some of these values for the stdev of the
      // congestion mode
      for (int i = 0; i < ROUND_HISTORY_SIZE; i++) {
        iat_on_hold_[i].clear();
      }
    }
  } else if (queue > MAX_QUEUING_DELAY) {
    if (prev_congestion_state == CongestionState::Normal) {
      rounds_with_congestion_ = 0;

      if (rounds_without_congestion_ > ROUND_TO_RESET_CAUSE)
        congestion_cause_ = CongestionCause::UNKNOWN;
    }
    congestion_state_ = CongestionState::Congested;
    received_rate_.push_back(received_rate);
    target_rate_.push_back(target_rate);
  } else {
    // nothing bad is happening
    congestion_state_ = CongestionState::Normal;
    reset_congestion_statistics();

    int past_index = (round_index_ + 1) % ROUND_HISTORY_SIZE;
    for (std::vector<double>::iterator it = iat_on_hold_[past_index].begin();
         it != iat_on_hold_[past_index].end(); ++it) {
      congestion_free_iat_.push_back(*it);
      if (congestion_free_iat_.size() > 50) {
        congestion_free_iat_.erase(congestion_free_iat_.begin());
      }
    }
    iat_on_hold_[past_index].clear();
    round_index_ = (round_index_ + 1) % ROUND_HISTORY_SIZE;
  }

  last_queue_ = queue;

  if (congestion_state_ == CongestionState::Congested) {
    if (prev_congestion_state == CongestionState::Normal) {
      // init the congetion window using the received rate
      // disabling for the moment the congestion window setup
      // congestion_win_ = (uint32_t)ceil(received_rate * rtt / packet_size);
      rounds_since_last_drop_ = ROUNDS_BEFORE_TAKE_ACTION + 1;
    }

    if (rounds_since_last_drop_ >= ROUNDS_BEFORE_TAKE_ACTION) {
      // disabling for the moment the congestion window setup
      // uint32_t win = congestion_win_ * WIN_DECREASE_FACTOR;
      // congestion_win_ = std::max(win, WIN_MIN);
      rounds_since_last_drop_ = 0;
      return;
    }

    rounds_since_last_drop_++;
  }

  if (congestion_state_ == CongestionState::Normal) {
    if (prev_congestion_state == CongestionState::Congested) {
      rounds_without_congestion_ = 0;
    }

    rounds_without_congestion_++;
    if (rounds_without_congestion_ < ROUNDS_BEFORE_TAKE_ACTION) return;

    // disabling for the moment the congestion window setup
    // congestion_win_ = congestion_win_ * WIN_INCREASE_FACTOR;
    // congestion_win_ = std::min(congestion_win_, INITIAL_WIN_MAX);
  }

  if (received_rate_.size() > 1000)
    received_rate_.erase(received_rate_.begin());
  if (target_rate_.size() > 1000) target_rate_.erase(target_rate_.begin());
}

void RTCRateControlIAT::onDataPacketReceived(
    const core::ContentObject &content_object, bool compute_stats) {
  core::ParamsRTC params = RTCState::getDataParams(content_object);

  uint64_t now = utils::SteadyTime::nowMs().count();

  uint32_t segment_number = content_object.getName().getSuffix();

  if (segment_number == (last_seq_number_ + 1) && compute_stats) {
    uint64_t iat = now - last_rcv_time_;
    uint64_t ist = params.timestamp - last_prod_time_;
    if (now >= last_rcv_time_ && params.timestamp > last_prod_time_) {
      if (iat >= ist && ist < MIN_IST_VALUE) {
        if (congestion_state_ == CongestionState::Congested) {
          iat_.push_back((iat - ist));
        } else {
          // no congestion, but we do not always add new values, but only when
          // there is no sign of congestion
          double queue = protocol_state_->getQueuing();
          if (queue <= CONGESTION_FREE_QUEUEING_DELAY) {
            iat_on_hold_[round_index_].push_back((iat - ist));
          }
        }
      }
    }
  }

  last_seq_number_ = segment_number;
  last_rcv_time_ = now;
  last_prod_time_ = params.timestamp;

  if (iat_.size() > 1000) iat_.erase(iat_.begin());
  return;
}

CongestionCause RTCRateControlIAT::apply_classification_tree(bool force_reply) {
  if (iat_.size() <= 2 || received_rate_.size() < 2)
    return CongestionCause::UNKNOWN;

  double received_ratio = 0;
  double iat_ratio = 0;
  double iat_stdev = compute_iat_stdev(iat_);
  double iat_congestion_free_stdev = compute_iat_stdev(congestion_free_iat_);

  double iat_avg = 0.0;

  double recv_avg = 0.0;
  double recv_max = 0.0;

  double target_rate_avg = 0.0;

  int counter = 0;
  std::vector<double>::reverse_iterator target_it = target_rate_.rbegin();
  for (std::vector<double>::reverse_iterator it = received_rate_.rbegin();
       it != received_rate_.rend(); ++it) {
    recv_avg += *it;
    target_rate_avg += *target_it;
    if (counter < ROUND_HISTORY_SIZE)
      if (recv_max < *it) {
        recv_max = *it;  // we consider only the last 2 seconds
      }
    counter++;
    target_it++;
  }
  recv_avg = recv_avg / received_rate_.size();
  target_rate_avg = target_rate_avg / target_rate_.size();

  for (std::vector<double>::iterator it = iat_.begin(); it != iat_.end();
       ++it) {
    iat_avg += *it;
  }
  iat_avg = iat_avg / iat_.size();

  double congestion_free_iat_avg = 0.0;
  for (std::vector<double>::iterator it = congestion_free_iat_.begin();
       it != congestion_free_iat_.end(); ++it) {
    congestion_free_iat_avg += *it;
  }
  congestion_free_iat_avg =
      congestion_free_iat_avg / congestion_free_iat_.size();

  received_ratio = recv_avg / target_rate_avg;

  iat_ratio = iat_stdev / iat_congestion_free_stdev;

  CongestionCause congestion_cause = CongestionCause::UNKNOWN;
  // applying classification tree model
  if (received_ratio <= 0.87)
    if (iat_stdev <= 6.48)
      if (received_ratio <= 0.83)
        congestion_cause = CongestionCause::LINK_CAPACITY;
      else if (force_reply)
        congestion_cause = CongestionCause::LINK_CAPACITY;
      else
        congestion_cause = CongestionCause::UNKNOWN;  // accuracy is too low
    else if (iat_ratio <= 2.46)
      if (force_reply)
        congestion_cause = CongestionCause::LINK_CAPACITY;
      else
        congestion_cause = CongestionCause::UNKNOWN;  // accuracy is too low
    else
      congestion_cause = CongestionCause::COMPETING_CROSS_TRAFFIC;
  else if (received_ratio <= 0.913 && iat_stdev <= 0.784)
    congestion_cause = CongestionCause::LINK_CAPACITY;
  else
    congestion_cause = CongestionCause::COMPETING_CROSS_TRAFFIC;

  return congestion_cause;
}

void RTCRateControlIAT::reset_congestion_statistics() {
  iat_.clear();
  received_rate_.clear();
  target_rate_.clear();
}

double RTCRateControlIAT::compute_iat_stdev(std::vector<double> v) {
  if (v.size() == 0) return 0;

  float sum = 0.0, mean, standard_deviation = 0.0;
  for (std::vector<double>::iterator it = v.begin(); it != v.end(); it++) {
    sum += *it;
  }

  mean = sum / v.size();
  for (std::vector<double>::iterator it = v.begin(); it != v.end(); it++) {
    standard_deviation += pow(*it - mean, 2);
  }
  return sqrt(standard_deviation / v.size());
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
