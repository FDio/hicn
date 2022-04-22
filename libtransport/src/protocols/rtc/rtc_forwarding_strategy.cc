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

#include <hicn/transport/interfaces/notification.h>
#include <protocols/rtc/rtc_forwarding_strategy.h>

namespace transport {

namespace protocol {

namespace rtc {

using namespace transport::interface;

RTCForwardingStrategy::RTCForwardingStrategy()
    : init_(false),
      forwarder_set_(false),
      selected_strategy_(NONE),
      current_strategy_(NONE),
      rounds_since_last_set_(0),
      portal_(nullptr),
      state_(nullptr) {}

RTCForwardingStrategy::~RTCForwardingStrategy() {}

void RTCForwardingStrategy::setCallback(
    interface::StrategyCallback&& callback) {
  callback_ = std::move(callback);
}

void RTCForwardingStrategy::initFwdStrategy(
    std::shared_ptr<core::Portal> portal, core::Prefix& prefix, RTCState* state,
    strategy_t strategy) {
  init_ = true;
  selected_strategy_ = strategy;
  if (strategy == BOTH)
    current_strategy_ = BEST_PATH;
  else
    current_strategy_ = strategy;
  rounds_since_last_set_ = 0;
  prefix_ = prefix;
  portal_ = portal;
  state_ = state;
}

void RTCForwardingStrategy::checkStrategy() {
  strategy_t used_strategy = selected_strategy_;
  if (used_strategy == BOTH) used_strategy = current_strategy_;
  assert(used_strategy == BEST_PATH || used_strategy == REPLICATION ||
         used_strategy == NONE);

  notification::ForwardingStrategy strategy =
      notification::ForwardingStrategy::NONE;
  switch (used_strategy) {
    case BEST_PATH:
      strategy = notification::ForwardingStrategy::BEST_PATH;
      break;
    case REPLICATION:
      strategy = notification::ForwardingStrategy::REPLICATION;
      break;
    default:
      break;
  }
  callback_(strategy);

  if (!init_) return;

  if (selected_strategy_ == NONE) return;

  if (selected_strategy_ == BEST_PATH) {
    checkStrategyBestPath();
    return;
  }

  if (selected_strategy_ == REPLICATION) {
    checkStrategyReplication();
    return;
  }

  checkStrategyBoth();
}

void RTCForwardingStrategy::checkStrategyBestPath() {
  if (!forwarder_set_) {
    setStrategy(BEST_PATH);
    forwarder_set_ = true;
    return;
  }

  uint8_t qs = state_->getQualityScore();

  if (qs >= 4 || rounds_since_last_set_ < 25) {  // wait a least 5 sec
                                                 // between each switch
    rounds_since_last_set_++;
    return;
  }

  // try to switch path
  setStrategy(BEST_PATH);
}

void RTCForwardingStrategy::checkStrategyReplication() {
  if (!forwarder_set_) {
    setStrategy(REPLICATION);
    forwarder_set_ = true;
    return;
  }

  // here we have nothing to do for the moment
  return;
}

void RTCForwardingStrategy::checkStrategyBoth() {
  if (!forwarder_set_) {
    setStrategy(current_strategy_);
    forwarder_set_ = true;
    return;
  }

  checkStrategyBestPath();

  // TODO
  // for the moment we use only best path.
  // but later:
  // 1. if both paths are bad use replication
  // 2. while using replication compute the effectiveness. if the majority of
  //    the packets are coming from a single path, try to use bestpath
}

void RTCForwardingStrategy::setStrategy(strategy_t strategy) {
  rounds_since_last_set_ = 0;
  current_strategy_ = strategy;
  portal_->setForwardingStrategy(prefix_,
                                 string_strategies_[current_strategy_]);
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
