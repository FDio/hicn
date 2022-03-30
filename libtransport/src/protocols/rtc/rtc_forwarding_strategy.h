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

#pragma once

#include <core/portal.h>
#include <hicn/transport/interfaces/callbacks.h>
#include <protocols/rtc/rtc_state.h>

#include <array>

namespace transport {

namespace protocol {

namespace rtc {

class RTCForwardingStrategy {
 public:
  enum strategy_t {
    BEST_PATH,
    REPLICATION,
    BOTH,
    NONE,
  };

  RTCForwardingStrategy();
  ~RTCForwardingStrategy();

  void initFwdStrategy(std::shared_ptr<core::Portal> portal,
                       core::Prefix& prefix, RTCState* state,
                       strategy_t strategy);

  void checkStrategy();
  void setCallback(interface::StrategyCallback* callback);

 private:
  void checkStrategyBestPath();
  void checkStrategyReplication();
  void checkStrategyBoth();

  void setStrategy(strategy_t strategy);

  std::array<std::string, 4> string_strategies_ = {"bestpath", "replication",
                                                   "both", "none"};

  bool init_;                     // true if all val are initializes
  bool forwarder_set_;            // true if the strategy is been set at least
                                  // once
  strategy_t selected_strategy_;  // this is the strategy selected using socket
                                  // options. this can also be equal to BOTH
  strategy_t current_strategy_;   // if both strategies can be used this
                                  // indicates the one that is currently in use
                                  // that can be only replication or best path
  uint32_t rounds_since_last_set_;
  core::Prefix prefix_;
  std::shared_ptr<core::Portal> portal_;
  RTCState* state_;
  interface::StrategyCallback* callback_;
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
