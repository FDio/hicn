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
#include <protocols/rtc/rtc_recovery_strategy.h>

namespace transport {

namespace protocol {

namespace rtc {

class RecoveryStrategyFecOnly : public RecoveryStrategy {
 public:
  RecoveryStrategyFecOnly(Indexer *indexer, SendRtxCallback &&callback,
                          asio::io_service &io_service,
                          interface::StrategyCallback *external_callback);

  RecoveryStrategyFecOnly(RecoveryStrategy &&rs);

  ~RecoveryStrategyFecOnly();

  void onNewRound(bool in_sync);
  void newPacketLoss(uint32_t seq);
  void receivedPacket(uint32_t seq);

 private:
  bool congestion_state_;
  bool probing_state_;
  uint32_t switch_rounds_;

  void probing();
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
