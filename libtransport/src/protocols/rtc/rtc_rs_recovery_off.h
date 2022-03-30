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

class RecoveryStrategyRecoveryOff : public RecoveryStrategy {
 public:
  RecoveryStrategyRecoveryOff(Indexer *indexer, SendRtxCallback &&callback,
                              asio::io_service &io_service,
                              interface::StrategyCallback *external_callback);

  RecoveryStrategyRecoveryOff(RecoveryStrategy &&rs);

  ~RecoveryStrategyRecoveryOff();

  void onNewRound(bool in_sync);
  void newPacketLoss(uint32_t seq);
  void receivedPacket(uint32_t seq);
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
