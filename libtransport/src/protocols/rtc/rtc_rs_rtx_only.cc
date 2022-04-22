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

#include <glog/logging.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_rs_rtx_only.h>

namespace transport {

namespace protocol {

namespace rtc {

RecoveryStrategyRtxOnly::RecoveryStrategyRtxOnly(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    interface::StrategyCallback &&external_callback)
    : RecoveryStrategy(indexer, std::move(callback), io_service, true, false,
                       std::move(external_callback)) {}

RecoveryStrategyRtxOnly::RecoveryStrategyRtxOnly(RecoveryStrategy &&rs)
    : RecoveryStrategy(std::move(rs)) {
  setRtxFec(true, false);
}

RecoveryStrategyRtxOnly::~RecoveryStrategyRtxOnly() {}

void RecoveryStrategyRtxOnly::turnOnRecovery() {
  recovery_on_ = true;
  setRtxFec(true, false);
}

void RecoveryStrategyRtxOnly::onNewRound(bool in_sync) {
  // nothing to do
  return;
}

void RecoveryStrategyRtxOnly::newPacketLoss(uint32_t seq) {
  if (!recovery_on_) {
    recover_with_fec_.insert(seq);
    state_->onPossibleLossWithNoRtx(seq);
    return;
  }
  addNewRtx(seq, false);
}

void RecoveryStrategyRtxOnly::receivedPacket(uint32_t seq) {
  removePacketState(seq);
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
