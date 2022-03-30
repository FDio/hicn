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
#include <protocols/rtc/rtc_rs_recovery_off.h>

namespace transport {

namespace protocol {

namespace rtc {

RecoveryStrategyRecoveryOff::RecoveryStrategyRecoveryOff(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    interface::StrategyCallback *external_callback)
    : RecoveryStrategy(indexer, std::move(callback), io_service, false, false,
                       external_callback) {}

RecoveryStrategyRecoveryOff::RecoveryStrategyRecoveryOff(RecoveryStrategy &&rs)
    : RecoveryStrategy(std::move(rs)) {
  setRtxFec(false, false);
}

RecoveryStrategyRecoveryOff::~RecoveryStrategyRecoveryOff() {}

void RecoveryStrategyRecoveryOff::onNewRound(bool in_sync) {
  // nothing to do
  return;
}

void RecoveryStrategyRecoveryOff::newPacketLoss(uint32_t seq) {
  // here we only keep track of the lost packets to avoid to
  // count them multple times in the counters. for this we
  // use the recover_with_fec_ set
  recover_with_fec_.insert(seq);
  state_->onPossibleLossWithNoRtx(seq);
}

void RecoveryStrategyRecoveryOff::receivedPacket(uint32_t seq) {
  removePacketState(seq);
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
