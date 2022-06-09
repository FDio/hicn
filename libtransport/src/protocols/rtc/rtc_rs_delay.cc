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
#include <protocols/rtc/rtc_rs_delay.h>

namespace transport {

namespace protocol {

namespace rtc {

RecoveryStrategyDelayBased::RecoveryStrategyDelayBased(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    interface::RtcTransportRecoveryStrategies rs_type,
    interface::StrategyCallback &&external_callback)
    : RecoveryStrategy(indexer, std::move(callback), io_service, true, false,
                       rs_type,
                       std::move(external_callback)),  // start with rtx
      congestion_state_(false),
      probing_state_(false),
      switch_rounds_(0) {}

RecoveryStrategyDelayBased::RecoveryStrategyDelayBased(RecoveryStrategy &&rs)
    : RecoveryStrategy(std::move(rs)) {
  setRtxFec(true, false);
  // we have to re-init congestion and
  // probing
  switch_rounds_ = 0;
  congestion_state_ = false;
  probing_state_ = false;
}

RecoveryStrategyDelayBased::~RecoveryStrategyDelayBased() {}

void RecoveryStrategyDelayBased::turnOnRecovery() {
  recovery_on_ = true;
  uint64_t rtt = state_->getMinRTT();
  uint32_t fec_to_ask = computeFecPacketsToAsk();
  if (rtt > MAX_RTT_BEFORE_FEC && fec_to_ask > 0) {
    // we need to start FEC (see fec only strategy for more details)
    setRtxFec(true, true);
    rtx_during_fec_ = 1;  // avoid to stop fec
    indexer_->setNFec(fec_to_ask);
  } else {
    // use RTX
    setRtxFec(true, false);
    switch_rounds_ = 0;
  }
}

void RecoveryStrategyDelayBased::softSwitchToFec(uint32_t fec_to_ask) {
  if (fec_to_ask == 0) {
    setRtxFec(true, false);
    switch_rounds_ = 0;
  } else {
    switch_rounds_++;
    if (switch_rounds_ >= ((RTC_INTEREST_LIFETIME / ROUND_LEN) * 2) &&
        rtx_during_fec_ != 0) {  // go to fec only if it is needed (RTX are on)
      setRtxFec(false, true);
    } else {
      setRtxFec(true, true);
    }
  }
}

void RecoveryStrategyDelayBased::onNewRound(bool in_sync) {
  if (!recovery_on_) {
    // disable fec so that no extra packet will be sent
    // for rtx we check if recovery is on in newPacketLoss
    setRtxFec(true, false);
    indexer_->setNFec(0);
    return;
  }

  uint64_t rtt = state_->getAvgRTT();

  // XXX at the moment we are not looking at congestion events
  // bool congestion = rc_->inCongestionState();

  if ((!fec_on_ && rtt >= MAX_RTT_BEFORE_FEC) ||
      (fec_on_ && rtt > (MAX_RTT_BEFORE_FEC - 10))) {
    // switch from rtx to fec or keep use fec. Notice that if some rtx are
    // waiting to be scheduled, they will be sent normally, but no new rtx will
    // be created if the loss rate is 0 keep to use RTX.
    uint32_t fec_to_ask = computeFecPacketsToAsk();
    softSwitchToFec(fec_to_ask);
    if (rtx_during_fec_ == 0)  // if we do not send any RTX the losses
                               // registered may be due to jitter
      indexer_->setNFec(0);
    else
      indexer_->setNFec(fec_to_ask);
    return;
  }

  if ((fec_on_ && rtt <= (MAX_RTT_BEFORE_FEC - 10)) ||
      (!rtx_on_ && rtt <= MAX_RTT_BEFORE_FEC)) {
    // turn on rtx
    softSwitchToFec(0);
    indexer_->setNFec(0);
    return;
  }
}

void RecoveryStrategyDelayBased::newPacketLoss(uint32_t seq) {
  if (rtx_on_ && recovery_on_) {
    addNewRtx(seq, false);
  } else {
    if (!state_->isPending(seq) && !indexer_->isFec(seq)) {
      addNewRtx(seq, true);
    } else {
      recover_with_fec_.insert(seq);
      state_->onPossibleLossWithNoRtx(seq);
    }
  }
}

void RecoveryStrategyDelayBased::receivedPacket(uint32_t seq) {
  removePacketState(seq);
}

void RecoveryStrategyDelayBased::probing() {
  // TODO
  // for the moment ask for all fec and exit the probing phase
  probing_state_ = false;
  setRtxFec(false, true);
  indexer_->setNFec(computeFecPacketsToAsk());
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
