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
#include <protocols/rtc/rtc_rs_fec_only.h>

namespace transport {

namespace protocol {

namespace rtc {

RecoveryStrategyFecOnly::RecoveryStrategyFecOnly(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    interface::RtcTransportRecoveryStrategies rs_type,
    interface::StrategyCallback &&external_callback)
    : RecoveryStrategy(indexer, std::move(callback), io_service, true, false,
                       rs_type, std::move(external_callback)),
      congestion_state_(false),
      probing_state_(false),
      switch_rounds_(0) {}

RecoveryStrategyFecOnly::RecoveryStrategyFecOnly(RecoveryStrategy &&rs)
    : RecoveryStrategy(std::move(rs)) {
  setRtxFec(true, false);
  switch_rounds_ = 0;
  congestion_state_ = false;
  probing_state_ = false;
}

RecoveryStrategyFecOnly::~RecoveryStrategyFecOnly() {}

void RecoveryStrategyFecOnly::turnOnRecovery() {
  recovery_on_ = true;
  // init strategy
  uint32_t fec_to_ask = computeFecPacketsToAsk();
  if (fec_to_ask > 0) {
    // the probing phase detected a lossy link. we immedialty start the fec and
    // we disable the check to prevent to send fec packets before RTX. in fact
    // here we know that we have losses and it is not a problem of OOO packets
    setRtxFec(true, true);
    rtx_during_fec_ = 1;  // avoid to stop fec
    indexer_->setNFec(fec_to_ask);
  } else {
    // keep only RTX on
    setRtxFec(true, true);
  }
}

void RecoveryStrategyFecOnly::onNewRound(bool in_sync) {
  if (!recovery_on_) {
    indexer_->setNFec(0);
    return;
  }

  // XXX for the moment we are considering congestion events
  // if(rc_->inCongestionState()){
  //   congestion_state_ = true;
  //   probing_state_ = false;
  //   indexer_->setNFec(0);
  //   return;
  // }

  // no congestion
  if (congestion_state_) {
    // this is the first round after congestion
    // enter probing phase
    probing_state_ = true;
    congestion_state_ = false;
  }

  if (probing_state_) {
    probing();
  } else {
    uint32_t fec_to_ask = computeFecPacketsToAsk();
    // If fec_to_ask == 0 we use rtx even if in these strategy we use only fec.
    // In this way the first packet loss that triggers the usage of fec can be
    // recovered using rtx, otherwise it will always be lost
    if (fec_to_ask == 0) {
      setRtxFec(true, false);
      switch_rounds_ = 0;
    } else {
      switch_rounds_++;
      if (switch_rounds_ >= ((RTC_INTEREST_LIFETIME / ROUND_LEN) * 2) &&
          rtx_during_fec_ !=
              0) {  // go to fec only if it is needed (RTX are on)
        setRtxFec(false, true);
      } else {
        setRtxFec(true, true);  // keep both
      }
    }
    if (rtx_during_fec_ == 0)  // if we do not send any RTX the losses
                               // registered may be due to jitter
      indexer_->setNFec(0);
    else
      indexer_->setNFec(fec_to_ask);
  }
}

void RecoveryStrategyFecOnly::newPacketLoss(uint32_t seq) {
  if (rtx_on_ && recovery_on_) {
    addNewRtx(seq, false);
  } else {
    if (!state_->isPending(seq) && !indexer_->isFec(seq)) {
      addNewRtx(seq, true);
    } else {
      // if not pending add to list to recover with fec
      recover_with_fec_.insert(seq);
      state_->onPossibleLossWithNoRtx(seq);
    }
  }
}

void RecoveryStrategyFecOnly::receivedPacket(uint32_t seq) {
  removePacketState(seq);
}

void RecoveryStrategyFecOnly::probing() {
  // TODO
  // for the moment ask for all fec and exit the probing phase
  probing_state_ = false;
  uint32_t fec_to_ask = computeFecPacketsToAsk();
  indexer_->setNFec(fec_to_ask);
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
