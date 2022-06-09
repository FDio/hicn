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
#include <protocols/rtc/rtc_rs_low_rate.h>

namespace transport {

namespace protocol {

namespace rtc {

RecoveryStrategyLowRate::RecoveryStrategyLowRate(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    interface::RtcTransportRecoveryStrategies rs_type,
    interface::StrategyCallback &&external_callback)
    : RecoveryStrategy(indexer, std::move(callback), io_service, false, true,
                       rs_type,
                       std::move(external_callback)),  // start with fec
      fec_consecutive_rounds_((MILLI_IN_A_SEC / ROUND_LEN) * 5),  // 5 sec
      rtx_allowed_consecutive_rounds_(0) {
  initSwitchVector();
}

RecoveryStrategyLowRate::RecoveryStrategyLowRate(RecoveryStrategy &&rs)
    : RecoveryStrategy(std::move(rs)),
      fec_consecutive_rounds_((MILLI_IN_A_SEC / ROUND_LEN) * 5),  // 5 sec
      rtx_allowed_consecutive_rounds_(0) {
  setRtxFec(false, true);
  initSwitchVector();
}

RecoveryStrategyLowRate::~RecoveryStrategyLowRate() {}

void RecoveryStrategyLowRate::initSwitchVector() {
  // TODO adjust thresholds here when new data are collected
  // see resutls in
  // https://confluence-eng-gpk1.cisco.com/conf/display/SPT/dailyreports
  thresholds_t t1;
  t1.rtt = 15;              // 15ms
  t1.loss_rtx_to_fec = 15;  // 15%
  t1.loss_fec_to_rtx = 10;  // 10%
  thresholds_t t2;
  t2.rtt = 35;             // 35ms
  t2.loss_rtx_to_fec = 5;  // 5%
  t2.loss_fec_to_rtx = 1;  // 1%
  switch_vector.push_back(t1);
  switch_vector.push_back(t2);
}

void RecoveryStrategyLowRate::setRecoveryParameters(bool use_rtx, bool use_fec,
                                                    uint32_t fec_to_ask) {
  setRtxFec(use_rtx, use_fec);
  indexer_->setNFec(fec_to_ask);
}

void RecoveryStrategyLowRate::selectRecoveryStrategy(bool in_sync) {
  uint32_t fec_to_ask = computeFecPacketsToAsk();
  if (fec_to_ask == 0) {
    // fec is off, turn on RTX immediatly to avoid packet losses
    setRecoveryParameters(true, false, 0);
    fec_consecutive_rounds_ = 0;
    return;
  }

  uint32_t loss_rate = std::round(state_->getPerSecondLossRate() * 100);
  uint32_t rtt = (uint32_t)state_->getAvgRTT();

  bool use_rtx = false;
  for (size_t i = 0; i < switch_vector.size(); i++) {
    uint32_t max_loss_rate = 0;
    if (fec_on_)
      max_loss_rate = switch_vector[i].loss_fec_to_rtx;
    else
      max_loss_rate = switch_vector[i].loss_rtx_to_fec;

    if (rtt < switch_vector[i].rtt && loss_rate < max_loss_rate) {
      use_rtx = true;
      rtx_allowed_consecutive_rounds_++;
      break;
    }
  }

  if (!use_rtx) rtx_allowed_consecutive_rounds_ = 0;

  if (use_rtx) {
    if (fec_on_) {
      // here we should swtich from RTX to FEC
      // wait 10sec where the switch is allowed before actually switch
      if (rtx_allowed_consecutive_rounds_ >=
          ((MILLI_IN_A_SEC / ROUND_LEN) * 10)) {  // 10 sec
        // use RTX
        setRecoveryParameters(true, false, 0);
        fec_consecutive_rounds_ = 0;
      } else {
        // keep using FEC (and maybe RTX)
        setRecoveryParameters(true, true, fec_to_ask);
        fec_consecutive_rounds_++;
      }
    } else {
      // keep using RTX
      setRecoveryParameters(true, false, 0);
      fec_consecutive_rounds_ = 0;
    }
  } else {
    // use FEC and RTX
    setRecoveryParameters(true, true, fec_to_ask);
    fec_consecutive_rounds_++;
  }

  // everytime that we anable FEC we keep also RTX on. in this way the first
  // losses that are not covered by FEC are recovered using RTX. after 5 sec we
  // disable fec
  if (fec_consecutive_rounds_ >= ((MILLI_IN_A_SEC / ROUND_LEN) * 5)) {
    // turn off RTX
    setRtxFec(false);
  }
}

void RecoveryStrategyLowRate::turnOnRecovery() {
  recovery_on_ = 1;
  // the stategy will be init in the new round function
}

void RecoveryStrategyLowRate::onNewRound(bool in_sync) {
  if (!recovery_on_) {
    // disable fec so that no extra packet will be sent
    // for rtx we check if recovery is on in newPacketLoss
    setRtxFec(true, false);
    indexer_->setNFec(0);
    return;
  }

  // XXX since this strategy will be used only for flow at low rate we do not
  // consider congestion events like in other strategies

  selectRecoveryStrategy(in_sync);
}

void RecoveryStrategyLowRate::newPacketLoss(uint32_t seq) {
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

void RecoveryStrategyLowRate::receivedPacket(uint32_t seq) {
  removePacketState(seq);
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
