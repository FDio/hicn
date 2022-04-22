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
#include <protocols/rtc/rtc_ldr.h>
#include <protocols/rtc/rtc_rs_delay.h>
#include <protocols/rtc/rtc_rs_fec_only.h>
#include <protocols/rtc/rtc_rs_low_rate.h>
#include <protocols/rtc/rtc_rs_recovery_off.h>
#include <protocols/rtc/rtc_rs_rtx_only.h>
#include <protocols/rtc/rtc_state.h>

#include <algorithm>
#include <unordered_set>

namespace transport {

namespace protocol {

namespace rtc {

RTCLossDetectionAndRecovery::RTCLossDetectionAndRecovery(
    Indexer *indexer, asio::io_service &io_service,
    interface::RtcTransportRecoveryStrategies type,
    RecoveryStrategy::SendRtxCallback &&callback,
    interface::StrategyCallback &&external_callback) {
  rs_type_ = type;
  if (type == interface::RtcTransportRecoveryStrategies::RECOVERY_OFF) {
    rs_ = std::make_shared<RecoveryStrategyRecoveryOff>(
        indexer, std::move(callback), io_service, std::move(external_callback));
  } else if (type == interface::RtcTransportRecoveryStrategies::DELAY_BASED) {
    rs_ = std::make_shared<RecoveryStrategyDelayBased>(
        indexer, std::move(callback), io_service, std::move(external_callback));
  } else if (type == interface::RtcTransportRecoveryStrategies::FEC_ONLY) {
    rs_ = std::make_shared<RecoveryStrategyFecOnly>(
        indexer, std::move(callback), io_service, std::move(external_callback));
  } else if (type == interface::RtcTransportRecoveryStrategies::LOW_RATE ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_BESTPATH ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_REPLICATION ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_ALL_FWD_STRATEGIES) {
    rs_ = std::make_shared<RecoveryStrategyLowRate>(
        indexer, std::move(callback), io_service, std::move(external_callback));
  } else {
    // default
    rs_type_ = interface::RtcTransportRecoveryStrategies::RTX_ONLY;
    rs_ = std::make_shared<RecoveryStrategyRtxOnly>(
        indexer, std::move(callback), io_service, std::move(external_callback));
  }
}

RTCLossDetectionAndRecovery::~RTCLossDetectionAndRecovery() {}

void RTCLossDetectionAndRecovery::changeRecoveryStrategy(
    interface::RtcTransportRecoveryStrategies type) {
  if (type == rs_type_) return;

  rs_type_ = type;
  if (type == interface::RtcTransportRecoveryStrategies::RECOVERY_OFF) {
    rs_ =
        std::make_shared<RecoveryStrategyRecoveryOff>(std::move(*(rs_.get())));
  } else if (type == interface::RtcTransportRecoveryStrategies::DELAY_BASED) {
    rs_ = std::make_shared<RecoveryStrategyDelayBased>(std::move(*(rs_.get())));
  } else if (type == interface::RtcTransportRecoveryStrategies::FEC_ONLY) {
    rs_ = std::make_shared<RecoveryStrategyFecOnly>(std::move(*(rs_.get())));
  } else if (type == interface::RtcTransportRecoveryStrategies::LOW_RATE ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_BESTPATH ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_REPLICATION ||
             type == interface::RtcTransportRecoveryStrategies::
                         LOW_RATE_AND_ALL_FWD_STRATEGIES) {
    rs_ = std::make_shared<RecoveryStrategyLowRate>(std::move(*(rs_.get())));
  } else {
    // default
    rs_ = std::make_shared<RecoveryStrategyRtxOnly>(std::move(*(rs_.get())));
  }
}

void RTCLossDetectionAndRecovery::onNewRound(bool in_sync) {
  rs_->incRoundId();
  rs_->onNewRound(in_sync);
}

void RTCLossDetectionAndRecovery::onTimeout(uint32_t seq, bool lost) {
  if (!lost) {
    detectLoss(seq, seq + 1);
  } else {
    rs_->onLostTimeout(seq);
  }
}

void RTCLossDetectionAndRecovery::onPacketRecoveredFec(uint32_t seq) {
  rs_->receivedPacket(seq);
}

void RTCLossDetectionAndRecovery::onDataPacketReceived(
    const core::ContentObject &content_object) {
  uint32_t seq = content_object.getName().getSuffix();
  bool is_rtx = rs_->isRtx(seq);
  rs_->receivedPacket(seq);
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "received data. add from "
      << rs_->getState()->getHighestSeqReceivedInOrder() + 1 << " to " << seq;
  if (!is_rtx)
    detectLoss(rs_->getState()->getHighestSeqReceivedInOrder() + 1, seq);
}

void RTCLossDetectionAndRecovery::onNackPacketReceived(
    const core::ContentObject &nack) {
  struct nack_packet_t *nack_pkt =
      (struct nack_packet_t *)nack.getPayload()->data();
  uint32_t production_seq = nack_pkt->getProductionSegment();
  uint32_t seq = nack.getName().getSuffix();

  // received a nack. we can try to recover all data packets between the last
  // received data and the production seq in the nack. this is similar to the
  // recption of a probe
  // e.g.: the client receives packets 10 11 12 20 where 20 is a nack
  // with productionSeq = 18. this says that all the packets between 12 and 18
  // may got lost and we should ask them

  rs_->receivedPacket(seq);
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "received nack. add from "
      << rs_->getState()->getHighestSeqReceivedInOrder() + 1 << " to "
      << production_seq;
  detectLoss(rs_->getState()->getHighestSeqReceivedInOrder() + 1,
             production_seq);
}

void RTCLossDetectionAndRecovery::onProbePacketReceived(
    const core::ContentObject &probe) {
  // we don't log the reception of a probe packet for the sentinel timer because
  // probes are not taken into account into the sync window. we use them as
  // future nacks to detect possible packets lost

  uint32_t production_seq = RTCState::getProbeParams(probe).prod_seg;

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "received probe. add from "
      << rs_->getState()->getHighestSeqReceivedInOrder() + 1 << " to "
      << production_seq;

  detectLoss(rs_->getState()->getHighestSeqReceivedInOrder() + 1,
             production_seq);
}

void RTCLossDetectionAndRecovery::detectLoss(uint32_t start, uint32_t stop) {
  if (start >= stop) return;

  // skip nacked packets
  if (start <= rs_->getState()->getLastSeqNacked()) {
    start = rs_->getState()->getLastSeqNacked() + 1;
  }

  // skip received or lost packets
  if (start <= rs_->getState()->getHighestSeqReceivedInOrder()) {
    start = rs_->getState()->getHighestSeqReceivedInOrder() + 1;
  }

  for (uint32_t seq = start; seq < stop; seq++) {
    if (rs_->getState()->getPacketState(seq) == PacketState::UNKNOWN) {
      if (rs_->lossDetected(seq)) {
        rs_->getState()->onLossDetected(seq);
      }
    }
  }
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
