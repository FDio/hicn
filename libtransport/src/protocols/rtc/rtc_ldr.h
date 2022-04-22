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
#include <hicn/transport/config.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
// RtcTransportRecoveryStrategies
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/name.h>
#include <protocols/rtc/rtc_recovery_strategy.h>

#include <functional>

namespace transport {

namespace protocol {

namespace rtc {

class RTCLossDetectionAndRecovery
    : public std::enable_shared_from_this<RTCLossDetectionAndRecovery> {
 public:
  RTCLossDetectionAndRecovery(Indexer *indexer, asio::io_service &io_service,
                              interface::RtcTransportRecoveryStrategies type,
                              RecoveryStrategy::SendRtxCallback &&callback,
                              interface::StrategyCallback &&external_callback);

  ~RTCLossDetectionAndRecovery();

  void setState(RTCState *state) { rs_->setState(state); }
  void setRateControl(RTCRateControl *rateControl) {
    rs_->setRateControl(rateControl);
  }

  void setFecParams(uint32_t n, uint32_t k) { rs_->setFecParams(n, k); }

  void turnOnRecovery() { rs_->turnOnRecovery(); }
  bool isRtxOn() { return rs_->isRtxOn(); }

  void changeRecoveryStrategy(interface::RtcTransportRecoveryStrategies type);

  void onNewRound(bool in_sync);

  // the following functions return true if a loss is detected, false otherwise
  bool onTimeout(uint32_t seq, bool lost);
  bool onPacketRecoveredFec(uint32_t seq);
  bool onDataPacketReceived(const core::ContentObject &content_object);
  bool onNackPacketReceived(const core::ContentObject &nack);
  bool onProbePacketReceived(const core::ContentObject &probe);

  void clear() { rs_->clear(); }

  bool isRtx(uint32_t seq) { return rs_->isRtx(seq); }
  bool isPossibleLossWithNoRtx(uint32_t seq) {
    return rs_->isPossibleLossWithNoRtx(seq);
  }

 private:
  // returns true if a loss is detected, false otherwise
  bool detectLoss(uint32_t start, uint32_t stop, bool recv_probe);

  interface::RtcTransportRecoveryStrategies rs_type_;
  std::shared_ptr<RecoveryStrategy> rs_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
