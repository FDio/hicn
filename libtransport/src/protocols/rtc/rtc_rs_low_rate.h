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

#include <vector>

namespace transport {

namespace protocol {

namespace rtc {

struct thresholds_t {
  uint32_t rtt;
  uint32_t loss_rtx_to_fec;  // loss rate used to move from rtx to fec
  uint32_t loss_fec_to_rtx;  // loss rate used to move from fec to rtx
};

class RecoveryStrategyLowRate : public RecoveryStrategy {
 public:
  RecoveryStrategyLowRate(Indexer *indexer, SendRtxCallback &&callback,
                          asio::io_service &io_service,
                          interface::RtcTransportRecoveryStrategies rs_type,
                          interface::StrategyCallback &&external_callback);

  RecoveryStrategyLowRate(RecoveryStrategy &&rs);

  ~RecoveryStrategyLowRate();

  void turnOnRecovery();
  void onNewRound(bool in_sync);
  void newPacketLoss(uint32_t seq);
  void receivedPacket(uint32_t seq);

 private:
  void initSwitchVector();
  void setRecoveryParameters(bool use_rtx, bool use_fec, uint32_t fec_to_ask);
  void selectRecoveryStrategy(bool in_sync);

  uint32_t fec_consecutive_rounds_;
  uint32_t rtx_allowed_consecutive_rounds_;

  // this table contains the thresholds that indicates when to switch from RTX
  // to FEC and viceversa. values in the vector are detected with a set of
  // experiments. the vector is used in the following way: if rtt and loss rate
  // are less than one of the values in the in the vector, losses are
  // recovered using RTX. otherwive losses are recovered using FEC. as for FEC
  // only and delay based strategy, the swith from RTX to FEC is smooth,
  // meaning that FEC and RTX are used together for some rounds
  std::vector<thresholds_t> switch_vector;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
