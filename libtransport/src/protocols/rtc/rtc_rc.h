/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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
#include <protocols/rtc/rtc_state.h>

namespace transport {

namespace protocol {

namespace rtc {

class RTCRateControl : public std::enable_shared_from_this<RTCRateControl> {
 public:
  RTCRateControl()
      : rc_on_(false),
        congestion_win_(1000000),  // init the win to a large number
        congestion_state_(CongestionState::Normal),
        protocol_state_(nullptr) {}

  virtual ~RTCRateControl() = default;

  void turnOnRateControl() { rc_on_ = true; }
  void setState(std::shared_ptr<RTCState> state) { protocol_state_ = state; };
  uint32_t getCongesionWindow() { return congestion_win_; };

  virtual void onNewRound(double round_len) = 0;
  virtual void onDataPacketReceived(
      const core::ContentObject &content_object) = 0;

 protected:
  enum class CongestionState { Normal = 0, Underuse = 1, Congested = 2, Last };

 protected:
  bool rc_on_;
  uint32_t congestion_win_;
  CongestionState congestion_state_;

  std::shared_ptr<RTCState> protocol_state_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
