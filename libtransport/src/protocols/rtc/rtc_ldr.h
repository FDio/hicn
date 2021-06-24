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
#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/name.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_state.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <functional>
#include <map>

namespace transport {

namespace protocol {

namespace rtc {

class RTCLossDetectionAndRecovery
    : public std::enable_shared_from_this<RTCLossDetectionAndRecovery> {
  struct rtx_state_ {
    uint64_t first_send_;
    uint64_t next_send_;
    uint32_t rtx_count_;
  };

  using rtxState = struct rtx_state_;
  using SendRtxCallback = std::function<void(uint32_t)>;

 public:
  RTCLossDetectionAndRecovery(SendRtxCallback &&callback,
                              asio::io_service &io_service);

  ~RTCLossDetectionAndRecovery();

  void setState(std::shared_ptr<RTCState> state) { state_ = state; }
  void turnOnRTX();
  void turnOffRTX();

  void onTimeout(uint32_t seq);
  void onDataPacketReceived(const core::ContentObject &content_object);
  void onNackPacketReceived(const core::ContentObject &nack);
  void onProbePacketReceived(const core::ContentObject &probe);

  void clear();

  bool isRtx(uint32_t seq) {
    if (rtx_state_.find(seq) != rtx_state_.end()) return true;
    return false;
  }

 private:
  void addToRetransmissions(uint32_t start, uint32_t stop);
  uint64_t computeNextSend(uint32_t seq, bool new_rtx);
  void retransmit();
  void scheduleNextRtx();
  bool deleteRtx(uint32_t seq);
  void scheduleSentinelTimer(uint64_t expires_from_now);
  void sentinelTimer();

  uint64_t getNow() {
    using namespace std::chrono;
    uint64_t now =
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
            .count();
    return now;
  }

  // this map keeps track of the retransmitted interest, ordered from the oldest
  // to the newest one. the state contains the timer of the first send of the
  // interest (from pendingIntetests_), the timer of the next send (key of the
  // multimap) and the number of rtx
  std::map<uint32_t, rtxState> rtx_state_;
  // this map stored the rtx by timer. The key is the time at which the rtx
  // should be sent, and the val is the interest seq number
  std::multimap<uint64_t, uint32_t> rtx_timers_;

  bool rtx_on_;
  uint64_t next_rtx_timer_;
  uint64_t last_event_;
  uint64_t sentinel_timer_interval_;
  std::unique_ptr<asio::steady_timer> timer_;
  std::unique_ptr<asio::steady_timer> sentinel_timer_;
  std::shared_ptr<RTCState> state_;

  SendRtxCallback send_rtx_callback_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
