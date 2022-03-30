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
#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/indexer.h>
#include <protocols/rtc/rtc_rc.h>
#include <protocols/rtc/rtc_state.h>

#include <map>
#include <unordered_map>

namespace transport {

namespace protocol {

namespace rtc {

class RecoveryStrategy : public std::enable_shared_from_this<RecoveryStrategy> {
 protected:
  struct rtx_state_ {
    uint64_t first_send_;
    uint64_t next_send_;
    uint32_t rtx_count_;
  };

  using rtxState = struct rtx_state_;

 public:
  using SendRtxCallback = std::function<void(uint32_t)>;

  RecoveryStrategy(Indexer *indexer, SendRtxCallback &&callback,
                   asio::io_service &io_service, bool use_rtx, bool use_fec,
                   interface::StrategyCallback *external_callback);

  RecoveryStrategy(RecoveryStrategy &&rs);

  virtual ~RecoveryStrategy();

  void setRtxFec(std::optional<bool> rtx_on = {},
                 std::optional<bool> fec_on = {});
  void setState(RTCState *state) { state_ = state; }
  void setRateControl(RTCRateControl *rateControl) { rc_ = rateControl; }
  void setFecParams(uint32_t n, uint32_t k);

  void tunrOnRecovery() { recovery_on_ = true; }

  bool isRtx(uint32_t seq) {
    if (rtx_state_.find(seq) != rtx_state_.end()) return true;
    return false;
  }

  bool isPossibleLossWithNoRtx(uint32_t seq) {
    if (recover_with_fec_.find(seq) != recover_with_fec_.end()) return true;
    return false;
  }

  bool isRtxOn() { return rtx_on_; }

  RTCState *getState() { return state_; }
  bool lossDetected(uint32_t seq);
  void clear();

  virtual void onNewRound(bool in_sync) = 0;
  virtual void newPacketLoss(uint32_t seq) = 0;
  virtual void receivedPacket(uint32_t seq) = 0;
  void onLostTimeout(uint32_t seq);

  void incRoundId() { round_id_++; }

  // utils
  uint64_t getNow() {
    uint64_t now = utils::SteadyTime::nowMs().count();
    return now;
  }

 protected:
  // rtx functions
  void addNewRtx(uint32_t seq, bool force);
  uint64_t computeNextSend(uint32_t seq, bool new_rtx);
  void retransmit();
  void scheduleNextRtx();
  void deleteRtx(uint32_t seq);

  // fec functions
  uint32_t computeFecPacketsToAsk(bool in_sync);

  // common functons
  void removePacketState(uint32_t seq);

  bool recovery_on_;
  bool rtx_on_;
  bool fec_on_;

  // this map keeps track of the retransmitted interest, ordered from the oldest
  // to the newest one. the state contains the timer of the first send of the
  // interest (from pendingIntetests_), the timer of the next send (key of the
  // multimap) and the number of rtx
  std::map<uint32_t, rtxState> rtx_state_;
  // this map stored the rtx by timer. The key is the time at which the rtx
  // should be sent, and the val is the interest seq number
  std::multimap<uint64_t, uint32_t> rtx_timers_;

  // lost packets that will be recovered with fec
  std::unordered_set<uint32_t> recover_with_fec_;

  // rtx vars
  std::unique_ptr<asio::steady_timer> timer_;
  uint64_t next_rtx_timer_;
  SendRtxCallback send_rtx_callback_;

  // fec vars
  uint32_t n_;
  uint32_t k_;
  Indexer *indexer_;

  RTCState *state_;
  RTCRateControl *rc_;

 private:
  struct fec_state_ {
    uint32_t fec_to_ask;
    uint32_t last_update;      // round id of the last update
                               // (wait 10 ruonds (2sec) between updates)
    uint32_t consecutive_use;  // consecutive ruonds where this fec was used
    double avg_residual_losses;
  };

  void reduceFec();

  uint32_t round_id_;  // number of rounds
  uint32_t last_fec_used_;
  std::vector<fec_state_> fec_per_loss_rate_;
  interface::StrategyCallback *callback_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
