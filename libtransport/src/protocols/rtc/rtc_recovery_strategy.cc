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
#include <hicn/transport/interfaces/notification.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_recovery_strategy.h>

namespace transport {

namespace protocol {

namespace rtc {

using namespace transport::interface;

RecoveryStrategy::RecoveryStrategy(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service,
    bool use_rtx, bool use_fec, interface::StrategyCallback &&external_callback)
    : recovery_on_(false),
      rtx_during_fec_(0),
      next_rtx_timer_(MAX_TIMER_RTX),
      send_rtx_callback_(std::move(callback)),
      indexer_(indexer),
      round_id_(0),
      last_fec_used_(0),
      callback_(std::move(external_callback)) {
  setRtxFec(use_rtx, use_fec);
  timer_ = std::make_unique<asio::steady_timer>(io_service);
}

RecoveryStrategy::RecoveryStrategy(RecoveryStrategy &&rs)
    : rtx_during_fec_(0),
      rtx_state_(std::move(rs.rtx_state_)),
      rtx_timers_(std::move(rs.rtx_timers_)),
      recover_with_fec_(std::move(rs.recover_with_fec_)),
      timer_(std::move(rs.timer_)),
      next_rtx_timer_(std::move(rs.next_rtx_timer_)),
      send_rtx_callback_(std::move(rs.send_rtx_callback_)),
      n_(std::move(rs.n_)),
      k_(std::move(rs.k_)),
      indexer_(std::move(rs.indexer_)),
      state_(std::move(rs.state_)),
      rc_(std::move(rs.rc_)),
      round_id_(std::move(rs.round_id_)),
      last_fec_used_(std::move(rs.last_fec_used_)),
      callback_(std::move(rs.callback_)) {
  setFecParams(n_, k_);
}

RecoveryStrategy::~RecoveryStrategy() {}

void RecoveryStrategy::setFecParams(uint32_t n, uint32_t k) {
  n_ = n;
  k_ = k;

  // XXX for the moment we go in steps of 5% loss rate.
  // max loss rate = 95%
  for (uint32_t loss_rate = 5; loss_rate < 100; loss_rate += 5) {
    double dec_loss_rate = (double)(loss_rate + 5) / 100.0;
    double exp_losses = (double)k_ * dec_loss_rate;
    uint32_t fec_to_ask = ceil(exp_losses / (1 - dec_loss_rate));

    fec_state_ f;
    f.fec_to_ask = std::min(fec_to_ask, (n_ - k_));
    f.last_update = round_id_;
    f.avg_residual_losses = 0.0;
    f.consecutive_use = 0;
    fec_per_loss_rate_.push_back(f);
  }
}

bool RecoveryStrategy::lossDetected(uint32_t seq) {
  if (isRtx(seq)) {
    // this packet is already in the list of rtx
    return false;
  }

  auto it_fec = recover_with_fec_.find(seq);
  if (it_fec != recover_with_fec_.end()) {
    // this packet is already in list of packets to recover with fec
    // this list contians also fec packets that will not be recovered with rtx
    return false;
  }

  auto it_nack = nacked_seq_.find(seq);
  if (it_nack != nacked_seq_.end()) {
    // this packet was nacked so we do not use it to determine the loss rate
    return false;
  }

  return true;
}

void RecoveryStrategy::notifyNewLossDetedcted(uint32_t seq) {
  // new loss detected
  // first record the loss. second do what is needed to recover it
  state_->onLossDetected(seq);
  newPacketLoss(seq);
}

void RecoveryStrategy::requestPossibleLostPacket(uint32_t seq) {
  // these are packets for which we send a RTX but we do not increase the loss
  // counter beacuse we don't know if they are lost or not
  addNewRtx(seq, false);
}

void RecoveryStrategy::receivedFutureNack(uint32_t seq) {
  nacked_seq_.insert(seq);
}

void RecoveryStrategy::clear() {
  rtx_state_.clear();
  rtx_timers_.clear();
  recover_with_fec_.clear();

  if (next_rtx_timer_ != MAX_TIMER_RTX) {
    next_rtx_timer_ = MAX_TIMER_RTX;
    timer_->cancel();
  }
}

// rtx functions
void RecoveryStrategy::addNewRtx(uint32_t seq, bool force) {
  if (!indexer_->isFec(seq) || force) {
    // this packet needs to be re-transmitted
    rtxState state;
    state.first_send_ = state_->getInterestSentTime(seq);
    if (state.first_send_ == 0)  // this interest was never sent before
      state.first_send_ = getNow();
    state.next_send_ = computeNextSend(seq, true);
    state.rtx_count_ = 0;
    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "Add " << seq << " to retransmissions. next rtx is in "
        << state.next_send_ - getNow() << " ms";
    rtx_state_.insert(std::pair<uint32_t, rtxState>(seq, state));
    rtx_timers_.insert(std::pair<uint64_t, uint32_t>(state.next_send_, seq));

    // if a new rtx is introduced, check the rtx timer
    scheduleNextRtx();
  } else {
    // do not re-send fec packets but keep track of them
    recover_with_fec_.insert(seq);
    state_->onPossibleLossWithNoRtx(seq);
  }
}

uint64_t RecoveryStrategy::computeNextSend(uint32_t seq, bool new_rtx) {
  uint64_t now = getNow();
  if (new_rtx) {
    // for the new rtx we wait one estimated IAT after the loss detection. this
    // is bacause, assuming that packets arrive with a constant IAT, we should
    // get a new packet every IAT
    double prod_rate = state_->getProducerRate();
    uint32_t estimated_iat = SENTINEL_TIMER_INTERVAL;
    uint32_t jitter = 0;

    if (prod_rate != 0) {
      double packet_size = state_->getAveragePacketSize();
      estimated_iat = ceil(1000.0 / (prod_rate / packet_size));
      jitter = ceil(state_->getJitter());
    }

    uint32_t wait = 1;
    if (estimated_iat < 18) {
      // for low rate app we do not wait to send a RTX
      // we consider low rate stream with less than 50pps (iat >= 20ms)
      // (e.g. audio in videoconf, mobile games).
      // in the check we use 18ms to accomodate for measurements errors
      // for flows with higher rate wait 1 ait + jitter
      wait = estimated_iat + jitter;
    }

    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "first rtx for " << seq << " in " << wait
        << " ms, rtt = " << state_->getMinRTT() << " ait = " << estimated_iat
        << " jttr = " << jitter;

    return now + wait;
  } else {
    // wait one RTT
    uint32_t wait = SENTINEL_TIMER_INTERVAL;

    double prod_rate = state_->getProducerRate();
    if (prod_rate == 0) {
      return now + SENTINEL_TIMER_INTERVAL;
    }

    double packet_size = state_->getAveragePacketSize();
    uint32_t estimated_iat = ceil(1000.0 / (prod_rate / packet_size));

    uint64_t rtt = state_->getMinRTT();
    if (rtt == 0) rtt = SENTINEL_TIMER_INTERVAL;
    wait = rtt;

    uint32_t jitter = ceil(state_->getJitter());
    wait += jitter;

    // it may happen that the channel is congested and we have some additional
    // queuing delay to take into account
    uint32_t queue = ceil(state_->getQueuing());
    wait += queue;

    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "next rtx for " << seq << " in " << wait
        << " ms, rtt = " << state_->getMinRTT() << " ait = " << estimated_iat
        << " jttr = " << jitter << " queue = " << queue;

    return now + wait;
  }
}

void RecoveryStrategy::retransmit() {
  if (rtx_timers_.size() == 0) return;

  uint64_t now = getNow();

  auto it = rtx_timers_.begin();
  std::unordered_set<uint32_t> lost_pkt;
  uint32_t sent_counter = 0;
  while (it != rtx_timers_.end() && it->first <= now &&
         sent_counter < MAX_RTX_IN_BATCH) {
    uint32_t seq = it->second;
    auto rtx_it =
        rtx_state_.find(seq);  // this should always return a valid iter
    if (rtx_it->second.rtx_count_ >= RTC_MAX_RTX ||
        (now - rtx_it->second.first_send_) >= RTC_MAX_AGE ||
        seq < state_->getLastSeqNacked()) {
      // max rtx reached or packet too old or packet nacked, this packet is lost
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "packet " << seq << " lost because 1) max rtx: "
          << (rtx_it->second.rtx_count_ >= RTC_MAX_RTX) << " 2) max age: "
          << ((now - rtx_it->second.first_send_) >= RTC_MAX_AGE)
          << " 3) nacked: " << (seq < state_->getLastSeqNacked());
      lost_pkt.insert(seq);
      it++;
    } else {
      // resend the packet
      state_->onRetransmission(seq);
      double prod_rate = state_->getProducerRate();
      if (prod_rate != 0) rtx_it->second.rtx_count_++;
      rtx_it->second.next_send_ = computeNextSend(seq, false);
      it = rtx_timers_.erase(it);
      rtx_timers_.insert(
          std::pair<uint64_t, uint32_t>(rtx_it->second.next_send_, seq));
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "send rtx for sequence " << seq << ", next send in "
          << (rtx_it->second.next_send_ - now);

      // if fec is on increase the number of RTX send during fec
      if (fec_on_) rtx_during_fec_++;
      send_rtx_callback_(seq);
      sent_counter++;
    }
  }

  // remove packets if needed
  for (auto lost_it = lost_pkt.begin(); lost_it != lost_pkt.end(); lost_it++) {
    uint32_t seq = *lost_it;
    state_->onPacketLost(seq);
    deleteRtx(seq);
  }
}

void RecoveryStrategy::scheduleNextRtx() {
  if (rtx_timers_.size() == 0) {
    // all the rtx were removed, reset timer
    next_rtx_timer_ = MAX_TIMER_RTX;
    return;
  }

  // check if timer is alreay set
  if (next_rtx_timer_ != MAX_TIMER_RTX) {
    // a new check for rtx is already scheduled
    if (next_rtx_timer_ > rtx_timers_.begin()->first) {
      // we need to re-schedule it
      timer_->cancel();
    } else {
      // wait for the next timer
      return;
    }
  }

  // set a new timer
  next_rtx_timer_ = rtx_timers_.begin()->first;
  uint64_t now = utils::SteadyTime::nowMs().count();
  uint64_t wait = 1;
  if (next_rtx_timer_ != MAX_TIMER_RTX && next_rtx_timer_ > now)
    wait = next_rtx_timer_ - now;

  std::weak_ptr<RecoveryStrategy> self(shared_from_this());
  timer_->expires_from_now(std::chrono::milliseconds(wait));
  timer_->async_wait([self](const std::error_code &ec) {
    if (ec) return;
    if (auto s = self.lock()) {
      s->retransmit();
      s->next_rtx_timer_ = MAX_TIMER_RTX;
      s->scheduleNextRtx();
    }
  });
}

void RecoveryStrategy::deleteRtx(uint32_t seq) {
  auto it_rtx = rtx_state_.find(seq);
  if (it_rtx == rtx_state_.end()) return;  // rtx not found

  // remove the rtx from the timers list
  uint64_t ts = it_rtx->second.next_send_;
  auto it_timers = rtx_timers_.find(ts);
  while (it_timers != rtx_timers_.end() && it_timers->first == ts) {
    if (it_timers->second == seq) {
      rtx_timers_.erase(it_timers);
      break;
    }
    it_timers++;
  }
  // remove rtx
  rtx_state_.erase(it_rtx);
}

// fec functions
uint32_t RecoveryStrategy::computeFecPacketsToAsk() {
  double loss_rate = state_->getMaxLossRate() * 100;  // use loss rate in %

  if (loss_rate > 95) loss_rate = 95;  // max loss rate

  if (loss_rate == 0) return 0;

  // once per minute try to reduce the fec rate. it may happen that for some bin
  // we ask too many fec packet. here we try to reduce this values gently
  if (round_id_ % ROUNDS_PER_MIN == 0) {
    reduceFec();
  }

  // keep track of the last used fec. if we use a new bin on this round reset
  // consecutive use and avg loss in the prev bin
  uint32_t bin = ceil(loss_rate / 5.0) - 1;
  if (bin > fec_per_loss_rate_.size() - 1) bin = fec_per_loss_rate_.size() - 1;

  if (bin != last_fec_used_) {
    fec_per_loss_rate_[last_fec_used_].consecutive_use = 0;
    fec_per_loss_rate_[last_fec_used_].avg_residual_losses = 0.0;
  }
  last_fec_used_ = bin;
  fec_per_loss_rate_[last_fec_used_].consecutive_use++;

  // we update the stats only once very 5 rounds (1sec) that is the rate at
  // which we compute residual losses
  if (round_id_ % ROUNDS_PER_SEC == 0) {
    double residual_losses = state_->getResidualLossRate() * 100;
    // update residual loss rate
    fec_per_loss_rate_[bin].avg_residual_losses =
        (fec_per_loss_rate_[bin].avg_residual_losses * MOVING_AVG_ALPHA) +
        (1 - MOVING_AVG_ALPHA) * residual_losses;

    if ((fec_per_loss_rate_[bin].last_update - round_id_) <
        WAIT_BEFORE_FEC_UPDATE) {
      // this bin is been updated recently so don't modify it  and
      // return the current state
      return fec_per_loss_rate_[bin].fec_to_ask;
    }

    // if the residual loss rate is too high and we can ask more fec packets and
    // we are using this configuration since at least 5 sec update fec
    if (fec_per_loss_rate_[bin].avg_residual_losses > MAX_RESIDUAL_LOSS_RATE &&
        fec_per_loss_rate_[bin].fec_to_ask < (n_ - k_) &&
        fec_per_loss_rate_[bin].consecutive_use > WAIT_BEFORE_FEC_UPDATE) {
      // so increase the number of fec packets to ask
      fec_per_loss_rate_[bin].fec_to_ask++;
      fec_per_loss_rate_[bin].last_update = round_id_;
      fec_per_loss_rate_[bin].avg_residual_losses = 0.0;
    }
  }

  return fec_per_loss_rate_[bin].fec_to_ask;
}

void RecoveryStrategy::setRtxFec(std::optional<bool> rtx_on,
                                 std::optional<bool> fec_on) {
  if (rtx_on) rtx_on_ = *rtx_on;
  if (fec_on) {
    if (fec_on_ == false && (*fec_on) == true) {  // turn on fec
      // reset the number of RTX sent during fec
      rtx_during_fec_ = 0;
    }
    fec_on_ = *fec_on;
  }

  notification::RecoveryStrategy strategy =
      notification::RecoveryStrategy::RECOVERY_OFF;

  if (rtx_on_ && fec_on_)
    strategy = notification::RecoveryStrategy::RTX_AND_FEC;
  else if (rtx_on_)
    strategy = notification::RecoveryStrategy::RTX_ONLY;
  else if (fec_on_)
    strategy = notification::RecoveryStrategy::FEC_ONLY;

  callback_(strategy);
}

// common functions
void RecoveryStrategy::onLostTimeout(uint32_t seq) { removePacketState(seq); }

void RecoveryStrategy::removePacketState(uint32_t seq) {
  auto it_fec = recover_with_fec_.find(seq);
  if (it_fec != recover_with_fec_.end()) {
    recover_with_fec_.erase(it_fec);
    return;
  }

  auto it_nack = nacked_seq_.find(seq);
  if (it_nack != nacked_seq_.end()) {
    nacked_seq_.erase(it_nack);
    return;
  }

  deleteRtx(seq);
}

// private methods

void RecoveryStrategy::reduceFec() {
  for (uint32_t loss_rate = 5; loss_rate < 100; loss_rate += 5) {
    double dec_loss_rate = (double)loss_rate / 100.0;
    double exp_losses = (double)k_ * dec_loss_rate;
    uint32_t fec_to_ask = ceil(exp_losses / (1 - dec_loss_rate));

    uint32_t bin = ceil(loss_rate / 5.0) - 1;
    if (fec_per_loss_rate_[bin].fec_to_ask > fec_to_ask) {
      fec_per_loss_rate_[bin].fec_to_ask--;
    }
  }
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
