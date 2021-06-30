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

#include <glog/logging.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_ldr.h>

#include <algorithm>
#include <unordered_set>

namespace transport {

namespace protocol {

namespace rtc {

RTCLossDetectionAndRecovery::RTCLossDetectionAndRecovery(
    Indexer *indexer, SendRtxCallback &&callback, asio::io_service &io_service)
    : rtx_on_(false),
      fec_on_(false),
      next_rtx_timer_(MAX_TIMER_RTX),
      last_event_(0),
      sentinel_timer_interval_(MAX_TIMER_RTX),
      indexer_(indexer),
      send_rtx_callback_(std::move(callback)) {
  timer_ = std::make_unique<asio::steady_timer>(io_service);
  sentinel_timer_ = std::make_unique<asio::steady_timer>(io_service);
}

RTCLossDetectionAndRecovery::~RTCLossDetectionAndRecovery() {}

void RTCLossDetectionAndRecovery::turnOnRTX() {
  rtx_on_ = true;
  scheduleSentinelTimer(state_->getRTT() * CATCH_UP_RTT_INCREMENT);
}

void RTCLossDetectionAndRecovery::turnOffRTX() {
  rtx_on_ = false;
  clear();
}

uint32_t RTCLossDetectionAndRecovery::computeFecPacketsToAsk(bool in_sync) {
  uint32_t current_fec = indexer_->getNFec();
  double current_loss_rate = state_->getLossRate();
  double last_loss_rate = state_->getLastRoundLossRate();

  // when in sync ask for fec only if there are losses for 2 rounds
  if (in_sync && current_fec == 0 &&
      (current_loss_rate == 0 || last_loss_rate == 0))
    return 0;

  double loss_rate = state_->getMaxLossRate() * 1.5;

  if (!in_sync && loss_rate == 0) loss_rate = 0.05;
  if (loss_rate > 0.5) loss_rate = 0.5;

  double exp_losses = (double)k_ * loss_rate;
  uint32_t fec_to_ask = ceil(exp_losses / (1 - loss_rate));

  if (fec_to_ask > (n_ - k_)) fec_to_ask = n_ - k_;

  return fec_to_ask;
}

void RTCLossDetectionAndRecovery::onNewRound(bool in_sync) {
  uint64_t rtt = state_->getRTT();
  if (!fec_on_ && rtt >= 100) {
    // turn on fec, here we may have no info so ask for all packets
    fec_on_ = true;
    turnOffRTX();
    indexer_->setNFec(computeFecPacketsToAsk(in_sync));
    return;
  }

  if (fec_on_ && rtt > 80) {
    // keep using fec, maybe update it
    indexer_->setNFec(computeFecPacketsToAsk(in_sync));
    return;
  }

  if ((fec_on_ && rtt <= 80) || (!rtx_on_ && rtt <= 100)) {
    // turn on rtx
    fec_on_ = false;
    indexer_->setNFec(0);
    turnOnRTX();
    return;
  }
}

void RTCLossDetectionAndRecovery::onTimeout(uint32_t seq) {
  // always add timeouts to the RTX list to avoid to send the same packet as if
  // it was not a rtx
  addToRetransmissions(seq, seq + 1);
  last_event_ = getNow();
}

void RTCLossDetectionAndRecovery::onPacketRecoveredFec(uint32_t seq) {
  // if an RTX is scheduled for a packet recovered using FEC delete it
  deleteRtx(seq);
  recover_with_fec_.erase(seq);
}

void RTCLossDetectionAndRecovery::onDataPacketReceived(
    const core::ContentObject &content_object) {
  last_event_ = getNow();

  uint32_t seq = content_object.getName().getSuffix();
  if (deleteRtx(seq)) {
    state_->onPacketRecoveredRtx(seq);
  } else {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "received data. add from "
        << state_->getHighestSeqReceivedInOrder() + 1 << " to " << seq;
    addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1, seq);
  }
}

void RTCLossDetectionAndRecovery::onNackPacketReceived(
    const core::ContentObject &nack) {
  last_event_ = getNow();

  uint32_t seq = nack.getName().getSuffix();

  struct nack_packet_t *nack_pkt =
      (struct nack_packet_t *)nack.getPayload()->data();
  uint32_t production_seq = nack_pkt->getProductionSegement();

  if (production_seq > seq) {
    // this is a past nack, all data before productionSeq are lost. if
    // productionSeq > state_->getHighestSeqReceivedInOrder() is impossible to
    // recover any packet. If this is not the case we can try to recover the
    // packets between state_->getHighestSeqReceivedInOrder() and productionSeq.
    // e.g.: the client receives packets 8 10 11 9 where 9 is a nack with
    // productionSeq = 14. 9 is lost but we can try to recover packets 12 13 and
    // 14 that are not arrived yet
    deleteRtx(seq);
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "received past nack. add from "
                                 << state_->getHighestSeqReceivedInOrder() + 1
                                 << " to " << production_seq;
    addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1,
                         production_seq);
  } else {
    // future nack. here there should be a gap between the last data received
    // and this packet and is it possible to recover the packets between the
    // last received data and the production seq. we should not use the seq
    // number of the nack since we know that is too early to ask for this seq
    // number
    // e.g.: // e.g.: the client receives packets 10 11 12 20 where 20 is a nack
    // with productionSeq = 18. this says that all the packets between 12 and 18
    // may got lost and we should ask them
    deleteRtx(seq);
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "received futrue nack. add from "
                                 << state_->getHighestSeqReceivedInOrder() + 1
                                 << " to " << production_seq;
    addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1,
                         production_seq);
  }
}

void RTCLossDetectionAndRecovery::onProbePacketReceived(
    const core::ContentObject &probe) {
  // we don't log the reception of a probe packet for the sentinel timer because
  // probes are not taken into account into the sync window. we use them as
  // future nacks to detect possible packets lost
  struct nack_packet_t *probe_pkt =
      (struct nack_packet_t *)probe.getPayload()->data();
  uint32_t production_seq = probe_pkt->getProductionSegement();
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "received probe. add from "
      << state_->getHighestSeqReceivedInOrder() + 1 << " to " << production_seq;

  addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1,
                       production_seq);
}

void RTCLossDetectionAndRecovery::clear() {
  rtx_state_.clear();
  rtx_timers_.clear();
  sentinel_timer_->cancel();
  if (next_rtx_timer_ != MAX_TIMER_RTX) {
    next_rtx_timer_ = MAX_TIMER_RTX;
    timer_->cancel();
  }
}

void RTCLossDetectionAndRecovery::addToRetransmissions(uint32_t start,
                                                       uint32_t stop) {
  // skip nacked packets
  if (start <= state_->getLastSeqNacked()) {
    start = state_->getLastSeqNacked() + 1;
  }

  // skip received or lost packets
  if (start <= state_->getHighestSeqReceivedInOrder()) {
    start = state_->getHighestSeqReceivedInOrder() + 1;
  }

  for (uint32_t seq = start; seq < stop; seq++) {
    if (state_->isReceivedOrLost(seq) == PacketState::UNKNOWN) {
      if (rtx_on_) {
        if (!indexer_->isFec(seq)) {
          // handle it with rtx
          if (!isRtx(seq)) {
            state_->onLossDetected(seq);
            rtxState state;
            state.first_send_ = state_->getInterestSentTime(seq);
            if (state.first_send_ == 0)  // this interest was never sent before
              state.first_send_ = getNow();
            state.next_send_ = computeNextSend(seq, true);
            state.rtx_count_ = 0;
            DLOG_IF(INFO, VLOG_IS_ON(4))
                << "Add " << seq << " to retransmissions. next rtx is %lu "
                << state.next_send_ - getNow();
            rtx_state_.insert(std::pair<uint32_t, rtxState>(seq, state));
            rtx_timers_.insert(
                std::pair<uint64_t, uint32_t>(state.next_send_, seq));
          }
        } else {
          // is fec, do not send it
          auto it = recover_with_fec_.find(seq);
          if (it == recover_with_fec_.end()) {
            state_->onLossDetected(seq);
            recover_with_fec_.insert(seq);
          }
        }
      } else {
        // keep track of losses but recover with FEC
        auto it = recover_with_fec_.find(seq);
        if (it == recover_with_fec_.end()) {
          state_->onLossDetected(seq);
          recover_with_fec_.insert(seq);
        }
      }
    }
  }
  scheduleNextRtx();
}

uint64_t RTCLossDetectionAndRecovery::computeNextSend(uint32_t seq,
                                                      bool new_rtx) {
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

    uint32_t wait = estimated_iat + jitter;
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "first rtx for " << seq << " in " << wait
        << " ms, rtt = " << state_->getRTT() << " ait = " << estimated_iat
        << " jttr = " << jitter;

    return now + wait;
  } else {
    // wait one RTT
    // however if the IAT is larger than the RTT, wait one IAT
    uint32_t wait = SENTINEL_TIMER_INTERVAL;

    double prod_rate = state_->getProducerRate();
    if (prod_rate == 0) {
      return now + SENTINEL_TIMER_INTERVAL;
    }

    double packet_size = state_->getAveragePacketSize();
    uint32_t estimated_iat = ceil(1000.0 / (prod_rate / packet_size));

    uint64_t rtt = state_->getRTT();
    if (rtt == 0) rtt = SENTINEL_TIMER_INTERVAL;
    wait = rtt;

    if (estimated_iat > rtt) wait = estimated_iat;

    uint32_t jitter = ceil(state_->getJitter());
    wait += jitter;

    // it may happen that the channel is congested and we have some additional
    // queuing delay to take into account
    uint32_t queue = ceil(state_->getQueuing());
    wait += queue;

    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "next rtx for " << seq << " in " << wait
        << " ms, rtt = " << state_->getRTT() << " ait = " << estimated_iat
        << " jttr = " << jitter << " queue = " << queue;

    return now + wait;
  }
}

void RTCLossDetectionAndRecovery::retransmit() {
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

void RTCLossDetectionAndRecovery::scheduleNextRtx() {
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
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  uint64_t wait = 1;
  if (next_rtx_timer_ != MAX_TIMER_RTX && next_rtx_timer_ > now)
    wait = next_rtx_timer_ - now;

  std::weak_ptr<RTCLossDetectionAndRecovery> self(shared_from_this());
  timer_->expires_from_now(std::chrono::milliseconds(wait));
  timer_->async_wait([self](std::error_code ec) {
    if (ec) return;
    if (auto s = self.lock()) {
      s->retransmit();
      s->next_rtx_timer_ = MAX_TIMER_RTX;
      s->scheduleNextRtx();
    }
  });
}

bool RTCLossDetectionAndRecovery::deleteRtx(uint32_t seq) {
  auto it_rtx = rtx_state_.find(seq);
  if (it_rtx == rtx_state_.end()) return false;  // rtx not found

  uint64_t ts = it_rtx->second.next_send_;
  auto it_timers = rtx_timers_.find(ts);
  while (it_timers != rtx_timers_.end() && it_timers->first == ts) {
    if (it_timers->second == seq) {
      rtx_timers_.erase(it_timers);
      break;
    }
    it_timers++;
  }

  bool lost = it_rtx->second.rtx_count_ > 0;
  rtx_state_.erase(it_rtx);

  return lost;
}

void RTCLossDetectionAndRecovery::scheduleSentinelTimer(
    uint64_t expires_from_now) {
  std::weak_ptr<RTCLossDetectionAndRecovery> self(shared_from_this());
  sentinel_timer_->expires_from_now(
      std::chrono::milliseconds(expires_from_now));
  sentinel_timer_->async_wait([self](std::error_code ec) {
    if (ec) return;
    if (auto s = self.lock()) {
      s->sentinelTimer();
    }
  });
}

void RTCLossDetectionAndRecovery::sentinelTimer() {
  uint64_t now = getNow();

  bool expired = false;
  bool sent = false;
  if ((now - last_event_) >= sentinel_timer_interval_) {
    // at least a sentinel_timer_interval_ elapsed since last event
    expired = true;
    if (TRANSPORT_EXPECT_FALSE(!state_->isProducerActive())) {
      // this happens at the beginning (or if the producer stops for some
      // reason) we need to keep sending interest 0 until we get an answer
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "sentinel timer: the producer is not active, send packet 0";
      state_->onRetransmission(0);
      send_rtx_callback_(0);
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "sentinel timer: the producer is active, "
                                      "send the 10 oldest packets";
      sent = true;
      uint32_t rtx = 0;
      auto it = state_->getPendingInterestsMapBegin();
      auto end = state_->getPendingInterestsMapEnd();
      while (it != end && rtx < MAX_RTX_WITH_SENTINEL) {
        uint32_t seq = it->first;
        DLOG_IF(INFO, VLOG_IS_ON(3))
            << "sentinel timer, add " << seq << " to the rtx list";
        addToRetransmissions(seq, seq + 1);
        rtx++;
        it++;
      }
    }
  } else {
    // sentinel timer did not expire because we registered at least one event
  }

  uint32_t next_timer;
  double prod_rate = state_->getProducerRate();
  if (TRANSPORT_EXPECT_FALSE(!state_->isProducerActive()) || prod_rate == 0) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "next timer in " << SENTINEL_TIMER_INTERVAL;
    next_timer = SENTINEL_TIMER_INTERVAL;
  } else {
    double prod_rate = state_->getProducerRate();
    double packet_size = state_->getAveragePacketSize();
    uint32_t estimated_iat = ceil(1000.0 / (prod_rate / packet_size));
    uint32_t jitter = ceil(state_->getJitter());

    // try to reduce the number of timers if the estimated IAT is too small
    next_timer = std::max((estimated_iat + jitter) * 20, (uint32_t)1);
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "next sentinel in " << next_timer
        << " ms, rate: " << ((prod_rate * 8.0) / 1000000.0)
        << ", iat: " << estimated_iat << ", jitter: " << jitter;

    if (!expired) {
      // discount the amout of time that is already passed
      uint32_t discount = now - last_event_;
      if (next_timer > discount) {
        next_timer = next_timer - discount;
      } else {
        // in this case we trigger the timer in 1 ms
        next_timer = 1;
      }
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "timer after discout: " << next_timer;
    } else if (sent) {
      // wait at least one producer stats interval + owd to check if the
      // production rate is reducing.
      uint32_t min_wait = PRODUCER_STATS_INTERVAL + ceil(state_->getQueuing());
      next_timer = std::max(next_timer, min_wait);
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "wait for updates from prod, next timer: " << next_timer;
    }
  }

  scheduleSentinelTimer(next_timer);
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
