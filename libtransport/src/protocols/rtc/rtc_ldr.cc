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

#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_ldr.h>

#include <algorithm>
#include <unordered_set>

namespace transport {

namespace protocol {

namespace rtc {

RTCLossDetectionAndRecovery::RTCLossDetectionAndRecovery(
    SendRtxCallback &&callback, asio::io_service &io_service)
    : rtx_on_(false),
      next_rtx_timer_(MAX_TIMER_RTX),
      last_event_(0),
      sentinel_timer_interval_(MAX_TIMER_RTX),
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

void RTCLossDetectionAndRecovery::onTimeout(uint32_t seq) {
  // always add timeouts to the RTX list to avoid to send the same packet as if
  // it was not a rtx
  addToRetransmissions(seq, seq + 1);
  last_event_ = getNow();
}

void RTCLossDetectionAndRecovery::onDataPacketReceived(
    const core::ContentObject &content_object) {
  last_event_ = getNow();

  uint32_t seq = content_object.getName().getSuffix();
  if (deleteRtx(seq)) {
    state_->onPacketRecovered(seq);
  } else {
    if (TRANSPORT_EXPECT_FALSE(!rtx_on_)) return;  // do not add if RTX is off
    TRANSPORT_LOGD("received data. add from %u to %u ",
                   state_->getHighestSeqReceivedInOrder() + 1, seq);
    addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1, seq);
  }
}

void RTCLossDetectionAndRecovery::onNackPacketReceived(
    const core::ContentObject &nack) {
  last_event_ = getNow();

  uint32_t seq = nack.getName().getSuffix();

  if (TRANSPORT_EXPECT_FALSE(!rtx_on_)) return;  // do not add if RTX is off

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
    TRANSPORT_LOGD("received past nack. add from %u to %u ",
                   state_->getHighestSeqReceivedInOrder() + 1, production_seq);
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
    TRANSPORT_LOGD("received futrue nack. add from %u to %u ",
                   state_->getHighestSeqReceivedInOrder() + 1, production_seq);
    addToRetransmissions(state_->getHighestSeqReceivedInOrder() + 1,
                         production_seq);
  }
}

void RTCLossDetectionAndRecovery::onProbePacketReceived(
    const core::ContentObject &probe) {
  // we don't log the reception of a probe packet for the sentinel timer because
  // probes are not taken into account into the sync window. we use them as
  // future nacks to detect possible packets lost
  if (TRANSPORT_EXPECT_FALSE(!rtx_on_)) return;  // do not add if RTX is off
  struct nack_packet_t *probe_pkt =
      (struct nack_packet_t *)probe.getPayload()->data();
  uint32_t production_seq = probe_pkt->getProductionSegement();
  TRANSPORT_LOGD("received probe. add from %u to %u ",
                 state_->getHighestSeqReceivedInOrder() + 1, production_seq);
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
    if (!isRtx(seq) &&  // is not already an rtx
                        // is not received or lost
        state_->isReceivedOrLost(seq) == PacketState::UNKNOWN) {
      // add rtx
      rtxState state;
      state.first_send_ = state_->getInterestSentTime(seq);
      if (state.first_send_ == 0)  // this interest was never sent before
        state.first_send_ = getNow();
      state.next_send_ = computeNextSend(seq, true);
      state.rtx_count_ = 0;
      TRANSPORT_LOGD("add %u to retransmissions. next rtx is %lu ", seq,
                     (state.next_send_ - getNow()));
      rtx_state_.insert(std::pair<uint32_t, rtxState>(seq, state));
      rtx_timers_.insert(std::pair<uint64_t, uint32_t>(state.next_send_, seq));
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
    TRANSPORT_LOGD("first rtx for %u in %u ms, rtt = %lu ait = %u jttr = %u",
                   seq, wait, state_->getRTT(), estimated_iat, jitter);

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

    TRANSPORT_LOGD(
        "next rtx for %u in %u ms, rtt = %lu ait = %u jttr = %u queue = %u",
        seq, wait, state_->getRTT(), estimated_iat, jitter, queue);

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
         sent_counter < MAX_INTERESTS_IN_BATCH) {
    uint32_t seq = it->second;
    auto rtx_it =
        rtx_state_.find(seq);  // this should always return a valid iter
    if (rtx_it->second.rtx_count_ >= RTC_MAX_RTX ||
        (now - rtx_it->second.first_send_) >= RTC_MAX_AGE ||
        seq < state_->getLastSeqNacked()) {
      // max rtx reached or packet too old or packet nacked, this packet is lost
      TRANSPORT_LOGD(
          "packet %u lost because 1) max rtx: %u 2) max age: %u 3) naked: %u",
          seq, (rtx_it->second.rtx_count_ >= RTC_MAX_RTX),
          ((now - rtx_it->second.first_send_) >= RTC_MAX_AGE),
          (seq < state_->getLastSeqNacked()));
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
      TRANSPORT_LOGD("send rtx for sequence %u, next send in %lu", seq,
                     (rtx_it->second.next_send_ - now));
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
      TRANSPORT_LOGD(
          "sentinel timer: the producer is not active, send packet 0");
      state_->onRetransmission(0);
      send_rtx_callback_(0);
    } else {
      TRANSPORT_LOGD(
          "sentinel timer: the producer is active, send the 10 oldest packets");
      sent = true;
      uint32_t rtx = 0;
      auto it = state_->getPendingInterestsMapBegin();
      auto end = state_->getPendingInterestsMapEnd();
      while (it != end && rtx < MAX_RTX_WITH_SENTINEL) {
        uint32_t seq = it->first;
        TRANSPORT_LOGD("sentinel timer, add %u to the rtx list", seq);
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
    TRANSPORT_LOGD("next timer in %u", SENTINEL_TIMER_INTERVAL);
    next_timer = SENTINEL_TIMER_INTERVAL;
  } else {
    double prod_rate = state_->getProducerRate();
    double packet_size = state_->getAveragePacketSize();
    uint32_t estimated_iat = ceil(1000.0 / (prod_rate / packet_size));
    uint32_t jitter = ceil(state_->getJitter());

    // try to reduce the number of timers if the estimated IAT is too small
    next_timer = std::max((estimated_iat + jitter) * 20, (uint32_t)1);
    TRANSPORT_LOGD("next sentinel in %u ms, rate: %f, iat: %u, jitter: %u",
                   next_timer, ((prod_rate * 8.0) / 1000000.0), estimated_iat,
                   jitter);

    if (!expired) {
      // discount the amout of time that is already passed
      uint32_t discount = now - last_event_;
      if (next_timer > discount) {
        next_timer = next_timer - discount;
      } else {
        // in this case we trigger the timer in 1 ms
        next_timer = 1;
      }
      TRANSPORT_LOGD("timer after discout: %u", next_timer);
    } else if (sent) {
      // wait at least one producer stats interval + owd to check if the
      // production rate is reducing.
      uint32_t min_wait = PRODUCER_STATS_INTERVAL + ceil(state_->getQueuing());
      next_timer = std::max(next_timer, min_wait);
      TRANSPORT_LOGD("wait for updates from prod, next timer: %u", next_timer);
    }
  }

  scheduleSentinelTimer(next_timer);
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
