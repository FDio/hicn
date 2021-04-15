/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <implementation/socket_consumer.h>
#include <math.h>
#include <protocols/rtc/rtc.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_rc_frame.h>
#include <protocols/rtc/rtc_rc_queue.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(
    implementation::ConsumerSocket *icn_socket)
    : TransportProtocol(icn_socket, nullptr),
      DatagramReassembly(icn_socket, this),
      number_(0) {
  icn_socket->getSocketOption(PORTAL, portal_);
  round_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  scheduler_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getIoService());
}

RTCTransportProtocol::~RTCTransportProtocol() {}

void RTCTransportProtocol::resume() {
  if (is_running_) return;

  is_running_ = true;

  newRound();
  scheduleNextInterests();

  portal_->runEventsLoop();
  is_running_ = false;
}

// private
void RTCTransportProtocol::initParams() {
  portal_->setConsumerCallback(this);

  rc_ = std::make_shared<RTCRateControlQueue>();
  ldr_ = std::make_shared<RTCLossDetectionAndRecovery>(
      std::bind(&RTCTransportProtocol::sendRtxInterest, this,
                std::placeholders::_1),
      portal_->getIoService());

  state_ = std::make_shared<RTCState>(
      std::bind(&RTCTransportProtocol::sendProbeInterest, this,
                std::placeholders::_1),
      portal_->getIoService());

  rc_->setState(state_);
  // TODO: for the moment we keep the congestion control disabled
  // rc_->tunrOnRateControl();
  ldr_->setState(state_);

  // protocol state
  current_state_ = SyncState::catch_up;

  // Cancel timer
  number_++;
  round_timer_->cancel();
  scheduler_timer_->cancel();
  scheduler_timer_on_ = false;

  // delete all timeouts and future nacks
  timeouts_or_nacks_.clear();

  // cwin vars
  current_sync_win_ = INITIAL_WIN;
  max_sync_win_ = INITIAL_WIN_MAX;

  // names/packets var
  next_segment_ = 0;

  socket_->setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           RTC_INTEREST_LIFETIME);
}

// private
void RTCTransportProtocol::reset() {
  TRANSPORT_LOGD("reset called");
  initParams();
  newRound();
}

void RTCTransportProtocol::inactiveProducer() {
  // when the producer is inactive we reset the consumer state
  // cwin vars
  current_sync_win_ = INITIAL_WIN;
  max_sync_win_ = INITIAL_WIN_MAX;

  TRANSPORT_LOGD("Current window: %u, max_sync_win_: %u", current_sync_win_,
                 max_sync_win_);

  // names/packets var
  next_segment_ = 0;

  ldr_->clear();
}

void RTCTransportProtocol::newRound() {
  round_timer_->expires_from_now(std::chrono::milliseconds(ROUND_LEN));
  // TODO pass weak_ptr here
  round_timer_->async_wait([this, n{number_}](std::error_code ec) {
    if (ec) return;

    if (n != number_) {
      return;
    }

    // saving counters that will be reset on new round
    uint32_t sent_retx = state_->getSentRtxInRound();
    uint32_t received_bytes = state_->getReceivedBytesInRound();
    uint32_t sent_interest = state_->getSentInterestInRound();
    uint32_t lost_data = state_->getLostData();
    uint32_t recovered_losses = state_->getRecoveredLosses();
    uint32_t received_nacks = state_->getReceivedNacksInRound();

    bool in_sync = (current_state_ == SyncState::in_sync);
    state_->onNewRound((double)ROUND_LEN, in_sync);
    rc_->onNewRound((double)ROUND_LEN);

    // update sync state if needed
    if (current_state_ == SyncState::in_sync) {
      double cache_rate = state_->getPacketFromCacheRatio();
      if (cache_rate > MAX_DATA_FROM_CACHE) {
        current_state_ = SyncState::catch_up;
      }
    } else {
      double target_rate = state_->getProducerRate() * PRODUCTION_RATE_FRACTION;
      double received_rate = state_->getReceivedRate();
      uint32_t round_without_nacks = state_->getRoundsWithoutNacks();
      double cache_ratio = state_->getPacketFromCacheRatio();
      if (round_without_nacks >= ROUNDS_IN_SYNC_BEFORE_SWITCH &&
          received_rate >= target_rate && cache_ratio < MAX_DATA_FROM_CACHE) {
        current_state_ = SyncState::in_sync;
      }
    }

    TRANSPORT_LOGD("Calling updateSyncWindow in newRound function");
    updateSyncWindow();

    sendStatsToApp(sent_retx, received_bytes, sent_interest, lost_data,
                   recovered_losses, received_nacks);
    newRound();
  });
}

void RTCTransportProtocol::computeMaxSyncWindow() {
  double production_rate = state_->getProducerRate();
  double packet_size = state_->getAveragePacketSize();
  if (production_rate == 0.0 || packet_size == 0.0) {
    // the consumer has no info about the producer,
    // keep the previous maxCWin
    TRANSPORT_LOGD(
        "Returning in computeMaxSyncWindow because: prod_rate: %d || "
        "packet_size: %d",
        (int)(production_rate == 0.0), (int)(packet_size == 0.0));
    return;
  }

  uint32_t lifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           lifetime);
  double lifetime_ms = (double)lifetime / MILLI_IN_A_SEC;

  double factor = INTEREST_LIFETIME_REDUCTION_FACTOR;
  if (current_state_ == SyncState::catch_up)
    factor = INTEREST_LIFETIME_INCREASE_FACTOR;

  max_sync_win_ =
      (uint32_t)ceil((production_rate * lifetime_ms * factor) / packet_size);

  max_sync_win_ = std::min(max_sync_win_, rc_->getCongesionWindow());
}

void RTCTransportProtocol::updateSyncWindow() {
  computeMaxSyncWindow();

  if (max_sync_win_ == INITIAL_WIN_MAX) {
    if (TRANSPORT_EXPECT_FALSE(!state_->isProducerActive())) return;

    current_sync_win_ = INITIAL_WIN;
    scheduleNextInterests();
    return;
  }

  if (current_state_ == SyncState::catch_up) {
    current_sync_win_ = max_sync_win_;
    scheduleNextInterests();
    return;
  }

  double prod_rate = state_->getProducerRate();
  double rtt = (double)state_->getRTT() / MILLI_IN_A_SEC;
  double packet_size = state_->getAveragePacketSize();

  // if some of the info are not available do not update the current win
  if (prod_rate != 0.0 && rtt != 0.0 && packet_size != 0.0) {
    current_sync_win_ = (uint32_t)ceil(prod_rate * rtt / packet_size);
    current_sync_win_ +=
        ceil(prod_rate * (PRODUCER_BUFFER_MS / MILLI_IN_A_SEC) / packet_size);

    current_sync_win_ = std::min(current_sync_win_, max_sync_win_);
    current_sync_win_ = std::max(current_sync_win_, WIN_MIN);
  }

  scheduleNextInterests();
}

void RTCTransportProtocol::decreaseSyncWindow() {
  // called on future nack
  // we have a new sample of the production rate, so update max win first
  computeMaxSyncWindow();
  current_sync_win_--;
  current_sync_win_ = std::max(current_sync_win_, WIN_MIN);
  scheduleNextInterests();
}

void RTCTransportProtocol::sendInterest(Name *interest_name) {
  TRANSPORT_LOGD("Sending interest for name %s",
                 interest_name->toString().c_str());

  auto interest = core::PacketManager<>::getInstance().getPacket<Interest>();
  interest->setName(*interest_name);

  uint32_t lifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           lifetime);
  interest->setLifetime(uint32_t(lifetime));

  if (*on_interest_output_) {
    (*on_interest_output_)(*socket_->getInterface(), *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_ && !is_first_)) {
    return;
  }

  portal_->sendInterest(std::move(interest));
}

void RTCTransportProtocol::sendRtxInterest(uint32_t seq) {
  if (!is_running_ && !is_first_) return;

  Name *interest_name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           &interest_name);

  interest_name->setSuffix(seq);
  sendInterest(interest_name);
}

void RTCTransportProtocol::sendProbeInterest(uint32_t seq) {
  if (!is_running_ && !is_first_) return;

  Name *interest_name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           &interest_name);

  interest_name->setSuffix(seq);
  sendInterest(interest_name);
}

void RTCTransportProtocol::scheduleNextInterests() {
  TRANSPORT_LOGD("Schedule next interests");

  if (!is_running_ && !is_first_) return;

  if (scheduler_timer_on_) return;  // wait befor send other interests

  if (TRANSPORT_EXPECT_FALSE(!state_->isProducerActive())) {
    TRANSPORT_LOGD("Inactive producer.");
    // here we keep seding the same interest until the producer
    // does not start again
    if (next_segment_ != 0) {
      // the producer just become inactive, reset the state
      inactiveProducer();
    }

    Name *interest_name = nullptr;
    socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                             &interest_name);

    interest_name->setSuffix(next_segment_);

    if (portal_->interestIsPending(*interest_name)) {
      // if interest 0 is already pending we return
      return;
    }

    sendInterest(interest_name);
    state_->onSendNewInterest(interest_name);
    return;
  }

  TRANSPORT_LOGD("Pending interest number: %d -- current_sync_win_: %d",
                 state_->getPendingInterestNumber(), current_sync_win_);

  // skip nacked pacekts
  if (next_segment_ <= state_->getLastSeqNacked()) {
    next_segment_ = state_->getLastSeqNacked() + 1;
  }

  // skipe received packets
  if (next_segment_ <= state_->getHighestSeqReceivedInOrder()) {
    next_segment_ = state_->getHighestSeqReceivedInOrder() + 1;
  }

  uint32_t sent_interests = 0;
  while ((state_->getPendingInterestNumber() < current_sync_win_) &&
         (sent_interests < MAX_INTERESTS_IN_BATCH)) {
    TRANSPORT_LOGD("In while loop. Window size: %u", current_sync_win_);
    Name *interest_name = nullptr;
    socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                             &interest_name);

    interest_name->setSuffix(next_segment_);

    // send the packet only if:
    // 1) it is not pending yet (not true for rtx)
    // 2) the packet is not received or lost
    // 3) is not in the rtx list
    if (portal_->interestIsPending(*interest_name) ||
        state_->isReceivedOrLost(next_segment_) != PacketState::UNKNOWN ||
        ldr_->isRtx(next_segment_)) {
      TRANSPORT_LOGD(
          "skip interest %u because: pending %u, recv %u, rtx %u",
          next_segment_, (portal_->interestIsPending(*interest_name)),
          (state_->isReceivedOrLost(next_segment_) != PacketState::UNKNOWN),
          (ldr_->isRtx(next_segment_)));
      next_segment_ = (next_segment_ + 1) % MIN_PROBE_SEQ;
      continue;
    }

    TRANSPORT_LOGD("Send content interest %u (scheduleNextInterests)",
                   interest_name->getSuffix());

    sent_interests++;
    sendInterest(interest_name);
    state_->onSendNewInterest(interest_name);

    next_segment_ = (next_segment_ + 1) % MIN_PROBE_SEQ;
  }

  if (state_->getPendingInterestNumber() < current_sync_win_) {
    // we still have space in the window but we already sent a batch of
    // MAX_INTERESTS_IN_BATCH interest. for the following ones wait one
    // WAIT_BETWEEN_INTEREST_BATCHES to avoid local packets drop

    scheduler_timer_on_ = true;
    scheduler_timer_->expires_from_now(
        std::chrono::microseconds(WAIT_BETWEEN_INTEREST_BATCHES));
    scheduler_timer_->async_wait([this](std::error_code ec) {
      if (ec) return;
      if (!scheduler_timer_on_) return;

      scheduler_timer_on_ = false;
      scheduleNextInterests();
    });
  }
}

void RTCTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  uint32_t segment_number = interest->getName().getSuffix();

  TRANSPORT_LOGD("timeout for packet  %u", segment_number);

  if (segment_number >= MIN_PROBE_SEQ) {
    // this is a timeout on a probe, do nothing
    return;
  }

  timeouts_or_nacks_.insert(segment_number);

  if (TRANSPORT_EXPECT_TRUE(state_->isProducerActive()) &&
      segment_number <= state_->getHighestSeqReceivedInOrder()) {
    // we retransmit packets only if the producer is active, otherwise we
    // use timeouts to avoid to send too much traffic
    //
    // a timeout is sent using RTX only if it is an old packet. if it is for a
    // seq number that we didn't reach yet, we send the packet using the normal
    // schedule next interest
    TRANSPORT_LOGD("handle timeout for packet  %u using rtx", segment_number);
    ldr_->onTimeout(segment_number);
    state_->onTimeout(segment_number);
    scheduleNextInterests();
    return;
  }

  TRANSPORT_LOGD("handle timeout for packet  %u using normal interests",
                 segment_number);

  if (segment_number < next_segment_) {
    // this is a timeout for a packet that will be generated in the future but
    // we are asking for higher sequence numbers. we need to go back like in the
    // case of future nacks
    next_segment_ = segment_number;
  }

  state_->onTimeout(segment_number);
  scheduleNextInterests();
}

void RTCTransportProtocol::onNack(const ContentObject &content_object) {
  struct nack_packet_t *nack =
      (struct nack_packet_t *)content_object.getPayload()->data();
  uint32_t production_seg = nack->getProductionSegement();
  uint32_t nack_segment = content_object.getName().getSuffix();
  bool is_rtx = ldr_->isRtx(nack_segment);

  // check if the packet got a timeout

  TRANSPORT_LOGD("Nack received %u. Production segment: %u", nack_segment,
                 production_seg);

  bool compute_stats = true;
  auto tn_it = timeouts_or_nacks_.find(nack_segment);
  if (tn_it != timeouts_or_nacks_.end() || is_rtx) {
    compute_stats = false;
    // remove packets from timeouts_or_nacks only in case of a past nack
  }

  state_->onNackPacketReceived(content_object, compute_stats);
  ldr_->onNackPacketReceived(content_object);

  // both in case of past and future nack we set next_segment_ equal to the
  // production segment in the nack. In case of past nack we will skip unneded
  // interest (this is already done in the scheduleNextInterest in any case)
  // while in case of future nacks we can go back in time and ask again for the
  // content that generated the nack
  next_segment_ = production_seg;

  if (production_seg > nack_segment) {
    // remove the nack is it exists
    if (tn_it != timeouts_or_nacks_.end()) timeouts_or_nacks_.erase(tn_it);

    // the client is asking for content in the past
    // switch to catch up state and increase the window
    // this is true only if the packet is not an RTX
    if (!is_rtx) current_state_ = SyncState::catch_up;

    updateSyncWindow();
  } else {
    // if production_seg == nack_segment we consider this a future nack, since
    // production_seg is not yet created. this may happen in case of low
    // production rate (e.g. ping at 1pps)

    // if a future nack was also retransmitted add it to the timeout_or_nacks
    // set
    if (is_rtx) timeouts_or_nacks_.insert(nack_segment);

    // the client is asking for content in the future
    // switch to in sync state and decrease the window
    current_state_ = SyncState::in_sync;
    decreaseSyncWindow();
  }
}

void RTCTransportProtocol::onProbe(const ContentObject &content_object) {
  struct nack_packet_t *probe =
      (struct nack_packet_t *)content_object.getPayload()->data();
  uint32_t production_seg = probe->getProductionSegement();

  // as for the nacks set next_segment_
  next_segment_ = production_seg;

  state_->onProbePacketReceived(content_object);
  ldr_->onProbePacketReceived(content_object);
  updateSyncWindow();
}

void RTCTransportProtocol::onContentObject(Interest &interest,
                                           ContentObject &content_object) {
  TRANSPORT_LOGD("Received content object of size: %zu",
                 content_object.payloadSize());
  uint32_t payload_size = content_object.payloadSize();
  uint32_t segment_number = content_object.getName().getSuffix();

  if (segment_number >= MIN_PROBE_SEQ) {
    TRANSPORT_LOGD("Received probe %u", segment_number);
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onProbe(content_object);
    return;
  }

  if (payload_size == NACK_HEADER_SIZE) {
    TRANSPORT_LOGD("Received nack %u", segment_number);
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onNack(content_object);
    return;
  }

  TRANSPORT_LOGD("Received content %u", segment_number);

  rc_->onDataPacketReceived(content_object);
  bool compute_stats = true;
  auto tn_it = timeouts_or_nacks_.find(segment_number);
  if (tn_it != timeouts_or_nacks_.end()) {
    compute_stats = false;
    timeouts_or_nacks_.erase(tn_it);
  }
  if (ldr_->isRtx(segment_number)) {
    compute_stats = false;
  }

  // check if the packet was already received
  PacketState state = state_->isReceivedOrLost(segment_number);
  state_->onDataPacketReceived(content_object, compute_stats);
  ldr_->onDataPacketReceived(content_object);

  // if the stat for this seq number is received do not send the packet to app
  if (state != PacketState::RECEIVED) {
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    reassemble(content_object);
  } else {
    TRANSPORT_LOGD("Received duplicated content %u, drop it", segment_number);
  }

  updateSyncWindow();
}

void RTCTransportProtocol::sendStatsToApp(
    uint32_t retx_count, uint32_t received_bytes, uint32_t sent_interests,
    uint32_t lost_data, uint32_t recovered_losses, uint32_t received_nacks) {
  if (*stats_summary_) {
    // Send the stats to the app
    stats_->updateQueuingDelay(state_->getQueuing());

    // stats_->updateInterestFecTx(0); //todo must be implemented
    // stats_->updateBytesFecRecv(0); //todo must be implemented

    stats_->updateRetxCount(retx_count);
    stats_->updateBytesRecv(received_bytes);
    stats_->updateInterestTx(sent_interests);
    stats_->updateReceivedNacks(received_nacks);

    stats_->updateAverageWindowSize(current_sync_win_);
    stats_->updateLossRatio(state_->getLossRate());
    stats_->updateAverageRtt(state_->getRTT());
    stats_->updateLostData(lost_data);
    stats_->updateRecoveredData(recovered_losses);
    stats_->updateCCState((unsigned int)current_state_ ? 1 : 0);
    (*stats_summary_)(*socket_->getInterface(), *stats_);
  }
}

void RTCTransportProtocol::reassemble(ContentObject &content_object) {
  auto read_buffer = content_object.getPayload();
  TRANSPORT_LOGD("Size of payload: %zu", read_buffer->length());
  read_buffer->trimStart(DATA_HEADER_SIZE);
  Reassembly::read_buffer_ = std::move(read_buffer);
  Reassembly::notifyApplication();
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
