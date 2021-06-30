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
#include <protocols/errors.h>
#include <protocols/incremental_indexer_bytestream.h>
#include <protocols/rtc/rtc.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_indexer.h>
#include <protocols/rtc/rtc_rc_queue.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(
    implementation::ConsumerSocket *icn_socket)
    : TransportProtocol(icn_socket, new RtcIndexer<>(icn_socket, this),
                        new DatagramReassembly(icn_socket, this)),
      number_(0) {
  icn_socket->getSocketOption(PORTAL, portal_);
  round_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  scheduler_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getIoService());
  pacing_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
}

RTCTransportProtocol::~RTCTransportProtocol() {}

void RTCTransportProtocol::resume() {
  newRound();
  TransportProtocol::resume();
}

std::size_t RTCTransportProtocol::transportHeaderLength() {
  return DATA_HEADER_SIZE +
         (fec_decoder_ != nullptr ? fec_decoder_->getFecHeaderSize() : 0);
}

// private
void RTCTransportProtocol::initParams() {
  TransportProtocol::reset();

  rc_ = std::make_shared<RTCRateControlQueue>();
  ldr_ = std::make_shared<RTCLossDetectionAndRecovery>(
      indexer_verifier_.get(),
      std::bind(&RTCTransportProtocol::sendRtxInterest, this,
                std::placeholders::_1),
      portal_->getIoService());

  state_ = std::make_shared<RTCState>(
      indexer_verifier_.get(),
      std::bind(&RTCTransportProtocol::sendProbeInterest, this,
                std::placeholders::_1),
      std::bind(&RTCTransportProtocol::discoveredRtt, this),
      portal_->getIoService());

  rc_->setState(state_);
  // TODO: for the moment we keep the congestion control disabled
  // rc_->tunrOnRateControl();
  ldr_->setState(state_);

  // protocol state
  start_send_interest_ = false;
  current_state_ = SyncState::catch_up;

  // Cancel timer
  number_++;
  round_timer_->cancel();

  scheduler_timer_->cancel();
  scheduler_timer_on_ = false;
  last_interest_sent_time_ = 0;
  last_interest_sent_seq_ = 0;

#if 0
  if(portal_->isConnectedToFwd()){
    max_aggregated_interest_ = 1;
  }else{
    max_aggregated_interest_ = MAX_INTERESTS_IN_BATCH;
  }
#else
  max_aggregated_interest_ = 1;
#endif

  max_sent_int_ =
      std::ceil((double)MAX_PACING_BATCH / (double)max_aggregated_interest_);

  pacing_timer_->cancel();
  pacing_timer_on_ = false;

  // delete all timeouts and future nacks
  timeouts_or_nacks_.clear();

  // cwin vars
  current_sync_win_ = INITIAL_WIN;
  max_sync_win_ = INITIAL_WIN_MAX;

  socket_->setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           RTC_INTEREST_LIFETIME);

  // FEC
  using namespace std::placeholders;
  enableFEC(std::bind(&RTCTransportProtocol::onFecPackets, this, _1),
            /* We leave the buffer allocation to the fec decoder */
            fec::FECBase::BufferRequested(0));

  if (fec_decoder_) {
    indexer_verifier_->enableFec(fec_type_);
    indexer_verifier_->setNFec(0);
    ldr_->setFecParams(fec::FECUtils::getBlockSymbols(fec_type_),
                       fec::FECUtils::getSourceSymbols(fec_type_));
  } else {
    indexer_verifier_->disableFec();
  }
}

// private
void RTCTransportProtocol::reset() {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "reset called";
  initParams();
  newRound();
}

void RTCTransportProtocol::inactiveProducer() {
  // when the producer is inactive we reset the consumer state
  // cwin vars
  current_sync_win_ = INITIAL_WIN;
  max_sync_win_ = INITIAL_WIN_MAX;

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Current window: " << current_sync_win_
                               << ", max_sync_win_: " << max_sync_win_;

  // names/packets var
  indexer_verifier_->reset();
  indexer_verifier_->enableFec(fec_type_);
  indexer_verifier_->setNFec(0);

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
    uint32_t definitely_lost = state_->getDefinitelyLostPackets();
    uint32_t recovered_losses = state_->getRecoveredLosses();
    uint32_t received_nacks = state_->getReceivedNacksInRound();
    uint32_t received_fec = state_->getReceivedFecPackets();

    bool in_sync = (current_state_ == SyncState::in_sync);
    ldr_->onNewRound(in_sync);
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

    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Calling updateSyncWindow in newRound function";
    updateSyncWindow();

    sendStatsToApp(sent_retx, received_bytes, sent_interest, lost_data,
                   definitely_lost, recovered_losses, received_nacks,
                   received_fec);
    newRound();
  });
}

void RTCTransportProtocol::discoveredRtt() {
  start_send_interest_ = true;
  ldr_->turnOnRTX();
  ldr_->onNewRound(false);
  updateSyncWindow();
}

void RTCTransportProtocol::computeMaxSyncWindow() {
  double production_rate = state_->getProducerRate();
  double packet_size = state_->getAveragePacketSize();
  if (production_rate == 0.0 || packet_size == 0.0) {
    // the consumer has no info about the producer,
    // keep the previous maxCWin
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Returning in computeMaxSyncWindow because: prod_rate: "
        << (production_rate == 0.0)
        << " || packet_size: " << (packet_size == 0.0);
    return;
  }

  production_rate += (production_rate * indexer_verifier_->getMaxFecOverhead());

  uint32_t lifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           lifetime);
  double lifetime_ms = (double)lifetime / MILLI_IN_A_SEC;

  max_sync_win_ = (uint32_t)ceil(
      (production_rate * lifetime_ms * INTEREST_LIFETIME_REDUCTION_FACTOR) /
      packet_size);

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

  double prod_rate = state_->getProducerRate();
  double rtt = (double)state_->getRTT() / MILLI_IN_A_SEC;
  double packet_size = state_->getAveragePacketSize();

  // if some of the info are not available do not update the current win
  if (prod_rate != 0.0 && rtt != 0.0 && packet_size != 0.0) {
    double fec_interest_overhead = (double)state_->getPendingFecPackets() /
                                   (double)(state_->getPendingInterestNumber() -
                                            state_->getPendingFecPackets());

    double fec_overhead =
        std::max(indexer_verifier_->getFecOverhead(), fec_interest_overhead);

    prod_rate += (prod_rate * fec_overhead);

    current_sync_win_ = (uint32_t)ceil(prod_rate * rtt / packet_size);
    uint32_t buffer = PRODUCER_BUFFER_MS;
    if (rtt > 150)
      buffer = buffer * 2;  // if the RTT is too large we increase the
                            // the size of the buffer
    current_sync_win_ +=
        ceil(prod_rate * (buffer / MILLI_IN_A_SEC) / packet_size);

    if (current_state_ == SyncState::catch_up) {
      current_sync_win_ = current_sync_win_ * CATCH_UP_WIN_INCREMENT;
    }

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

void RTCTransportProtocol::sendRtxInterest(uint32_t seq) {
  if (!isRunning() && !is_first_) return;

  if (!start_send_interest_) return;

  Name *interest_name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           &interest_name);

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "send rtx " << seq;
  interest_name->setSuffix(seq);
  sendInterest(*interest_name);
}

void RTCTransportProtocol::sendProbeInterest(uint32_t seq) {
  if (!isRunning() && !is_first_) return;

  Name *interest_name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           &interest_name);

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "send probe " << seq;
  interest_name->setSuffix(seq);
  sendInterest(*interest_name);
}

void RTCTransportProtocol::scheduleNextInterests() {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Schedule next interests";

  if (!isRunning() && !is_first_) return;

  if (pacing_timer_on_) return;  // wait pacing timer for the next send

  if (!start_send_interest_)
    return;  // RTT discovering phase is not finished so
             // do not start to send interests

  if (TRANSPORT_EXPECT_FALSE(!state_->isProducerActive())) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Inactive producer.";
    // here we keep seding the same interest until the producer
    // does not start again
    if (indexer_verifier_->checkNextSuffix() != 0) {
      // the producer just become inactive, reset the state
      inactiveProducer();
    }

    Name *interest_name = nullptr;
    socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                             &interest_name);

    uint32_t next_seg = 0;
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "send interest " << next_seg;
    interest_name->setSuffix(next_seg);

    if (portal_->interestIsPending(*interest_name)) {
      // if interest 0 is already pending we return
      return;
    }

    sendInterest(*interest_name);
    state_->onSendNewInterest(interest_name);
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Pending interest number: " << state_->getPendingInterestNumber()
      << " -- current_sync_win_: " << current_sync_win_;

  uint32_t pending = state_->getPendingInterestNumber();
  if (pending >= current_sync_win_) return;  // no space in the window

  if ((current_sync_win_ - pending) < max_aggregated_interest_) {
    if (scheduler_timer_on_) return;  // timer already scheduled

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();

    uint64_t time = now - last_interest_sent_time_;
    if (time < WAIT_FOR_INTEREST_BATCH) {
      uint64_t next = WAIT_FOR_INTEREST_BATCH - time;
      scheduler_timer_on_ = true;
      scheduler_timer_->expires_from_now(std::chrono::milliseconds(next));
      scheduler_timer_->async_wait([this](std::error_code ec) {
        if (ec) return;
        if (!scheduler_timer_on_) return;

        scheduler_timer_on_ = false;
        scheduleNextInterests();
      });
      return;  // whait for the timer
    }
  }

  scheduler_timer_on_ = false;
  scheduler_timer_->cancel();

  // skip nacked pacekts
  if (indexer_verifier_->checkNextSuffix() <= state_->getLastSeqNacked()) {
    indexer_verifier_->jumpToIndex(state_->getLastSeqNacked() + 1);
  }

  // skipe received packets
  if (indexer_verifier_->checkNextSuffix() <=
      state_->getHighestSeqReceivedInOrder()) {
    indexer_verifier_->jumpToIndex(state_->getHighestSeqReceivedInOrder() + 1);
  }

  uint32_t sent_interests = 0;
  uint32_t sent_packets = 0;
  uint32_t aggregated_counter = 0;
  Name *name = nullptr;
  Name interest_name;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME, &name);
  std::array<uint32_t, MAX_AGGREGATED_INTEREST> additional_suffixes;

  while ((state_->getPendingInterestNumber() < current_sync_win_) &&
         (sent_interests < max_sent_int_)) {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "In while loop. Window size: " << current_sync_win_;

    uint32_t next_seg = indexer_verifier_->getNextSuffix();

    name->setSuffix(next_seg);

    // send the packet only if:
    // 1) it is not pending yet (not true for rtx)
    // 2) the packet is not received or lost
    // 3) is not in the rtx list
    // 4) is fec and is not in order (!= last sent + 1)
    if (portal_->interestIsPending(*name) ||
        state_->isReceivedOrLost(next_seg) != PacketState::UNKNOWN ||
        ldr_->isRtx(next_seg) ||
        (indexer_verifier_->isFec(next_seg) &&
         next_seg != last_interest_sent_seq_ + 1)) {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "skip interest " << next_seg << " because: pending "
          << portal_->interestIsPending(*name) << ", recv "
          << (state_->isReceivedOrLost(next_seg) != PacketState::UNKNOWN)
          << ", rtx " << (ldr_->isRtx(next_seg)) << ", is old fec "
          << ((indexer_verifier_->isFec(next_seg) &&
               next_seg != last_interest_sent_seq_ + 1));
      continue;
    }

    if (aggregated_counter == 0) {
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "(name) send interest " << next_seg;
      interest_name = *name;
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "(append) send interest " << next_seg;
      additional_suffixes[aggregated_counter - 1] = next_seg;
    }

    last_interest_sent_seq_ = next_seg;
    state_->onSendNewInterest(name);
    aggregated_counter++;

    if (aggregated_counter >= max_aggregated_interest_) {
      sent_packets++;
      sent_interests++;
      sendInterest(interest_name, &additional_suffixes, aggregated_counter - 1);
      last_interest_sent_time_ =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count();
      aggregated_counter = 0;
    }
  }

  // exiting the while we may have some pending interest to send
  if (aggregated_counter != 0) {
    sent_packets++;
    last_interest_sent_time_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    sendInterest(interest_name, &additional_suffixes, aggregated_counter - 1);
  }

  if (state_->getPendingInterestNumber() < current_sync_win_) {
    // we still have space in the window but we already sent too many packets
    // wait PACING_WAIT to avoid drops in the kernel

    pacing_timer_on_ = true;
    pacing_timer_->expires_from_now(std::chrono::microseconds(PACING_WAIT));
    scheduler_timer_->async_wait([this](std::error_code ec) {
      if (ec) return;
      if (!pacing_timer_on_) return;

      pacing_timer_on_ = false;
      scheduleNextInterests();
    });
  }
}

void RTCTransportProtocol::onInterestTimeout(Interest::Ptr &interest,
                                             const Name &name) {
  uint32_t segment_number = name.getSuffix();

  if (segment_number >= MIN_PROBE_SEQ) {
    // this is a timeout on a probe, do nothing
    return;
  }

  PacketState state = state_->isReceivedOrLost(segment_number);
  if (state != PacketState::UNKNOWN) {
    // we may recover a packets using fec, ignore this timer
    return;
  }

  timeouts_or_nacks_.insert(segment_number);

  if (TRANSPORT_EXPECT_TRUE(state_->isProducerActive()) &&
      segment_number <= state_->getHighestSeqReceived()) {
    // we retransmit packets only if the producer is active, otherwise we
    // use timeouts to avoid to send too much traffic
    //
    // a timeout is sent using RTX only if it is an old packet. if it is for a
    // seq number that we didn't reach yet, we send the packet using the normal
    // schedule next interest
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "handle timeout for packet  " << segment_number << " using rtx";
    if (ldr_->isRtxOn()) {
      ldr_->onTimeout(segment_number);
      if (indexer_verifier_->isFec(segment_number))
        state_->onTimeout(segment_number, true);
      else
        state_->onTimeout(segment_number, false);
    } else {
      // in this case we wil never recover the timeout
      state_->onTimeout(segment_number, true);
    }
    scheduleNextInterests();
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "handle timeout for packet " << segment_number
                               << " using normal interests";

  if (segment_number < indexer_verifier_->checkNextSuffix()) {
    // this is a timeout for a packet that will be generated in the future but
    // we are asking for higher sequence numbers. we need to go back like in the
    // case of future nacks
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "On timeout next seg = " << indexer_verifier_->checkNextSuffix()
        << ", jump to " << segment_number;
    // add an extra space in the window
    current_sync_win_++;
    indexer_verifier_->jumpToIndex(segment_number);
  }

  state_->onTimeout(segment_number, false);
  scheduleNextInterests();
}

void RTCTransportProtocol::onNack(const ContentObject &content_object) {
  struct nack_packet_t *nack =
      (struct nack_packet_t *)content_object.getPayload()->data();
  uint32_t production_seg = nack->getProductionSegement();
  uint32_t nack_segment = content_object.getName().getSuffix();
  bool is_rtx = ldr_->isRtx(nack_segment);

  // check if the packet got a timeout

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Nack received " << nack_segment
                               << ". Production segment: " << production_seg;

  bool compute_stats = true;
  auto tn_it = timeouts_or_nacks_.find(nack_segment);
  if (tn_it != timeouts_or_nacks_.end() || is_rtx) {
    compute_stats = false;
    // remove packets from timeouts_or_nacks only in case of a past nack
  }

  state_->onNackPacketReceived(content_object, compute_stats);
  ldr_->onNackPacketReceived(content_object);

  // both in case of past and future nack we jump to the
  // production segment in the nack. In case of past nack we will skip unneded
  // interest (this is already done in the scheduleNextInterest in any case)
  // while in case of future nacks we can go back in time and ask again for the
  // content that generated the nack
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "On nack next seg = " << indexer_verifier_->checkNextSuffix()
      << ", jump to " << production_seg;
  indexer_verifier_->jumpToIndex(production_seg);

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
  bool valid = state_->onProbePacketReceived(content_object);
  if (!valid) return;

  struct nack_packet_t *probe =
      (struct nack_packet_t *)content_object.getPayload()->data();
  uint32_t production_seg = probe->getProductionSegement();

  // as for the nacks set next_segment
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "on probe next seg = " << indexer_verifier_->checkNextSuffix()
      << ", jump to " << production_seg;
  indexer_verifier_->jumpToIndex(production_seg);

  ldr_->onProbePacketReceived(content_object);
  updateSyncWindow();
}

void RTCTransportProtocol::onContentObjectReceived(
    Interest &interest, ContentObject &content_object, std::error_code &ec) {
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Received content object of size: " << content_object.payloadSize();
  uint32_t payload_size = content_object.payloadSize();
  uint32_t segment_number = content_object.getName().getSuffix();

  ec = make_error_code(protocol_error::not_reassemblable);

  if (segment_number >= MIN_PROBE_SEQ) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received probe " << segment_number;
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onProbe(content_object);
    return;
  }

  if (payload_size == NACK_HEADER_SIZE) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received nack " << segment_number;
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onNack(content_object);
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received content " << segment_number;

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

  if (state != PacketState::RECEIVED) {
    // send packet to decoder
    if (fec_decoder_) {
      DLOG_IF(INFO, VLOG_IS_ON(4))
          << "send packet " << segment_number << " to FEC decoder";
      fec_decoder_->onDataPacket(
          content_object, content_object.headerSize() + rtc::DATA_HEADER_SIZE);
    }
    if (!indexer_verifier_->isFec(segment_number)) {
      // the packet may be alredy sent to the ap by the decoder, check again if
      // it is already received
      state = state_->isReceivedOrLost(segment_number);
      if (state != PacketState::RECEIVED) {
        DLOG_IF(INFO, VLOG_IS_ON(4)) << "Received content " << segment_number;

        state_->onDataPacketReceived(content_object, compute_stats);

        if (*on_content_object_input_) {
          (*on_content_object_input_)(*socket_->getInterface(), content_object);
        }
        ec = make_error_code(protocol_error::success);
      }
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(4)) << "Received fec " << segment_number;
      state_->onFecPacketReceived(content_object);
    }
  } else {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Received duplicated content " << segment_number << ", drop it";
    ec = make_error_code(protocol_error::duplicated_content);
  }

  ldr_->onDataPacketReceived(content_object);
  rc_->onDataPacketReceived(content_object);

  updateSyncWindow();
}

void RTCTransportProtocol::sendStatsToApp(
    uint32_t retx_count, uint32_t received_bytes, uint32_t sent_interests,
    uint32_t lost_data, uint32_t definitely_lost, uint32_t recovered_losses,
    uint32_t received_nacks, uint32_t received_fec) {
  if (*stats_summary_) {
    // Send the stats to the app
    stats_->updateQueuingDelay(state_->getQueuing());

    // stats_->updateInterestFecTx(0); //todo must be implemented
    // stats_->updateBytesFecRecv(0); //todo must be implemented

    stats_->updateRetxCount(retx_count);
    stats_->updateBytesRecv(received_bytes);
    stats_->updateInterestTx(sent_interests);
    stats_->updateReceivedNacks(received_nacks);
    stats_->updateReceivedFEC(received_fec);

    stats_->updateAverageWindowSize(current_sync_win_);
    stats_->updateLossRatio(state_->getLossRate());
    stats_->updateAverageRtt(state_->getRTT());
    stats_->updateQueuingDelay(state_->getQueuing());
    stats_->updateLostData(lost_data);
    stats_->updateDefinitelyLostData(definitely_lost);
    stats_->updateRecoveredData(recovered_losses);
    stats_->updateCCState((unsigned int)current_state_ ? 1 : 0);
    (*stats_summary_)(*socket_->getInterface(), *stats_);
  }
}

void RTCTransportProtocol::onFecPackets(
    std::vector<std::pair<uint32_t, fec::buffer>> &packets) {
  for (auto &packet : packets) {
    PacketState state = state_->isReceivedOrLost(packet.first);
    if (state != PacketState::RECEIVED) {
      state_->onPacketRecoveredFec(packet.first);
      ldr_->onPacketRecoveredFec(packet.first);
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Recovered packet " << packet.first << " through FEC.";
      reassembly_->reassemble(*packet.second, packet.first);
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Packet" << packet.first << "already received.";
    }
  }
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
