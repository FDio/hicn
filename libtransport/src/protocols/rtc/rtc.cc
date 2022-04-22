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

#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <implementation/socket_consumer.h>
#include <math.h>
#include <protocols/errors.h>
#include <protocols/incremental_indexer_bytestream.h>
#include <protocols/rtc/rtc.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_indexer.h>
#include <protocols/rtc/rtc_rc_congestion_detection.h>

#include <algorithm>

namespace transport {

namespace protocol {

namespace rtc {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(
    implementation::ConsumerSocket *icn_socket)
    : TransportProtocol(icn_socket, new RtcIndexer<>(icn_socket, this),
                        new RtcReassembly(icn_socket, this)),
      number_(0) {
  icn_socket->getSocketOption(PORTAL, portal_);
  round_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  scheduler_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  pacing_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
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
  std::weak_ptr<RTCTransportProtocol> self = shared_from_this();

  fwd_strategy_.setCallback([self](notification::Strategy strategy) {
    auto ptr = self.lock();
    if (ptr && ptr->isRunning()) {
      if (*ptr->on_fwd_strategy_) (*ptr->on_fwd_strategy_)(strategy);
    }
  });

  std::shared_ptr<auth::Verifier> verifier;
  socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);

  uint32_t unverified_interval;
  socket_->getSocketOption(GeneralTransportOptions::UNVERIFIED_INTERVAL,
                           unverified_interval);

  double unverified_ratio;
  socket_->getSocketOption(GeneralTransportOptions::UNVERIFIED_RATIO,
                           unverified_ratio);

  rc_ = std::make_shared<RTCRateControlCongestionDetection>();
  ldr_ = std::make_shared<RTCLossDetectionAndRecovery>(
      indexer_verifier_.get(), portal_->getThread().getIoService(),
      interface::RtcTransportRecoveryStrategies::RTX_ONLY,
      [self](uint32_t seq) {
        auto ptr = self.lock();
        if (ptr && ptr->isRunning()) {
          ptr->sendRtxInterest(seq);
        }
      },
      [self](notification::Strategy strategy) {
        auto ptr = self.lock();
        if (ptr && ptr->isRunning()) {
          if (*ptr->on_rec_strategy_) (*ptr->on_rec_strategy_)(strategy);
        }
      });

  verifier_ = std::make_shared<RTCVerifier>(verifier, unverified_interval,
                                            unverified_ratio);

  state_ = std::make_shared<RTCState>(
      indexer_verifier_.get(),
      [self](uint32_t seq) {
        auto ptr = self.lock();
        if (ptr && ptr->isRunning()) {
          ptr->sendProbeInterest(seq);
        }
      },
      [self]() {
        auto ptr = self.lock();
        if (ptr && ptr->isRunning()) {
          ptr->discoveredRtt();
        }
      },
      portal_->getThread().getIoService());

  rc_->setState(state_);
  rc_->turnOnRateControl();
  ldr_->setState(state_.get());
  ldr_->setRateControl(rc_.get());
  verifier_->setState(state_);

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
  if (const char *max_aggr = std::getenv("MAX_AGGREGATED_INTERESTS")) {
    LOG(INFO) << "Max Aggregated: " << max_aggr;
    max_aggregated_interest_ = std::stoul(std::string(max_aggr));
  }
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

  // init state params
  state_->initParams();
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

  std::weak_ptr<RTCTransportProtocol> self = shared_from_this();
  round_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) {
      return;
    }

    auto ptr = self.lock();

    if (!ptr || !ptr->isRunning()) {
      return;
    }

    auto &state = ptr->state_;

    // saving counters that will be reset on new round
    uint32_t sent_retx = state->getSentRtxInRound();
    uint32_t received_bytes =
        (state->getReceivedBytesInRound() +     // data packets received
         state->getReceivedFecBytesInRound());  // fec packets received
    uint32_t sent_interest = state->getSentInterestInRound();
    uint32_t lost_data = state->getLostData();
    uint32_t definitely_lost = state->getDefinitelyLostPackets();
    uint32_t recovered_losses = state->getRecoveredLosses();
    uint32_t received_nacks = state->getReceivedNacksInRound();
    uint32_t received_fec = state->getReceivedFecPackets();

    bool in_sync = (ptr->current_state_ == SyncState::in_sync);
    ptr->ldr_->onNewRound(in_sync);
    ptr->state_->onNewRound((double)ROUND_LEN, in_sync);
    ptr->rc_->onNewRound((double)ROUND_LEN);

    // update sync state if needed
    if (ptr->current_state_ == SyncState::in_sync) {
      double cache_rate = state->getPacketFromCacheRatio();
      if (cache_rate > MAX_DATA_FROM_CACHE) {
        ptr->current_state_ = SyncState::catch_up;
      }
    } else {
      double target_rate = state->getProducerRate() * PRODUCTION_RATE_FRACTION;
      double received_rate =
          state->getReceivedRate() + state->getRecoveredFecRate();
      uint32_t round_without_nacks = state->getRoundsWithoutNacks();
      double cache_ratio = state->getPacketFromCacheRatio();
      if (round_without_nacks >= ROUNDS_IN_SYNC_BEFORE_SWITCH &&
          received_rate >= target_rate && cache_ratio < MAX_DATA_FROM_CACHE) {
        ptr->current_state_ = SyncState::in_sync;
      }
    }

    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Calling updateSyncWindow in newRound function";
    ptr->updateSyncWindow();

    ptr->sendStatsToApp(sent_retx, received_bytes, sent_interest, lost_data,
                        definitely_lost, recovered_losses, received_nacks,
                        received_fec);
    ptr->fwd_strategy_.checkStrategy();
    ptr->newRound();
  });
}

void RTCTransportProtocol::discoveredRtt() {
  start_send_interest_ = true;
  uint32_t strategy;
  socket_->getSocketOption(RtcTransportOptions::RECOVERY_STRATEGY, strategy);
  ldr_->changeRecoveryStrategy(
      (interface::RtcTransportRecoveryStrategies)strategy);
  ldr_->turnOnRecovery();
  ldr_->onNewRound(false);

  // set forwarding strategy switch if selected
  Name *name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME, &name);
  Prefix prefix(*name, 128);
  if ((interface::RtcTransportRecoveryStrategies)strategy ==
      interface::RtcTransportRecoveryStrategies::LOW_RATE_AND_BESTPATH) {
    fwd_strategy_.initFwdStrategy(portal_, prefix, state_.get(),
                                  RTCForwardingStrategy::BEST_PATH);
  } else if ((interface::RtcTransportRecoveryStrategies)strategy ==
             interface::RtcTransportRecoveryStrategies::
                 LOW_RATE_AND_REPLICATION) {
    fwd_strategy_.initFwdStrategy(portal_, prefix, state_.get(),
                                  RTCForwardingStrategy::REPLICATION);
  } else if ((interface::RtcTransportRecoveryStrategies)strategy ==
             interface::RtcTransportRecoveryStrategies::
                 LOW_RATE_AND_ALL_FWD_STRATEGIES) {
    fwd_strategy_.initFwdStrategy(portal_, prefix, state_.get(),
                                  RTCForwardingStrategy::BOTH);
  }

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

  max_sync_win_ = std::min(max_sync_win_, rc_->getCongestionWindow());
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
  double rtt = (double)state_->getMinRTT() / MILLI_IN_A_SEC;
  double packet_size = state_->getAveragePacketSize();

  // if some of the info are not available do not update the current win
  if (prod_rate != 0.0 && rtt != 0.0 && packet_size != 0.0) {
    current_sync_win_ = (uint32_t)ceil(prod_rate * rtt / packet_size);
    uint32_t buffer = PRODUCER_BUFFER_MS;

    current_sync_win_ +=
        ceil(prod_rate * (buffer / MILLI_IN_A_SEC) / packet_size);

    if (current_state_ == SyncState::catch_up) {
      current_sync_win_ = current_sync_win_ * CATCH_UP_WIN_INCREMENT;
    }

    uint32_t min_win = WIN_MIN;
    bool aggregated_data_on;
    socket_->getSocketOption(RtcTransportOptions::AGGREGATED_DATA,
                             aggregated_data_on);
    if (aggregated_data_on) {
      min_win = WIN_MIN_WITH_AGGREGARED_DATA;
      min_win += (min_win * (1 - (std::max(0.3, rtt) - rtt) / 0.3));
    }

    current_sync_win_ = std::min(current_sync_win_, max_sync_win_);
    current_sync_win_ = std::max(current_sync_win_, min_win);
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

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send probe " << seq;
  interest_name->setSuffix(seq);
  sendInterest(*interest_name);
}

void RTCTransportProtocol::scheduleNextInterests() {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Schedule next interests";

  if (!isRunning() && !is_first_) {
    return;
  }

  if (pacing_timer_on_) {
    return;  // wait pacing timer for the next send
  }

  if (!start_send_interest_) {
    return;  // RTT discovering phase is not finished so
             // do not start to send interests
  }

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
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send interest " << next_seg;
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
  uint32_t pending_fec = state_->getPendingFecPackets();

  if ((pending - pending_fec) >= current_sync_win_)
    return;  // no space in the window

  // XXX double check if aggregated interests are still working here
  if ((current_sync_win_ - (pending - pending_fec)) <
      max_aggregated_interest_) {
    if (scheduler_timer_on_) return;  // timer already scheduled

    uint64_t now = utils::SteadyTime::nowMs().count();

    uint64_t time = now - last_interest_sent_time_;
    if (time < WAIT_FOR_INTEREST_BATCH) {
      uint64_t next = WAIT_FOR_INTEREST_BATCH - time;
      scheduler_timer_on_ = true;
      scheduler_timer_->expires_from_now(std::chrono::milliseconds(next));

      std::weak_ptr<RTCTransportProtocol> self = shared_from_this();
      scheduler_timer_->async_wait([self](const std::error_code &ec) {
        if (ec) return;

        auto ptr = self.lock();
        if (ptr && ptr->isRunning()) {
          if (!ptr->scheduler_timer_on_) return;

          ptr->scheduler_timer_on_ = false;
          ptr->scheduleNextInterests();
        }
      });
      return;  // wait for the timer
    }
  }

  scheduler_timer_on_ = false;
  scheduler_timer_->cancel();

  // skip nacked pacekts
  if (indexer_verifier_->checkNextSuffix() <= state_->getLastSeqNacked()) {
    indexer_verifier_->jumpToIndex(state_->getLastSeqNacked() + 1);
  }

  // skip received packets
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

  while (((state_->getPendingInterestNumber() -
           state_->getPendingFecPackets()) < current_sync_win_) &&
         (sent_interests < max_sent_int_)) {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "In while loop. Window size: " << current_sync_win_;

    uint32_t next_seg = indexer_verifier_->getNextSuffix();

    name->setSuffix(next_seg);

    // send the packet only if:
    // 1) it is not pending yet (not true for rtx)
    // 2) the packet is not received or def lost
    // 3) is not in the rtx list
    // 4) is fec and is not in order (!= last sent + 1)
    PacketState packet_state = state_->getPacketState(next_seg);
    if (portal_->interestIsPending(*name) ||
        packet_state == PacketState::RECEIVED ||
        packet_state == PacketState::DEFINITELY_LOST || ldr_->isRtx(next_seg) ||
        (indexer_verifier_->isFec(next_seg) &&
         next_seg != last_interest_sent_seq_ + 1)) {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "skip interest " << next_seg << " because: pending "
          << portal_->interestIsPending(*name) << ", recv or lost"
          << (int)packet_state << ", rtx " << (ldr_->isRtx(next_seg))
          << ", is old fec "
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
      last_interest_sent_time_ = utils::SteadyTime::nowMs().count();
      aggregated_counter = 0;
    }
  }

  // exiting the while we may have some pending interest to send
  if (aggregated_counter != 0) {
    sent_packets++;
    last_interest_sent_time_ = utils::SteadyTime::nowMs().count();
    sendInterest(interest_name, &additional_suffixes, aggregated_counter - 1);
  }

  if ((state_->getPendingInterestNumber() - state_->getPendingFecPackets()) <
      current_sync_win_) {
    // we still have space in the window but we already sent too many packets
    // wait PACING_WAIT to avoid drops in the kernel

    pacing_timer_on_ = true;
    pacing_timer_->expires_from_now(std::chrono::microseconds(PACING_WAIT));

    std::weak_ptr<RTCTransportProtocol> self = shared_from_this();
    scheduler_timer_->async_wait([self](const std::error_code &ec) {
      if (ec) return;

      auto ptr = self.lock();
      if (ptr && ptr->isRunning()) {
        if (!ptr->pacing_timer_on_) return;

        ptr->pacing_timer_on_ = false;
        ptr->scheduleNextInterests();
      }
    });
  }
}

void RTCTransportProtocol::onInterestTimeout(Interest::Ptr &interest,
                                             const Name &name) {
  uint32_t segment_number = name.getSuffix();

  if (ProbeHandler::getProbeType(segment_number) != ProbeType::NOT_PROBE) {
    // this is a timeout on a probe, do nothing
    return;
  }

  PacketState state = state_->getPacketState(segment_number);
  if (state == PacketState::RECEIVED || state == PacketState::DEFINITELY_LOST) {
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
      if (indexer_verifier_->isFec(segment_number)) {
        // if this is a fec packet we do not recover it with rtx so we consider
        // the packet to be lost
        ldr_->onTimeout(segment_number, true);
        state_->onTimeout(segment_number, true);
      } else {
        ldr_->onTimeout(segment_number, false);
        state_->onTimeout(segment_number, false);
      }
    } else {
      // in this case we wil never recover the timeout
      ldr_->onTimeout(segment_number, true);
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
  uint32_t production_seg = nack->getProductionSegment();
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

    state_->onJumpForward(production_seg);
    verifier_->onJumpForward(production_seg);
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
  uint32_t suffix = content_object.getName().getSuffix();
  ParamsRTC params = RTCState::getProbeParams(content_object);

  if (ProbeHandler::getProbeType(suffix) == ProbeType::INIT) {
    fec::FECType fec_type = params.fec_type;

    if (fec_type != fec::FECType::UNKNOWN && !fec_decoder_) {
      // Update FEC type
      fec_type_ = fec_type;

      // Enable FEC
      enableFEC(std::bind(&RTCTransportProtocol::onFecPackets, this,
                          std::placeholders::_1),
                fec::FECBase::BufferRequested(0));

      // Update FEC parameters
      indexer_verifier_->enableFec(fec_type);
      indexer_verifier_->setNFec(0);
      ldr_->setFecParams(fec::FECUtils::getBlockSymbols(fec_type),
                         fec::FECUtils::getSourceSymbols(fec_type));
      fec_decoder_->setIOService(portal_->getThread().getIoService());
    } else if (fec_type == fec::FECType::UNKNOWN) {
      indexer_verifier_->disableFec();
    }
  }

  if (!state_->onProbePacketReceived(content_object)) return;

  // As for NACKs, set next_segment
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "on probe next seg = " << indexer_verifier_->checkNextSuffix()
      << ", jump to " << params.prod_seg;
  indexer_verifier_->jumpToIndex(params.prod_seg);

  ldr_->onProbePacketReceived(content_object);
  updateSyncWindow();
}

void RTCTransportProtocol::onContentObjectReceived(
    Interest &interest, ContentObject &content_object, std::error_code &ec) {
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Received content object of size: " << content_object.payloadSize();

  uint32_t segment_number = content_object.getName().getSuffix();
  PayloadType payload_type = content_object.getPayloadType();
  PacketState state;

  ContentObject *content_ptr = &content_object;
  ContentObject::Ptr manifest_ptr = nullptr;

  bool is_probe =
      ProbeHandler::getProbeType(segment_number) != ProbeType::NOT_PROBE;
  bool is_nack = !is_probe && content_object.payloadSize() == NACK_HEADER_SIZE;
  bool is_fec = indexer_verifier_->isFec(segment_number);
  bool is_manifest =
      !is_probe && !is_nack && !is_fec && payload_type == PayloadType::MANIFEST;
  bool is_data =
      !is_probe && !is_nack && !is_fec && payload_type == PayloadType::DATA;
  bool compute_stats = is_data || is_manifest;

  ec = make_error_code(protocol_error::not_reassemblable);

  // A helper function to process manifests or data packets received
  auto onDataPacketReceived = [this](ContentObject &content_object,
                                     bool compute_stats) {
    ldr_->onDataPacketReceived(content_object);
    rc_->onDataPacketReceived(content_object, compute_stats);
    updateSyncWindow();
  };

  // First verify the packet signature and apply the corresponding policy
  auth::VerificationPolicy policy = verifier_->verify(content_object, is_fec);
  indexer_verifier_->applyPolicy(interest, content_object, false, policy);

  if (is_probe) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received probe " << segment_number;
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onProbe(content_object);
    return;
  }

  if (is_nack) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received nack " << segment_number;
    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }
    onNack(content_object);
    return;
  }

  // content_ptr will point either to the input data packet or to a manifest
  // whose FEC header has been removed
  if (is_manifest) {
    manifest_ptr = removeFecHeader(content_object);
    if (manifest_ptr) {
      content_ptr = manifest_ptr.get();
    }
  }

  // From there, the packet is either a FEC, a manifest or a data packet.
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received content " << segment_number;

  // Do not count timed out packets in stats
  auto tn_it = timeouts_or_nacks_.find(segment_number);
  if (tn_it != timeouts_or_nacks_.end()) {
    compute_stats = false;
    timeouts_or_nacks_.erase(tn_it);
  }

  // Do not count retransmissions or losses in stats
  if (ldr_->isRtx(segment_number) ||
      ldr_->isPossibleLossWithNoRtx(segment_number)) {
    compute_stats = false;
  }

  // Fetch packet state
  state = state_->getPacketState(segment_number);

  // Check if the packet is a retransmission
  if (ldr_->isRtx(segment_number) && state != PacketState::RECEIVED) {
    if (is_data || is_manifest) {
      state_->onPacketRecoveredRtx(segment_number);

      if (*on_content_object_input_) {
        (*on_content_object_input_)(*socket_->getInterface(), content_object);
      }

      if (is_manifest) {
        processManifest(interest, *content_ptr);
      }

      ec = is_manifest ? make_error_code(protocol_error::not_reassemblable)
                       : make_error_code(protocol_error::success);

      // The packet is considered received, return early
      onDataPacketReceived(*content_ptr, compute_stats);
      return;
    }

    if (is_fec) {
      state_->onFecPacketRecoveredRtx(segment_number);
    }
  }

  // Fetch packet state again; it may have changed
  state = state_->getPacketState(segment_number);

  // Check if the packet was already received
  if (state == PacketState::RECEIVED || state == PacketState::TO_BE_RECEIVED) {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Received duplicated content " << segment_number << ", drop it";
    ec = make_error_code(protocol_error::duplicated_content);
    onDataPacketReceived(*content_ptr, compute_stats);
    return;
  }

  if (!is_fec) {
    state_->dataToBeReceived(segment_number);
  }

  // Send packet to FEC decoder
  if (fec_decoder_) {
    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "Send packet " << segment_number << " to FEC decoder";

    uint32_t offset = is_manifest
                          ? content_object.headerSize()
                          : content_object.headerSize() + rtc::DATA_HEADER_SIZE;
    uint32_t metadata = static_cast<uint32_t>(content_object.getPayloadType());

    fec_decoder_->onDataPacket(content_object, offset, metadata);
  }

  // We can return early if FEC
  if (is_fec) {
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Received FEC " << segment_number;
    state_->onFecPacketReceived(content_object);
    onDataPacketReceived(*content_ptr, compute_stats);
    return;
  }

  // The packet may have been already sent to the app by the decoder, check
  // again if it is already received
  state = state_->getPacketState(
      segment_number);  // state == RECEIVED or TO_BE_RECEIVED

  if (state != PacketState::RECEIVED) {
    DLOG_IF(INFO, VLOG_IS_ON(4))
        << (is_manifest ? "Received manifest " : "Received data ")
        << segment_number;

    if (is_manifest) {
      processManifest(interest, *content_ptr);
    }

    state_->onDataPacketReceived(*content_ptr, compute_stats);

    if (*on_content_object_input_) {
      (*on_content_object_input_)(*socket_->getInterface(), content_object);
    }

    ec = is_manifest ? make_error_code(protocol_error::not_reassemblable)
                     : make_error_code(protocol_error::success);
  }

  onDataPacketReceived(*content_ptr, compute_stats);
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

    stats_->updateAverageWindowSize(state_->getPendingInterestNumber());
    stats_->updateLossRatio(state_->getPerSecondLossRate());
    uint64_t rtt = state_->getAvgRTT();
    stats_->updateAverageRtt(utils::SteadyTime::Milliseconds(rtt));

    stats_->updateQueuingDelay(state_->getQueuing());
    stats_->updateLostData(lost_data);
    stats_->updateDefinitelyLostData(definitely_lost);
    stats_->updateRecoveredData(recovered_losses);
    stats_->updateCCState((unsigned int)current_state_ ? 1 : 0);
    (*stats_summary_)(*socket_->getInterface(), *stats_);
    bool in_congestion = rc_->inCongestionState();
    stats_->updateCongestionState(in_congestion);
    double residual_losses = state_->getResidualLossRate();
    stats_->updateResidualLossRate(residual_losses);
    stats_->updateQualityScore(state_->getQualityScore());

    // set alerts
    if (rtt > MAX_RTT)
      stats_->setAlert(interface::TransportStatistics::statsAlerts::LATENCY);
    else
      stats_->clearAlert(interface::TransportStatistics::statsAlerts::LATENCY);

    if (in_congestion)
      stats_->setAlert(interface::TransportStatistics::statsAlerts::CONGESTION);
    else
      stats_->clearAlert(
          interface::TransportStatistics::statsAlerts::CONGESTION);

    if (residual_losses > MAX_RESIDUAL_LOSSES)
      stats_->setAlert(interface::TransportStatistics::statsAlerts::LOSSES);
    else
      stats_->clearAlert(interface::TransportStatistics::statsAlerts::LOSSES);
  }
}

void RTCTransportProtocol::onFecPackets(fec::BufferArray &packets) {
  Packet::Format format;
  socket_->getSocketOption(interface::GeneralTransportOptions::PACKET_FORMAT,
                           format);

  Name *name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME, &name);

  for (auto &packet : packets) {
    uint32_t seq_number = packet.getIndex();
    uint32_t metadata = packet.getMetadata();
    fec::buffer buffer = packet.getBuffer();

    PayloadType payload_type = static_cast<PayloadType>(metadata);
    switch (payload_type) {
      case PayloadType::DATA:
      case PayloadType::MANIFEST:
        break;
      case PayloadType::UNSPECIFIED:
      default:
        payload_type = PayloadType::DATA;
        break;
    }

    switch (state_->getPacketState(seq_number)) {
      case PacketState::RECEIVED:
      case PacketState::TO_BE_RECEIVED: {
        DLOG_IF(INFO, VLOG_IS_ON(3))
            << "Packet " << seq_number << " already received";
        break;
      }
      default: {
        DLOG_IF(INFO, VLOG_IS_ON(3))
            << "Recovered packet " << seq_number << " through FEC";

        if (payload_type == PayloadType::MANIFEST) {
          name->setSuffix(seq_number);

          auto interest =
              core::PacketManager<>::getInstance().getPacket<Interest>(format);
          interest->setName(*name);

          auto content_object = toContentObject(
              *name, format, payload_type, buffer->data(), buffer->length());

          processManifest(*interest, *content_object);
        }

        state_->onPacketRecoveredFec(seq_number, buffer->length());
        ldr_->onPacketRecoveredFec(seq_number);

        if (payload_type == PayloadType::DATA) {
          verifier_->onDataRecoveredFec(seq_number);
          reassembly_->reassemble(*buffer, seq_number);
        }

        break;
      }
    }
  }
}

void RTCTransportProtocol::processManifest(Interest &interest,
                                           ContentObject &manifest) {
  auth::VerificationPolicy policy = verifier_->processManifest(manifest);
  indexer_verifier_->applyPolicy(interest, manifest, false, policy);
}

ContentObject::Ptr RTCTransportProtocol::removeFecHeader(
    const ContentObject &content_object) {
  if (!fec_decoder_ || !fec_decoder_->getFecHeaderSize()) {
    return nullptr;
  }

  size_t fec_header_size = fec_decoder_->getFecHeaderSize();
  const uint8_t *payload =
      content_object.data() + content_object.headerSize() + fec_header_size;
  size_t payload_size = content_object.payloadSize() - fec_header_size;

  ContentObject::Ptr co =
      toContentObject(content_object.getName(), content_object.getFormat(),
                      content_object.getPayloadType(), payload, payload_size);

  return co;
}

ContentObject::Ptr RTCTransportProtocol::toContentObject(
    const Name &name, Packet::Format format, PayloadType payload_type,
    const uint8_t *payload, std::size_t payload_size,
    std::size_t additional_header_size) {
  // Recreate ContentObject
  ContentObject::Ptr co =
      core::PacketManager<>::getInstance().getPacket<ContentObject>(
          format, additional_header_size);
  co->updateLength(payload_size);
  co->append(payload_size);
  co->trimStart(co->headerSize());

  // Copy payload
  std::memcpy(co->writableData(), payload, payload_size);

  // Restore network headers and some fields
  co->prepend(co->headerSize());
  co->setName(name);
  co->setPayloadType(payload_type);

  return co;
}

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
