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
#include <protocols/rtc/rtc_consts.h>
#include <protocols/rtc/rtc_state.h>

namespace transport {

namespace protocol {

namespace rtc {

RTCState::RTCState(Indexer *indexer,
                   ProbeHandler::SendProbeCallback &&probe_callback,
                   DiscoveredRttCallback &&discovered_rtt_callback,
                   asio::io_service &io_service)
    : loss_history_(10),  // log 10sec history
      indexer_(indexer),
      probe_handler_(std::make_shared<ProbeHandler>(std::move(probe_callback),
                                                    io_service)),
      discovered_rtt_callback_(std::move(discovered_rtt_callback)) {
  init_rtt_timer_ = std::make_unique<asio::steady_timer>(io_service);
}

RTCState::~RTCState() {}

void RTCState::initParams() {
  // packets counters (total)
  sent_interests_ = 0;
  sent_rtx_ = 0;
  received_data_ = 0;
  received_nacks_ = 0;
  received_timeouts_ = 0;
  received_probes_ = 0;

  // loss counters
  packets_lost_ = 0;
  definitely_lost_pkt_ = 0;
  losses_recovered_ = 0;
  first_seq_in_round_ = 0;
  highest_seq_received_ = 0;
  highest_seq_received_in_order_ = 0;
  last_seq_nacked_ = 0;
  loss_rate_ = 0.0;
  avg_loss_rate_ = -1.0;
  max_loss_rate_ = 0.0;
  last_round_loss_rate_ = 0.0;

  // loss rate per sec
  lost_per_sec_ = 0;
  total_expected_packets_ = 0;
  per_sec_loss_rate_ = 0.0;

  // residual losses counters
  expected_packets_ = 0;
  packets_sent_to_app_ = 0;
  rounds_from_last_compute_ = 0;
  residual_loss_rate_ = 0.0;

  // fec counters
  pending_fec_pkt_ = 0;
  received_fec_pkt_ = 0;

  // bw counters
  received_bytes_ = 0;
  received_fec_bytes_ = 0;
  recovered_bytes_with_fec_ = 0;

  avg_packet_size_ = INIT_PACKET_SIZE;
  production_rate_ = 0.0;
  received_rate_ = 0.0;
  fec_recovered_rate_ = 0.0;

  // nack counter
  nack_on_last_round_ = false;
  received_nacks_last_round_ = 0;

  // packets counter
  received_packets_last_round_ = 0;
  received_data_last_round_ = 0;
  received_data_from_cache_ = 0;
  data_from_cache_rate_ = 0;
  sent_interests_last_round_ = 0;
  sent_rtx_last_round_ = 0;

  // round conunters
  rounds_ = 0;
  rounds_without_nacks_ = 0;
  rounds_without_packets_ = 0;

  last_production_seq_ = 0;
  producer_is_active_ = false;
  last_prod_update_ = 0;

  // paths stats
  path_table_.clear();
  main_path_ = nullptr;

  // packet cache (not pending anymore)
  packet_cache_.clear();

  // pending interests
  pending_interests_.clear();

  // used to keep track of the skipped interest
  last_interest_sent_ = 0;

  // init rtt
  first_interest_sent_time_ = ~0;
  first_interest_sent_seq_ = 0;

  // start probing the producer
  init_rtt_ = false;
  probe_handler_->setSuffixRange(MIN_INIT_PROBE_SEQ, MAX_INIT_PROBE_SEQ);
  probe_handler_->setProbes(INIT_RTT_PROBE_INTERVAL, INIT_RTT_PROBES);
  probe_handler_->sendProbes();
  setInitRttTimer(INIT_RTT_PROBE_RESTART);
}

// packet events
void RTCState::onSendNewInterest(const core::Name *interest_name) {
  uint64_t now = utils::SteadyTime::nowMs().count();
  uint32_t seq = interest_name->getSuffix();
  pending_interests_.insert(std::pair<uint32_t, uint64_t>(seq, now));

  if (sent_interests_ == 0) {
    first_interest_sent_time_ = now;
    first_interest_sent_seq_ = seq;
  }

  if (indexer_->isFec(seq)) {
    pending_fec_pkt_++;
  }

  if (last_interest_sent_ == 0 && seq != 0) {
    last_interest_sent_ = seq;  // init last interest sent
  }

  // TODO what happen in case of jumps?
  eraseFromPacketCache(
      seq);  // if we send this interest we don't know its state
  for (uint32_t i = last_interest_sent_ + 1; i < seq; i++) {
    if (indexer_->isFec(i)) {
      // only fec packets can be skipped
      addToPacketCache(i, PacketState::SKIPPED);
    }
  }

  last_interest_sent_ = seq;

  sent_interests_++;
  sent_interests_last_round_++;
}

void RTCState::onTimeout(uint32_t seq, bool lost) {
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
    if (indexer_->isFec(seq)) pending_fec_pkt_--;
  }
  received_timeouts_++;

  if (lost) onPacketLost(seq);
}

void RTCState::onLossDetected(uint32_t seq) {
  PacketState state = getPacketState(seq);

  // if the packet is already marked with a state, do nothing
  if (state == PacketState::UNKNOWN) {
    packets_lost_++;
    addToPacketCache(seq, PacketState::LOST);
  }
}

void RTCState::onRetransmission(uint32_t seq) {
  // remove the interest for the pendingInterest map only after the first rtx.
  // in this way we can handle the ooo packets that come in late as normla
  // packet. we consider a packet lost only if we sent at least an RTX for it.
  // XXX this may become problematic if we stop the RTX transmissions
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
    if (indexer_->isFec(seq)) pending_fec_pkt_--;
  }
  sent_rtx_++;
  sent_rtx_last_round_++;
}

void RTCState::onPossibleLossWithNoRtx(uint32_t seq) {
  // if fec is on or rtx is disable we don't need to do anything to recover a
  // packet. however in both cases we need to remove possible missing packets
  // from the window of pendinig interest in order to free space without wating
  // for the timeout.
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
    if (indexer_->isFec(seq)) pending_fec_pkt_--;
  }
}

void RTCState::onDataPacketReceived(const core::ContentObject &content_object,
                                    bool compute_stats) {
  uint32_t seq = content_object.getName().getSuffix();

  if (compute_stats) {
    updatePathStats(content_object, false);
    received_data_last_round_++;
  }
  received_data_++;
  packets_sent_to_app_++;

  core::ParamsRTC params = RTCState::getDataParams(content_object);

  if (last_prod_update_ < params.timestamp) {
    last_prod_update_ = params.timestamp;
    production_rate_ = (double)params.prod_rate;
  }

  updatePacketSize(content_object);
  updateReceivedBytes(content_object);
  addRecvOrLost(seq, PacketState::RECEIVED);

  if (seq > highest_seq_received_) highest_seq_received_ = seq;

  // the producer is responding
  // it is generating valid data packets so we consider it active
  producer_is_active_ = true;

  received_packets_last_round_++;
}

void RTCState::onFecPacketReceived(const core::ContentObject &content_object) {
  uint32_t seq = content_object.getName().getSuffix();
  // updateReceivedBytes(content_object);
  received_fec_bytes_ +=
      (uint32_t)(content_object.headerSize() + content_object.payloadSize());

  if (seq > highest_seq_received_) highest_seq_received_ = seq;

  PacketState state = getPacketState(seq);
  if (state != PacketState::LOST) {
    // increase only for not lost packets
    received_fec_pkt_++;
  }
  addRecvOrLost(seq, PacketState::RECEIVED);
  // the producer is responding
  // it is generating valid data packets so we consider it active
  producer_is_active_ = true;
}

void RTCState::onNackPacketReceived(const core::ContentObject &nack,
                                    bool compute_stats) {
  uint32_t seq = nack.getName().getSuffix();
  struct nack_packet_t *nack_pkt =
      (struct nack_packet_t *)nack.getPayload()->data();
  uint64_t production_time = nack_pkt->getTimestamp();
  uint32_t production_seq = nack_pkt->getProductionSegment();
  uint32_t production_rate = nack_pkt->getProductionRate();

  if (TRANSPORT_EXPECT_FALSE(main_path_ == nullptr) ||
      last_prod_update_ < production_time) {
    // update production rate
    last_prod_update_ = production_time;
    last_production_seq_ = production_seq;
    production_rate_ = (double)production_rate;
  }

  if (compute_stats) {
    // this is not an RTX
    updatePathStats(nack, true);
    nack_on_last_round_ = true;
  }

  // for statistics pourpose we log all nacks, also the one received for
  // retransmitted packets
  received_nacks_++;
  received_nacks_last_round_++;

  bool to_delete = false;
  if (production_seq > seq) {
    // old nack, seq is lost
    // update last nacked
    if (last_seq_nacked_ < seq) last_seq_nacked_ = seq;
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "lost packet " << seq << " beacuse of a past nack";
    onPacketLost(seq);
  } else if (seq > production_seq) {
    // future nack
    // remove the nack from the pending interest map
    // (the packet is not received/lost yet)
    to_delete = true;
  } else {
    // this should be a quite rear event. simply remove the
    // packet from the pending interest list
    to_delete = true;
  }

  if (to_delete) {
    auto it = pending_interests_.find(seq);
    if (it != pending_interests_.end()) {
      pending_interests_.erase(it);
      if (indexer_->isFec(seq)) pending_fec_pkt_--;
    }
  }

  // the producer is responding
  // we consider it active only if the production rate is not 0
  // or the production sequence number is not 1
  if (production_rate_ != 0 || production_seq != 1) {
    producer_is_active_ = true;
  }

  received_packets_last_round_++;
}

void RTCState::onPacketLost(uint32_t seq) {
#if 0
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "packet " << seq << " is lost";
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    // this packet was never retransmitted so it does
    // not appear in the loss count
    packets_lost_++;
  }
#endif
  if (!indexer_->isFec(seq)) {
    PacketState state = getPacketState(seq);
    if (state == PacketState::LOST || state == PacketState::UNKNOWN) {
      definitely_lost_pkt_++;
      DLOG_IF(INFO, VLOG_IS_ON(4)) << "packet " << seq << " is lost";
    }
  }
  addRecvOrLost(seq, PacketState::DEFINITELY_LOST);
}

void RTCState::onPacketRecoveredRtx(uint32_t seq) {
  packets_sent_to_app_++;
  if (seq > highest_seq_received_) highest_seq_received_ = seq;
  losses_recovered_++;
  addRecvOrLost(seq, PacketState::RECEIVED);
}

void RTCState::onFecPacketRecoveredRtx(uint32_t seq) {
  // This is the same as onPacketRecoveredRtx, but in this is case the
  // pkt is also a FEC pkt, the addRecvOrLost will be called afterwards
  if (seq > highest_seq_received_) highest_seq_received_ = seq;
  losses_recovered_++;
}

void RTCState::onPacketRecoveredFec(uint32_t seq, uint32_t size) {
  losses_recovered_++;
  packets_sent_to_app_++;
  recovered_bytes_with_fec_ += size;

  if (seq > highest_seq_received_) highest_seq_received_ = seq;

  // adding header to the count
  recovered_bytes_with_fec_ += 60;  // XXX get header size some where

  if (getPacketState(seq) == PacketState::UNKNOWN)
    onLossDetected(seq);  // the pkt was lost but didn't account for it yet

  addRecvOrLost(seq, PacketState::RECEIVED);
}

bool RTCState::onProbePacketReceived(const core::ContentObject &probe) {
  uint32_t seq = probe.getName().getSuffix();

  uint64_t rtt;
  rtt = probe_handler_->getRtt(seq);
  if (rtt == 0) return false;  // this is not a valid probe

  // Like for data and nacks update the path stats. Here the RTT is computed
  // by the probe handler. Both probes for rtt and bw are good to estimate
  // info on the path.
  uint32_t path_label = probe.getPathLabel();
  auto path_it = path_table_.find(path_label);

  if (path_it == path_table_.end()) {
    // found a new path
    std::shared_ptr<RTCDataPath> newPath =
        std::make_shared<RTCDataPath>(path_label);
    auto ret = path_table_.insert(
        std::pair<uint32_t, std::shared_ptr<RTCDataPath>>(path_label, newPath));
    path_it = ret.first;
  }

  auto path = path_it->second;

  path->insertRttSample(utils::SteadyTime::Milliseconds(rtt), true);
  path->receivedNack();

  uint64_t now = utils::SteadyTime::nowMs().count();

  core::ParamsRTC params = RTCState::getProbeParams(probe);

  int64_t OWD = now - params.timestamp;
  path->insertOwdSample(OWD);

  if (last_prod_update_ < params.timestamp) {
    last_production_seq_ = params.prod_seg;
    last_prod_update_ = params.timestamp;
    production_rate_ = (double)params.prod_rate;
  }

  // the producer is responding
  // we consider it active only if the production rate is not 0
  // or the production sequence numner is not 1
  if (production_rate_ != 0 || params.prod_seg != 1) {
    producer_is_active_ = true;
  }

  // check for init RTT. if received_probes_ is equal to 0 schedule a timer to
  // wait for the INIT_RTT_PROBES. in this way if some probes get lost we don't
  // wait forever
  received_probes_++;

  if (!init_rtt_ && received_probes_ <= INIT_RTT_PROBES) {
    if (received_probes_ == 1) {
      // we got the first probe, wait at most INIT_RTT_PROBE_WAIT sec for the
      // others.
      main_path_ = path;
      setInitRttTimer(INIT_RTT_PROBE_WAIT);
    }
    if (received_probes_ == INIT_RTT_PROBES) {
      // we are done
      init_rtt_timer_->cancel();
      checkInitRttTimer();
    }
  }

  received_packets_last_round_++;

  // ignore probes sent before the first interest
  if ((now - rtt) <= first_interest_sent_time_) return false;
  return true;
}

void RTCState::onJumpForward(uint32_t next_seq) {
  for (uint32_t seq = highest_seq_received_in_order_ + 1; seq < next_seq;
       seq++) {
    auto it = pending_interests_.find(seq);
    PacketState packet_state = getPacketState(seq);
    if (it == pending_interests_.end() &&
        packet_state != PacketState::RECEIVED &&
        packet_state != PacketState::DEFINITELY_LOST) {
      onLossDetected(seq);
      onPacketLost(seq);
    }
  }
}

void RTCState::onNewRound(double round_len, bool in_sync) {
  if (path_table_.empty()) return;

  double bytes_per_sec =
      ((double)received_bytes_ * (MILLI_IN_A_SEC / round_len));
  if (received_rate_ == 0)
    received_rate_ = bytes_per_sec;
  else
    received_rate_ = (received_rate_ * MOVING_AVG_ALPHA) +
                     ((1 - MOVING_AVG_ALPHA) * bytes_per_sec);
  double fec_bytes_per_sec =
      ((double)received_fec_bytes_ * (MILLI_IN_A_SEC / round_len));

  if (fec_received_rate_ == 0)
    fec_received_rate_ = fec_bytes_per_sec;
  else
    fec_received_rate_ = (fec_received_rate_ * 0.8) + (0.2 * fec_bytes_per_sec);

  double fec_recovered_bytes_per_sec =
      ((double)recovered_bytes_with_fec_ * (MILLI_IN_A_SEC / round_len));

  if (fec_recovered_rate_ == 0)
    fec_recovered_rate_ = fec_recovered_bytes_per_sec;
  else
    fec_recovered_rate_ =
        (fec_recovered_rate_ * 0.8) + (0.2 * fec_recovered_bytes_per_sec);

#if 0
  // search for an active path. There should be only one active path (meaning a
  // path that leads to the producer socket -no cache- and from which we are
  // currently getting data packets) at any time. However it may happen that
  // there are mulitple active paths in case of mobility (the old path will
  // remain active for a short ammount of time). The main path is selected as
  // the active path from where the consumer received the latest data packet

  uint64_t last_packet_ts = 0;
  main_path_ = nullptr;

  for (auto it = path_table_.begin(); it != path_table_.end(); it++) {
    it->second->roundEnd();
    if (it->second->isActive()) {
      uint64_t ts = it->second->getLastPacketTS();
      if (ts > last_packet_ts) {
        last_packet_ts = ts;
        main_path_ = it->second;
      }
    }
  }
#endif

  // search for an active path. Is it possible to have multiple path that are
  // used at the same time. We use as reference path the one from where we gets
  // more packets. This means that the path should have better lantecy or less
  // channel losses

  uint32_t last_round_packets = 0;
  std::shared_ptr<RTCDataPath> old_main_path = main_path_;
  main_path_ = nullptr;

  for (auto it = path_table_.begin(); it != path_table_.end(); it++) {
    if (it->second->isActive()) {
      uint32_t pkt = it->second->getPacketsLastRound();
      if (pkt > last_round_packets) {
        last_round_packets = pkt;
        main_path_ = it->second;
      }
    }
    it->second->roundEnd();
  }

  if (main_path_ == nullptr) main_path_ = old_main_path;

  // in case we get a new main path we reset the stats of the old one. this is
  // beacuse, in case we need to switch back we don't what to take decisions on
  // old stats that may be outdated.
  if (main_path_ != old_main_path) old_main_path->clearRtt();

  updateLossRate(in_sync);

  // handle nacks
  if (!nack_on_last_round_ && received_bytes_ > 0) {
    rounds_without_nacks_++;
  } else {
    rounds_without_nacks_ = 0;
  }

  // check if the producer is active
  if (received_packets_last_round_ != 0) {
    rounds_without_packets_ = 0;
  } else {
    rounds_without_packets_++;
    if (rounds_without_packets_ >= MAX_ROUND_WHIOUT_PACKETS &&
        producer_is_active_ != false) {
      initParams();
    }
  }

  // compute cache/producer ratio
  if (received_data_last_round_ != 0) {
    double new_rate =
        (double)received_data_from_cache_ / (double)received_data_last_round_;
    data_from_cache_rate_ = data_from_cache_rate_ * MOVING_AVG_ALPHA +
                            (new_rate * (1 - MOVING_AVG_ALPHA));
  }

  // reset counters
  received_bytes_ = 0;
  received_fec_bytes_ = 0;
  recovered_bytes_with_fec_ = 0;
  packets_lost_ = 0;
  definitely_lost_pkt_ = 0;
  losses_recovered_ = 0;
  first_seq_in_round_ = highest_seq_received_;

  nack_on_last_round_ = false;
  received_nacks_last_round_ = 0;

  received_packets_last_round_ = 0;
  received_data_last_round_ = 0;
  received_data_from_cache_ = 0;
  sent_interests_last_round_ = 0;
  sent_rtx_last_round_ = 0;

  received_fec_pkt_ = 0;

  rounds_++;
}

void RTCState::updateReceivedBytes(const core::ContentObject &content_object) {
  received_bytes_ +=
      (uint32_t)(content_object.headerSize() + content_object.payloadSize());
}

void RTCState::updatePacketSize(const core::ContentObject &content_object) {
  uint32_t pkt_size =
      (uint32_t)(content_object.headerSize() + content_object.payloadSize());
  avg_packet_size_ = (MOVING_AVG_ALPHA * avg_packet_size_) +
                     ((1 - MOVING_AVG_ALPHA) * pkt_size);
}

void RTCState::updatePathStats(const core::ContentObject &content_object,
                               bool is_nack) {
  // get packet path
  uint32_t path_label = content_object.getPathLabel();
  auto path_it = path_table_.find(path_label);

  if (path_it == path_table_.end()) {
    // found a new path
    std::shared_ptr<RTCDataPath> newPath =
        std::make_shared<RTCDataPath>(path_label);
    auto ret = path_table_.insert(
        std::pair<uint32_t, std::shared_ptr<RTCDataPath>>(path_label, newPath));
    path_it = ret.first;
  }

  auto path = path_it->second;

  // compute rtt
  uint32_t seq = content_object.getName().getSuffix();
  uint64_t interest_sent_time = getInterestSentTime(seq);
  if (interest_sent_time == 0)
    return;  // this should not happen,
             // it means that we are processing an interest
             // that is not pending

  uint64_t now = utils::SteadyTime::nowMs().count();

  uint64_t RTT = now - interest_sent_time;

  path->insertRttSample(utils::SteadyTime::Milliseconds(RTT), false);

  // compute OWD (the first part of the nack and data packet header are the
  // same, so we cast to data data packet)
  core::ParamsRTC params = RTCState::getDataParams(content_object);
  int64_t OWD = now - params.timestamp;
  path->insertOwdSample(OWD);

  // compute IAT or set path to producer
  if (!is_nack) {
    // compute the iat only for the content packets
    uint32_t segment_number = content_object.getName().getSuffix();
    path->computeInterArrivalGap(segment_number);
    if (!path->pathToProducer()) received_data_from_cache_++;
  } else {
    path->receivedNack();
  }
}

void RTCState::updateLossRate(bool in_sync) {
  last_round_loss_rate_ = loss_rate_;
  loss_rate_ = 0.0;

  uint32_t number_theorically_received_packets_ =
      highest_seq_received_ - first_seq_in_round_;

  // XXX this may be quite inefficient if the rate is high
  // maybe is better to iterate over the set?

  uint32_t fec_packets = 0;
  for (uint32_t i = (first_seq_in_round_ + 1); i < highest_seq_received_; i++) {
    PacketState state = getPacketState(i);
    if (state == PacketState::SKIPPED) {
      if (number_theorically_received_packets_ > 0)
        number_theorically_received_packets_--;
    }
    if (indexer_->isFec(i)) fec_packets++;
  }
  if (indexer_->isFec(highest_seq_received_)) fec_packets++;

  // in this case no new packet was received after the previous round, avoid
  // division by 0
  if (number_theorically_received_packets_ == 0 && packets_lost_ == 0) return;

  if (number_theorically_received_packets_ != 0)
    loss_rate_ = (double)((double)(packets_lost_) /
                          (double)number_theorically_received_packets_);
  else
    // we didn't receive anything except NACKs that triggered losses
    loss_rate_ = 1.0;

  if (avg_loss_rate_ == -1.0)
    avg_loss_rate_ = loss_rate_;
  else
    avg_loss_rate_ =
        avg_loss_rate_ * MOVING_AVG_ALPHA + loss_rate_ * (1 - MOVING_AVG_ALPHA);

  // update counters for loss rate per second
  total_expected_packets_ += number_theorically_received_packets_;
  lost_per_sec_ += packets_lost_;

  if (in_sync) {
    // update counters for residual losses
    // fec packets are not sent to the app so we don't want to count them here
    expected_packets_ +=
        ((highest_seq_received_ - first_seq_in_round_) - fec_packets);
  } else {
    packets_sent_to_app_ = 0;
  }

  if (rounds_from_last_compute_ >= (MILLI_IN_A_SEC / ROUND_LEN)) {
    // compute loss rate per second
    if (lost_per_sec_ > total_expected_packets_)
      lost_per_sec_ = total_expected_packets_;

    if (total_expected_packets_ == 0)
      per_sec_loss_rate_ = 0;
    else
      per_sec_loss_rate_ =
          (double)((double)(lost_per_sec_) / (double)total_expected_packets_);

    loss_history_.pushBack(per_sec_loss_rate_);
    max_loss_rate_ = getMaxLoss();

    if (in_sync && expected_packets_ != 0) {
      // compute residual loss rate
      if (packets_sent_to_app_ > expected_packets_) {
        // this may happen if we get packet from the prev bin that get recovered
        // on the current one
        packets_sent_to_app_ = expected_packets_;
      }

      residual_loss_rate_ =
          1.0 - ((double)packets_sent_to_app_ / (double)expected_packets_);
      if (residual_loss_rate_ < 0.0) residual_loss_rate_ = 0.0;
    }

    lost_per_sec_ = 0;
    total_expected_packets_ = 0;
    expected_packets_ = 0;
    packets_sent_to_app_ = 0;
    rounds_from_last_compute_ = 0;
  }

  rounds_from_last_compute_++;
}

void RTCState::dataToBeReceived(uint32_t seq) {
  addToPacketCache(seq, PacketState::TO_BE_RECEIVED);
}

void RTCState::addRecvOrLost(uint32_t seq, PacketState state) {
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
    if (indexer_->isFec(seq)) pending_fec_pkt_--;
  }

  addToPacketCache(seq, state);

  // keep track of the last packet received/lost
  // without holes.
  if (highest_seq_received_in_order_ < last_seq_nacked_) {
    highest_seq_received_in_order_ = last_seq_nacked_;
  }

  if ((highest_seq_received_in_order_ + 1) == seq) {
    highest_seq_received_in_order_ = seq;
  } else if (seq <= highest_seq_received_in_order_) {
    // here we do nothing
  } else if (seq > highest_seq_received_in_order_) {
    // 1) there is a gap in the sequence so we do not update
    // highest_seq_received_in_order_
    // 2) all the packets from highest_seq_received_in_order_ to seq are
    // received or lost or are fec packetis. In this case we increase
    // highest_seq_received_in_order_ until we find an hole in the sequence

    for (uint32_t i = highest_seq_received_in_order_ + 1; i <= seq; i++) {
      PacketState state = getPacketState(i);
      if ((state == PacketState::UNKNOWN || state == PacketState::LOST)) {
        if (indexer_->isFec(i)) {
          // this is a fec packet and we don't care to receive it
          // however we may need to increse the number or lost packets
          // XXX: in case we want to use rtx to recover fec packets,
          // this may prevent to detect a packet loss and no rtx will be sent
          onLossDetected(i);
        } else {
          // this is a data packet and we need to get it
          break;
        }
      }
      // this packet is in order so we can update the
      // highest_seq_received_in_order_
      highest_seq_received_in_order_ = i;
    }
  }
}

void RTCState::setInitRttTimer(uint32_t wait) {
  init_rtt_timer_->cancel();
  init_rtt_timer_->expires_from_now(std::chrono::milliseconds(wait));

  std::weak_ptr<RTCState> self = shared_from_this();
  init_rtt_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) return;

    if (auto ptr = self.lock()) {
      ptr->checkInitRttTimer();
    }
  });
}

void RTCState::checkInitRttTimer() {
  if (received_probes_ < INIT_RTT_MIN_PROBES_TO_RECV) {
    // we didn't received enough probes, restart
    received_probes_ = 0;
    probe_handler_->setSuffixRange(MIN_INIT_PROBE_SEQ, MAX_INIT_PROBE_SEQ);
    probe_handler_->setProbes(INIT_RTT_PROBE_INTERVAL, INIT_RTT_PROBES);
    probe_handler_->sendProbes();
    setInitRttTimer(INIT_RTT_PROBE_RESTART);
    return;
  }

  init_rtt_ = true;
  main_path_->roundEnd();
  loss_history_.pushBack(probe_handler_->getProbeLossRate());
  max_loss_rate_ = getMaxLoss();

  probe_handler_->setSuffixRange(MIN_RTT_PROBE_SEQ, MAX_RTT_PROBE_SEQ);
  probe_handler_->setProbes(RTT_PROBE_INTERVAL, 0);
  probe_handler_->sendProbes();

  // init last_seq_nacked_. skip packets that may come from the cache
  double prod_rate = getProducerRate();
  double rtt = (double)getMinRTT() / MILLI_IN_A_SEC;
  double packet_size = getAveragePacketSize();
  uint32_t pkt_in_rtt_ = std::floor(((prod_rate / packet_size) * rtt) * 0.8);
  last_seq_nacked_ = last_production_seq_ + pkt_in_rtt_;

  discovered_rtt_callback_();
}

double RTCState::getMaxLoss() {
  if (loss_history_.size() != 0) return loss_history_.begin();
  return 0;
}

core::ParamsRTC RTCState::getProbeParams(const core::ContentObject &probe) {
  uint32_t seq = probe.getName().getSuffix();
  core::ParamsRTC params;

  switch (ProbeHandler::getProbeType(seq)) {
    case ProbeType::INIT: {
      core::ContentObjectManifest manifest(
          const_cast<core::ContentObject &>(probe));
      manifest.decode();
      params = manifest.getParamsRTC();
      break;
    }
    case ProbeType::RTT: {
      struct nack_packet_t *probe_pkt =
          (struct nack_packet_t *)probe.getPayload()->data();
      params = core::ParamsRTC{
          .timestamp = probe_pkt->getTimestamp(),
          .prod_rate = probe_pkt->getProductionRate(),
          .prod_seg = probe_pkt->getProductionSegment(),
      };
      break;
    }
    default:
      break;
  }

  return params;
}

core::ParamsRTC RTCState::getDataParams(const core::ContentObject &data) {
  core::ParamsRTC params;

  switch (data.getPayloadType()) {
    case core::PayloadType::DATA: {
      struct data_packet_t *data_pkt =
          (struct data_packet_t *)data.getPayload()->data();
      params = core::ParamsRTC{
          .timestamp = data_pkt->getTimestamp(),
          .prod_rate = data_pkt->getProductionRate(),
          .prod_seg = data.getName().getSuffix(),
      };
      break;
    }
    case core::PayloadType::MANIFEST: {
      core::ContentObjectManifest manifest(
          const_cast<core::ContentObject &>(data));
      manifest.decode();
      params = manifest.getParamsRTC();
      break;
    }
    default:
      break;
  }

  return params;
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
