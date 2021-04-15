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
#include <protocols/rtc/rtc_state.h>

namespace transport {

namespace protocol {

namespace rtc {

RTCState::RTCState(ProbeHandler::SendProbeCallback &&rtt_probes_callback,
                   asio::io_service &io_service)
    : rtt_probes_(std::make_shared<ProbeHandler>(
          MIN_RTT_PROBE_SEQ, MAX_RTT_PROBE_SEQ, RTT_PROBE_INTERVAL,
          std::move(rtt_probes_callback), io_service)) {
  rtt_probes_->sendProbes();
  initParams();
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
  losses_recovered_ = 0;
  first_seq_in_round_ = 0;
  highest_seq_received_ = 0;
  highest_seq_received_in_order_ = 0;
  last_seq_nacked_ = 0;
  loss_rate_ = 0.0;
  residual_loss_rate_ = 0.0;

  // bw counters
  received_bytes_ = 0;
  avg_packet_size_ = INIT_PACKET_SIZE;
  production_rate_ = 0.0;
  received_rate_ = 0.0;

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

  producer_is_active_ = false;
  last_prod_update_ = 0;

  // paths stats
  path_table_.clear();
  main_path_ = nullptr;

  // packet received
  received_or_lost_packets_.clear();

  // pending interests
  pending_interests_.clear();
}

// packet events
void RTCState::onSendNewInterest(const core::Name *interest_name) {
  sent_interests_++;
  sent_interests_last_round_++;
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  uint32_t seq = interest_name->getSuffix();
  pending_interests_.insert(std::pair<uint32_t, uint64_t>(seq, now));
}

void RTCState::onTimeout(uint32_t seq) {
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
  }
  received_timeouts_++;
}

void RTCState::onRetransmission(uint32_t seq) {
  // remove the interest for the pendingInterest map only after the first rtx.
  // in this way we can handle the ooo packets that come in late as normla
  // packet. we consider a packet lost only if we sent at least an RTX for it.
  // XXX this may become problematic if we stop the RTX transmissions
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    pending_interests_.erase(it);
    packets_lost_++;
  }
  sent_rtx_++;
  sent_rtx_last_round_++;
}

void RTCState::onDataPacketReceived(const core::ContentObject &content_object,
                                    bool compute_stats) {
  uint32_t seq = content_object.getName().getSuffix();
  if (compute_stats) {
    updatePathStats(content_object, false);
    received_data_last_round_++;
  }
  received_data_++;

  struct data_packet_t *data_pkt =
      (struct data_packet_t *)content_object.getPayload()->data();
  uint64_t production_time = data_pkt->getTimestamp();
  if (last_prod_update_ < production_time) {
    last_prod_update_ = production_time;
    uint32_t production_rate = data_pkt->getProductionRate();
    production_rate_ = (double)production_rate;
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

void RTCState::onNackPacketReceived(const core::ContentObject &nack,
                                    bool compute_stats) {
  uint32_t seq = nack.getName().getSuffix();
  struct nack_packet_t *nack_pkt =
      (struct nack_packet_t *)nack.getPayload()->data();
  uint64_t production_time = nack_pkt->getTimestamp();
  uint32_t production_seq = nack_pkt->getProductionSegement();
  uint32_t production_rate = nack_pkt->getProductionRate();

  if (TRANSPORT_EXPECT_FALSE(main_path_ == nullptr) ||
      last_prod_update_ < production_time) {
    // update production rate
    last_prod_update_ = production_time;
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

  if (production_seq > seq) {
    // old nack, seq is lost
    // update last nacked
    if (last_seq_nacked_ < seq) last_seq_nacked_ = seq;
    TRANSPORT_LOGD("lost packet %u beacuse of a past nack", seq);
    onPacketLost(seq);
  } else if (seq > production_seq) {
    // future nack
    // remove the nack from the pending interest map
    // (the packet is not received/lost yet)
    pending_interests_.erase(seq);
  } else {
    // this should be a quite rear event. simply remove the
    // packet from the pending interest list
    pending_interests_.erase(seq);
  }

  // the producer is responding
  // we consider it active only if the production rate is not 0
  // or the production sequence number is not 1
  if (production_rate_ != 0 || production_seq != 1) {
    producer_is_active_ = true;
  }

  // if this is the first packet received we use the production seq to set last
  // seq nacked. the production seq indicates the next packet that will be
  // generated by the producer, so we reduce it by 1.
  if (TRANSPORT_EXPECT_FALSE(highest_seq_received_ == 0)) {
    last_seq_nacked_ = production_seq - 1;
  }

  received_packets_last_round_++;
}

void RTCState::onPacketLost(uint32_t seq) {
  TRANSPORT_LOGD("packet %u is lost", seq);
  auto it = pending_interests_.find(seq);
  if (it != pending_interests_.end()) {
    // this packet was never retransmitted so it does
    // not appear in the loss count
    packets_lost_++;
  }
  addRecvOrLost(seq, PacketState::LOST);
}

void RTCState::onPacketRecovered(uint32_t seq) {
  losses_recovered_++;
  addRecvOrLost(seq, PacketState::RECEIVED);
}

void RTCState::onProbePacketReceived(const core::ContentObject &probe) {
  uint32_t seq = probe.getName().getSuffix();
  uint64_t rtt;

  rtt = rtt_probes_->getRtt(seq);

  if (rtt == 0) return;  // this is not a valid probe

  // like for data and nacks update the path stats. Here the RTT is computed
  // by the probe handler. Both probes for rtt and bw are good to esimate
  // info on the path
  uint32_t path_label = probe.getPathLabel();

  auto path_it = path_table_.find(path_label);

  // update production rate and last_seq_nacked like in case of a nack
  struct nack_packet_t *probe_pkt =
      (struct nack_packet_t *)probe.getPayload()->data();
  uint64_t sender_timestamp = probe_pkt->getTimestamp();
  uint32_t production_seq = probe_pkt->getProductionSegement();
  uint32_t production_rate = probe_pkt->getProductionRate();

  if (path_it == path_table_.end()) {
    // found a new path
    std::shared_ptr<RTCDataPath> newPath =
        std::make_shared<RTCDataPath>(path_label);
    auto ret = path_table_.insert(
        std::pair<uint32_t, std::shared_ptr<RTCDataPath>>(path_label, newPath));
    path_it = ret.first;
  }

  auto path = path_it->second;

  path->insertRttSample(rtt);
  path->receivedNack();

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  int64_t OWD = now - sender_timestamp;
  path->insertOwdSample(OWD);

  received_probes_++;

  if (last_prod_update_ < sender_timestamp) {
    last_prod_update_ = sender_timestamp;
    production_rate_ = (double)production_rate;
  }

  // the producer is responding
  // we consider it active only if the production rate is not 0
  // or the production sequence numner is not 1
  if (production_rate_ != 0 || production_seq != 1) {
    producer_is_active_ = true;
  }

  // if this is the first packet received we use the production seq to set last
  // seq nacked. the production seq indicates the next packet that will be
  // generated by the producer, so we reduce it by 1.
  if (TRANSPORT_EXPECT_FALSE(highest_seq_received_ == 0)) {
    last_seq_nacked_ = production_seq - 1;
  }

  received_packets_last_round_++;
}

void RTCState::onNewRound(double round_len, bool in_sync) {
  // XXX
  // here we take into account only the single path case so we assume that we
  // don't use two paths in parellel for this single flow

  if (path_table_.empty()) return;

  double bytes_per_sec =
      ((double)received_bytes_ * (MILLI_IN_A_SEC / round_len));
  received_rate_ = (received_rate_ * MOVING_AVG_ALPHA) +
                   ((1 - MOVING_AVG_ALPHA) * bytes_per_sec);

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

  if (in_sync) updateLossRate();

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
  packets_lost_ = 0;
  losses_recovered_ = 0;
  first_seq_in_round_ = highest_seq_received_;

  nack_on_last_round_ = false;
  received_nacks_last_round_ = 0;

  received_packets_last_round_ = 0;
  received_data_last_round_ = 0;
  received_data_from_cache_ = 0;
  sent_interests_last_round_ = 0;
  sent_rtx_last_round_ = 0;

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

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  uint64_t RTT = now - interest_sent_time;

  path->insertRttSample(RTT);

  // compute OWD (the first part of the nack and data packet header are the
  // same, so we cast to data data packet)
  struct data_packet_t *packet =
      (struct data_packet_t *)content_object.getPayload()->data();
  uint64_t sender_timestamp = packet->getTimestamp();
  int64_t OWD = now - sender_timestamp;
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

void RTCState::updateLossRate() {
  loss_rate_ = 0.0;
  residual_loss_rate_ = 0.0;

  uint32_t number_theorically_received_packets_ =
      highest_seq_received_ - first_seq_in_round_;

  // in this case no new packet was recevied after the previuos round, avoid
  // division by 0
  if (number_theorically_received_packets_ == 0) return;

  loss_rate_ = (double)((double)(packets_lost_) /
                        (double)number_theorically_received_packets_);

  residual_loss_rate_ = (double)((double)(packets_lost_ - losses_recovered_) /
                                 (double)number_theorically_received_packets_);

  if (residual_loss_rate_ < 0) residual_loss_rate_ = 0;
}

void RTCState::addRecvOrLost(uint32_t seq, PacketState state) {
  pending_interests_.erase(seq);
  if (received_or_lost_packets_.size() >= MAX_CACHED_PACKETS) {
    received_or_lost_packets_.erase(received_or_lost_packets_.begin());
  }
  // notice that it may happen that a packet that we consider lost arrives after
  // some time, in this case we simply overwrite the packet state.
  received_or_lost_packets_[seq] = state;

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
    // 1) there is a gap in the sequence so we do not update largest_in_seq_
    // 2) all the packets from largest_in_seq_ to seq are in
    //    received_or_lost_packets_ an we upate largest_in_seq_

    for (uint32_t i = highest_seq_received_in_order_ + 1; i <= seq; i++) {
      if (received_or_lost_packets_.find(i) ==
          received_or_lost_packets_.end()) {
        break;
      }
      // this packet is in order so we can update the
      // highest_seq_received_in_order_
      highest_seq_received_in_order_ = i;
    }
  }
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
