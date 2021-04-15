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
#include <protocols/rtc/probe_handler.h>
#include <protocols/rtc/rtc_data_path.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <map>
#include <set>

namespace transport {

namespace protocol {

namespace rtc {

enum class PacketState : uint8_t { RECEIVED, LOST, UNKNOWN };

class RTCState : std::enable_shared_from_this<RTCState> {
 public:
  RTCState(ProbeHandler::SendProbeCallback &&rtt_probes_callback,
           asio::io_service &io_service);

  ~RTCState();

  // packet events
  void onSendNewInterest(const core::Name *interest_name);
  void onTimeout(uint32_t seq);
  void onRetransmission(uint32_t seq);
  void onDataPacketReceived(const core::ContentObject &content_object,
                            bool compute_stats);
  void onNackPacketReceived(const core::ContentObject &nack,
                            bool compute_stats);
  void onPacketLost(uint32_t seq);
  void onPacketRecovered(uint32_t seq);
  void onProbePacketReceived(const core::ContentObject &probe);

  // protocol state
  void onNewRound(double round_len, bool in_sync);

  // main path
  uint32_t getProducerPath() const {
    if (mainPathIsValid()) return main_path_->getPathId();
    return 0;
  }

  // delay metrics
  uint64_t getRTT() const {
    if (mainPathIsValid()) return main_path_->getMinRtt();
    return 0;
  }
  void resetRttStats() {
    if (mainPathIsValid()) main_path_->clearRtt();
  }

  double getQueuing() const {
    if (mainPathIsValid()) return main_path_->getQueuingDealy();
    return 0.0;
  }
  double getIAT() const {
    if (mainPathIsValid()) return main_path_->getInterArrivalGap();
    return 0.0;
  }

  double getJitter() const {
    if (mainPathIsValid()) return main_path_->getJitter();
    return 0.0;
  }

  // pending interests
  uint64_t getInterestSentTime(uint32_t seq) {
    auto it = pending_interests_.find(seq);
    if (it != pending_interests_.end()) return it->second;
    return 0;
  }
  bool isPending(uint32_t seq) {
    if (pending_interests_.find(seq) != pending_interests_.end()) return true;
    return false;
  }
  uint32_t getPendingInterestNumber() const {
    return pending_interests_.size();
  }
  PacketState isReceivedOrLost(uint32_t seq) {
    auto it = received_or_lost_packets_.find(seq);
    if (it != received_or_lost_packets_.end()) return it->second;
    return PacketState::UNKNOWN;
  }

  // loss rate
  double getLossRate() const { return loss_rate_; }
  double getResidualLossRate() const { return residual_loss_rate_; }
  uint32_t getHighestSeqReceivedInOrder() const {
    return highest_seq_received_in_order_;
  }
  uint32_t getLostData() const { return packets_lost_; };
  uint32_t getRecoveredLosses() const { return losses_recovered_; }

  // generic stats
  uint32_t getReceivedBytesInRound() const { return received_bytes_; }
  uint32_t getReceivedNacksInRound() const {
    return received_nacks_last_round_;
  }
  uint32_t getSentInterestInRound() const { return sent_interests_last_round_; }
  uint32_t getSentRtxInRound() const { return sent_rtx_last_round_; }

  // bandwidth/production metrics
  double getAvailableBw() const { return 0.0; };  // TODO
  double getProducerRate() const { return production_rate_; }
  double getReceivedRate() const { return received_rate_; }
  double getAveragePacketSize() const { return avg_packet_size_; }

  // nacks
  uint32_t getRoundsWithoutNacks() const { return rounds_without_nacks_; }
  uint32_t getLastSeqNacked() const { return last_seq_nacked_; }

  // producer state
  bool isProducerActive() const { return producer_is_active_; }

  // packets from cache
  double getPacketFromCacheRatio() const { return data_from_cache_rate_; }

  std::map<uint32_t, uint64_t>::iterator getPendingInterestsMapBegin() {
    return pending_interests_.begin();
  }
  std::map<uint32_t, uint64_t>::iterator getPendingInterestsMapEnd() {
    return pending_interests_.end();
  }

 private:
  void initParams();

  // update stats
  void updateState();
  void updateReceivedBytes(const core::ContentObject &content_object);
  void updatePacketSize(const core::ContentObject &content_object);
  void updatePathStats(const core::ContentObject &content_object, bool is_nack);
  void updateLossRate();

  void addRecvOrLost(uint32_t seq, PacketState state);

  bool mainPathIsValid() const {
    if (main_path_ != nullptr)
      return true;
    else
      return false;
  }

  // packets counters (total)
  uint32_t sent_interests_;
  uint32_t sent_rtx_;
  uint32_t received_data_;
  uint32_t received_nacks_;
  uint32_t received_timeouts_;
  uint32_t received_probes_;

  // loss counters
  int32_t packets_lost_;
  int32_t losses_recovered_;
  uint32_t first_seq_in_round_;
  uint32_t highest_seq_received_;
  uint32_t highest_seq_received_in_order_;
  uint32_t last_seq_nacked_;  // segment for which we got an oldNack
  double loss_rate_;
  double residual_loss_rate_;

  // bw counters
  uint32_t received_bytes_;
  double avg_packet_size_;
  double production_rate_;  // rate communicated by the producer using nacks
  double received_rate_;    // rate recevied by the consumer

  // nack counter
  // the bool takes tracks only about the valid nacks (no rtx) and it is used to
  // switch between the states. Instead received_nacks_last_round_ logs all the
  // nacks for statistics
  bool nack_on_last_round_;
  uint32_t received_nacks_last_round_;

  // packets counter
  uint32_t received_packets_last_round_;
  uint32_t received_data_last_round_;
  uint32_t received_data_from_cache_;
  double data_from_cache_rate_;
  uint32_t sent_interests_last_round_;
  uint32_t sent_rtx_last_round_;

  // round conunters
  uint32_t rounds_;
  uint32_t rounds_without_nacks_;
  uint32_t rounds_without_packets_;

  // producer state
  bool
      producer_is_active_;  // the prodcuer is active if we receive some packets
  uint64_t last_prod_update_;  // timestamp of the last packets used to update
                               // stats from the producer

  // paths stats
  std::unordered_map<uint32_t, std::shared_ptr<RTCDataPath>> path_table_;
  std::shared_ptr<RTCDataPath> main_path_;

  // packet received
  // cache where to store info about the last MAX_CACHED_PACKETS
  std::map<uint32_t, PacketState> received_or_lost_packets_;

  // pending interests
  std::map<uint32_t, uint64_t> pending_interests_;

  // probes
  std::shared_ptr<ProbeHandler> rtt_probes_;
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
