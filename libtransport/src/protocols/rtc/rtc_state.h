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
#include <core/facade.h>
#include <hicn/transport/config.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/utils/rtc_quality_score.h>
#include <protocols/indexer.h>
#include <protocols/rtc/probe_handler.h>
#include <protocols/rtc/rtc_data_path.h>
#include <utils/max_filter.h>

#include <map>
#include <set>

namespace transport {

namespace protocol {

namespace rtc {

// packet state
// RECEIVED: the packet was already received
// LOST: the packet is marked as lost but can be recovered
// DEFINITELY_LOST: the packet is lost and cannot be recovered
// TO_BE_RECEIVED: when a packet is received is sent to the FEC decoder. the fec
// decoder may decide to send the packet directly to the app. to avoid
// duplicated the packet is marked with this state
// SKIPPED: an interest that was not sent, only for FEC packets
// UNKNOWN: unknown state
enum class PacketState : uint8_t {
  RECEIVED,
  TO_BE_RECEIVED,
  LOST,
  DEFINITELY_LOST,
  SKIPPED,
  UNKNOWN
};

class RTCState : public std::enable_shared_from_this<RTCState> {
  using PendingInterestsMap = std::map<uint32_t, uint64_t>;

 private:
  const double MAX_CACHED_PACKETS = 8192;  // XXX this value may be too small
                                           // for high rate apps

 public:
  using DiscoveredRttCallback = std::function<void()>;

 public:
  RTCState(Indexer *indexer, ProbeHandler::SendProbeCallback &&probe_callback,
           DiscoveredRttCallback &&discovered_rtt_callback,
           asio::io_service &io_service);

  ~RTCState();

  // initialization
  void initParams();

  // packet events
  void onSendNewInterest(const core::Name *interest_name);
  void onTimeout(uint32_t seq, bool lost);
  void onLossDetected(uint32_t seq);
  void onRetransmission(uint32_t seq);
  void onPossibleLossWithNoRtx(uint32_t seq);
  void onDataPacketReceived(const core::ContentObject &content_object,
                            bool compute_stats);
  void onFecPacketReceived(const core::ContentObject &content_object);
  void onNackPacketReceived(const core::ContentObject &nack,
                            bool compute_stats);
  void onPacketLost(uint32_t seq);
  void onPacketRecoveredRtx(const core::ContentObject &content_object);
  void onFecPacketRecoveredRtx(const core::ContentObject &content_object);
  void onPacketRecoveredFec(uint32_t seq, uint32_t size);
  bool onProbePacketReceived(const core::ContentObject &probe);
  void onJumpForward(uint32_t next_seq);

  // protocol state
  void onNewRound(double round_len, bool in_sync);

  // main path
  uint32_t getProducerPath() const {
    if (mainPathIsValid()) return main_path_->getPathId();
    return 0;
  }

  // delay metrics
  bool isRttDiscovered() const { return init_rtt_; }

  uint64_t getMinRTT() const {
    if (mainPathIsValid()) return main_path_->getMinRtt();
    return 0;
  }

  uint64_t getAvgRTT() const {
    if (mainPathIsValid()) return main_path_->getAvgRtt();
    return 0;
  }

  uint64_t getMaxRTT() const {
    if (mainPathIsValid()) return main_path_->getMaxRtt();
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
    return (uint32_t)pending_interests_.size();
  }

  PacketState getPacketState(uint32_t seq) {
    auto it = packet_cache_.find(seq);
    if (it != packet_cache_.end()) return it->second;
    return PacketState::UNKNOWN;
  }

  // loss rate
  double getPerRoundLossRate() const { return loss_rate_; }
  double getPerSecondLossRate() const { return per_sec_loss_rate_; }
  double getAvgLossRate() const { return avg_loss_rate_; }
  double getMaxLossRate() const {
    if (loss_history_.size() != 0) return loss_history_.begin();
    return 0;
  }

  double getLastRoundLossRate() const { return last_round_loss_rate_; }
  double getResidualLossRate() const { return residual_loss_rate_; }

  uint32_t getLostData() const { return packets_lost_; };
  uint32_t getRecoveredLosses() const { return losses_recovered_; }

  uint32_t getDefinitelyLostPackets() const { return definitely_lost_pkt_; }

  uint32_t getHighestSeqReceived() const { return highest_seq_received_; }

  uint32_t getHighestSeqReceivedInOrder() const {
    return highest_seq_received_in_order_;
  }

  // fec packets
  uint32_t getReceivedFecPackets() const { return received_fec_pkt_; }
  uint32_t getPendingFecPackets() const { return pending_fec_pkt_; }

  // generic stats
  uint32_t getReceivedBytesInRound() const { return received_bytes_; }
  uint32_t getReceivedFecBytesInRound() const { return received_fec_bytes_; }
  uint32_t getRecoveredFecBytesInRound() const {
    return recovered_bytes_with_fec_;
  }
  uint32_t getReceivedNacksInRound() const {
    return received_nacks_last_round_;
  }
  uint32_t getReceivedDataInRound() const { return received_data_last_round_; }
  uint32_t getSentInterestInRound() const { return sent_interests_last_round_; }
  uint32_t getSentRtxInRound() const { return sent_rtx_last_round_; }

  // bandwidth/production metrics
  double getAvailableBw() const { return 0.0; };  // TODO
  double getProducerRate() const { return production_rate_; }
  double getReceivedRate() const { return received_rate_; }
  double getReceivedFecRate() const { return fec_received_rate_; }
  double getRecoveredFecRate() const { return fec_recovered_rate_; }

  double getAveragePacketSize() const { return avg_packet_size_; }

  // nacks
  uint32_t getRoundsWithoutNacks() const { return rounds_without_nacks_; }
  uint32_t getLastSeqNacked() const { return last_seq_nacked_; }

  // producer state
  bool isProducerActive() const { return producer_is_active_; }

  // packets from cache
  // this should be called at the end of a round beacuse otherwise we may have
  // not enough packets to get a good stat
  double getPacketFromCacheRatio() const {
    if (received_data_last_round_ == 0) return 0;
    return (double)received_data_from_cache_ /
           (double)received_data_last_round_;
  }

  PendingInterestsMap::iterator getPendingInterestsMapBegin() {
    return pending_interests_.begin();
  }
  PendingInterestsMap::iterator getPendingInterestsMapEnd() {
    return pending_interests_.end();
  }

  // quality
  uint8_t getQualityScore() {
    uint8_t qs = quality_score_.getQualityScore(
        getMaxRTT(), std::round(getResidualLossRate() * 100));
    return qs;
  }

  // We received a data pkt that will be set to RECEIVED, but first we have to
  // go through FEC. We do not want to consider this pkt as recovered, thus we
  // set it as TO_BE_RECEIVED.
  void dataToBeReceived(uint32_t seq);

  // Extract RTC parameters from probes (init or RTT probes) and data packets.
  static core::ParamsRTC getProbeParams(const core::ContentObject &probe);
  static core::ParamsRTC getDataParams(const core::ContentObject &data);

 private:
  void addToPacketCache(uint32_t seq, PacketState state) {
    // this function adds or updates the current state
    if (packet_cache_.size() >= MAX_CACHED_PACKETS) {
      packet_cache_.erase(packet_cache_.begin());
    }
    packet_cache_[seq] = state;
  }

  void eraseFromPacketCache(uint32_t seq) { packet_cache_.erase(seq); }

  // update stats
  void updateState();
  void updateReceivedBytes(const core::ContentObject &content_object,
                           bool isFec);
  void updatePacketSize(const core::ContentObject &content_object);
  void updatePathStats(const core::ContentObject &content_object, bool is_nack);
  void updateLossRate(bool in_sycn);

  void addRecvOrLost(uint32_t seq, PacketState state);

  void setInitRttTimer(uint32_t wait);
  void checkInitRttTimer();

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
  uint32_t definitely_lost_pkt_;
  uint32_t first_seq_in_round_;
  uint32_t highest_seq_received_;
  uint32_t highest_seq_received_in_order_;
  uint32_t last_seq_nacked_;  // segment for which we got an oldNack
  double loss_rate_;
  double avg_loss_rate_;
  double last_round_loss_rate_;
  utils::MaxFilter<double> loss_history_;

  // per second loss rate
  uint32_t lost_per_sec_;
  uint32_t total_expected_packets_;
  double per_sec_loss_rate_;

  // conunters for residual losses
  // residual losses are computed every second and are used
  // as feedback to the upper levels (e.g application)
  uint32_t expected_packets_;
  uint32_t packets_sent_to_app_;
  uint32_t rounds_from_last_compute_;
  double residual_loss_rate_;

  // bw counters
  uint32_t received_bytes_;
  uint32_t received_fec_bytes_;
  uint32_t recovered_bytes_with_fec_;
  double avg_packet_size_;
  double production_rate_;     // rate communicated by the producer using nacks
  double received_rate_;       // rate recevied by the consumer (only data)
  double fec_received_rate_;   // fec rate recevied by the consumer
  double fec_recovered_rate_;  // rate recovered using fec

  // nack counters
  // the bool takes tracks only about the valid past nacks (no rtx) and it is
  // used to switch between the states. Instead received_nacks_last_round_ logs
  // all the nacks for statistics
  bool past_nack_on_last_round_;
  uint32_t received_nacks_last_round_;

  // packets counters
  uint32_t received_packets_last_round_;
  uint32_t received_data_last_round_;
  uint32_t received_data_from_cache_;
  uint32_t sent_interests_last_round_;
  uint32_t sent_rtx_last_round_;

  // fec counters
  uint32_t received_fec_pkt_;
  uint32_t pending_fec_pkt_;

  // round counters
  uint32_t rounds_;
  uint32_t rounds_without_nacks_;
  uint32_t rounds_without_packets_;

  // init rtt
  uint64_t first_interest_sent_time_;
  uint32_t first_interest_sent_seq_;

  // producer state
  bool
      producer_is_active_;  // the prodcuer is active if we receive some packets
  uint32_t last_production_seq_;   // last production seq received by the
                                   // producer used to init the sync protcol
  uint32_t last_prod_update_seq_;  // seq number of the last packet used to
                                   // update the update from the producer.
                                   // assumption: the highest seq number carries
                                   // the most up to date info. in case of
                                   // probes we look at the produced seq number

  // paths stats
  std::unordered_map<uint32_t, std::shared_ptr<RTCDataPath>> path_table_;
  std::shared_ptr<RTCDataPath> main_path_;

  // packet received
  // cache where to store info about the last MAX_CACHED_PACKETS
  // these are packets that are received or lost or definitely lost and are not
  // anymore in the pending intetest list
  std::map<uint32_t, PacketState> packet_cache_;

  // pending interests
  PendingInterestsMap pending_interests_;

  // indexer
  Indexer *indexer_;

  // used to keep track of the skipped interests
  uint32_t last_interest_sent_;

  // probes
  std::shared_ptr<ProbeHandler> probe_handler_;
  bool init_rtt_;
  std::unique_ptr<asio::steady_timer> init_rtt_timer_;

  // quality score
  RTCQualityScore quality_score_;

  // callbacks
  DiscoveredRttCallback discovered_rtt_callback_;
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
