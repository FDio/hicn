/*
 * Copyright (c) 2017-2019 Cisco and/or its affiTC_SYNC_STATE
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

#include <queue>
#include <set>
#include <unordered_map>

#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/protocols/rtc_data_path.h>

// algorithm state
#define HICN_RTC_SYNC_STATE 0
#define HICN_RTC_NORMAL_STATE 1
#define HICN_ROUNDS_IN_SYNC_BEFORE_SWITCH 3

// packet constants
#define HICN_INIT_PACKET_SIZE 1300       // bytes
#define HICN_PACKET_HEADER_SIZE 60       // bytes ipv6+tcp
#define HICN_NACK_HEADER_SIZE 8          // bytes
#define HICN_TIMESTAMP_SIZE 8            // bytes
#define HICN_RTC_INTEREST_LIFETIME 1000  // ms

// controller constant
#define HICN_ROUND_LEN \
  200  // ms interval of time on which we take decisions / measurements
#define HICN_MAX_RTX 128
#define HICN_MIN_RTT_WIN 30  // rounds

// cwin
#define HICN_INITIAL_CWIN 1           // packets
#define HICN_INITIAL_CWIN_MAX 100000  // packets
#define HICN_MIN_CWIN 5               // packets
#define HICN_WIN_INCREASE_FACTOR 1.1
#define HICN_WIN_DECREASE_FACTOR 0.8

// statistics constants
#define HICN_BANDWIDTH_SLACK_FACTOR 1.5
#define HICN_ESTIMATED_BW_ALPHA 0.7
#define HICN_ESTIMATED_PACKET_SIZE 0.7
#define HICN_ESTIMATED_LOSSES_ALPHA 0.8
#define HICN_INTEREST_LIFETIME_REDUCTION_FACTOR 0.8

// other constants
#define HICN_NANO_IN_A_SEC 1000000000
#define HICN_MICRO_IN_A_SEC 1000000
#define HICN_MILLI_IN_A_SEC 1000

// RTCP
#define HICN_MASK_RTCP_VERSION 192
#define HICN_MASK_TYPE_CODE \
  31  // this is RC in the RR/SR packet or FMT int the early feedback packets
#define HICN_RTPC_NACK_HEADER 12  // bytes
#define HICN_MAX_RTCP_SEQ_NUMBER 0xffff
#define HICN_RTCP_VERSION 2
// RTCP TYPES
#define HICN_RTCP_SR 200
#define HICN_RTCP_RR 201
#define HICN_RTCP_SDES 202
#define HICN_RTCP_RTPFB 205
#define HICN_RTCP_PSFB 206
// RTCP RC/FMT
#define HICN_RTCP_SDES_CNAME 1
#define HICN_RTCP_RTPFB_GENERIC_NACK 1
#define HICN_RTCP_PSFB_PLI 1

namespace transport {

namespace protocol {

struct sentInterest {
  uint64_t transmissionTime;
  uint8_t retransmissions;
};

class RTCTransportProtocol : public TransportProtocol {
 public:
  RTCTransportProtocol(interface::BaseSocket *icnet_socket);

  ~RTCTransportProtocol();

  void start(utils::SharableVector<uint8_t> &content_buffer);

  void stop();

  void resume();

  void onRTCPPacket(uint8_t *packet, size_t len);

 private:
  // algo functions
  void reset();
  void checkRound();

  // CC functions
  void updateDelayStats(const ContentObject &content_object);
  void updateStats(uint32_t round_duration);
  void updateCCState();
  void computeMaxWindow(uint32_t productionRate, uint32_t BDPWin);
  void updateWindow();
  void decreaseWindow();
  void increaseWindow();
  void resetPreviousWindow();

  // packet functions
  void sendInterest();
  void scheduleNextInterest();
  void scheduleAppNackRtx(std::vector<uint32_t> &nacks);
  void onTimeout(Interest::Ptr &&interest);
  void onNack(const ContentObject &content_object);
  void onContentObject(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object);
  void returnContentToUser(const ContentObject &content_object);

  // RTCP functions
  uint32_t hICN2RTP(uint32_t hicn_seq);
  uint32_t RTP2hICN(uint32_t rtp_seq);
  void processRtcpHeader(uint8_t *offset);
  void errorParsingRtcpHeader(uint8_t *offset);
  void processSDES(uint8_t *offset);
  void processGenericNack(uint8_t *offset);
  void processPli(uint8_t *offset);

  // controller var
  std::chrono::steady_clock::time_point lastRoundBegin_;
  // bool allPacketsInSync_;
  // unsigned numberOfRoundsInSync_;
  // unsigned numberOfCatchUpRounds_;
  // bool catchUpPhase_;
  unsigned currentState_;

  // uint32_t inProduction_;

  // cwin var
  uint32_t currentCWin_;
  uint32_t maxCWin_;
  // uint32_t previousCWin_;

  // names/packets var
  uint32_t actualSegment_;
  int32_t RTPhICN_offset_;
  uint32_t inflightInterestsCount_;
  std::queue<uint32_t> interestRetransmissions_;
  std::vector<sentInterest> inflightInterests_;
  uint32_t nackedByProducerMaxSize_;
  std::set<uint32_t>
      nackedByProducer_;  // this is used to avoid retransmissions from the
                          // application for pakets for which we already got a
                          // past NACK by the producer these packet are too old,
                          // they will never be retrived
  std::shared_ptr<utils::SharableVector<uint8_t>> content_buffer_;
  uint32_t modMask_;

  // stats
  uint32_t receivedBytes_;
  uint32_t sentInterest_;
  uint32_t receivedData_;
  uint32_t packetLost_;
  double avgPacketSize_;
  bool gotNack_;
  uint32_t gotFutureNack_;
  uint32_t roundsWithoutNacks_;
  uint32_t producerPathLabel_;  // XXX we pick only one path lable for the
                                // producer for now, assuming the usage of a
                                // single path this should be extended to a
                                // vector
  std::unordered_map<uint32_t, std::shared_ptr<RTCDataPath>> pathTable_;
  uint32_t roundCounter_;
  // std::vector<uint64_t> minRTTwin_;
  uint64_t minRtt_;

  std::unordered_map<uint32_t, uint64_t> holes_;
  uint32_t lastReceived_;

  // CC var
  double estimatedBw_;
  double lossRate_;
  double queuingDelay_;
  unsigned protocolState_;
};

}  // namespace protocol

}  // namespace transport
