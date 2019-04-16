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
#include <map>
#include <unordered_map>

#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/protocols/reassembly.h>
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
#define HICN_ROUND_LEN 200  // ms interval of time on which
			    // we take decisions / measurements
#define HICN_MAX_RTX 10
#define HICN_MAX_RTX_SIZE 1024
#define HICN_MAX_RTX_MAX_AGE 10000
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

namespace transport {

namespace protocol {

enum packetState {
  sent_,
  received_,
  timeout1_,
  timeout2_,
  lost_
};

typedef enum packetState packetState_t;

struct sentInterest {
  uint64_t transmissionTime;
  uint32_t sequence;  //sequence number of the interest sent
                      //to handle seq % buffer_size
  packetState_t state; //see packet state
};

class RTCTransportProtocol : public TransportProtocol, public Reassembly {
 public:
  RTCTransportProtocol(interface::ConsumerSocket *icnet_socket);

  ~RTCTransportProtocol();

  int start() override;

  void stop() override;

  void resume() override;

 private:
  // algo functions
  void reset() override;
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
  void sendInterest(Name *interest_name, bool rtx);
  void scheduleNextInterests() override;
  void scheduleAppNackRtx(std::vector<uint32_t> &nacks);
  void addRetransmissions(uint32_t val);
  void addRetransmissions(uint32_t start, uint32_t stop);
  void retransmit(bool first_rtx);
  void checkRtx();
  void onTimeout(Interest::Ptr &&interest) override;
  // checkIfProducerIsActive: return true if we need to schedule an interest
  // immediatly after, false otherwise (this happens when the producer socket
  // is not active)
  bool checkIfProducerIsActive(const ContentObject &content_object);
  void onNack(const ContentObject &content_object);
  //funtcion used to handle nacks for retransmitted interests
  void onNackForRtx(const ContentObject &content_object);
  void onContentObject(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object) override;
  void returnContentToApplication(const ContentObject &content_object);

  TRANSPORT_ALWAYS_INLINE virtual void reassemble(
      ContentObject::Ptr &&content_object) override {
    returnContentToApplication(*content_object);
  }

  // controller var
  std::chrono::steady_clock::time_point lastRoundBegin_;
  unsigned currentState_;

  // cwin var
  uint32_t currentCWin_;
  uint32_t maxCWin_;

  // names/packets var
  uint32_t actualSegment_;
  uint32_t inflightInterestsCount_;
  //map seq to rtx
  std::map<uint32_t, uint8_t> interestRetransmissions_;
  std::unique_ptr<asio::steady_timer> rtx_timer_;
  //std::queue<uint32_t> interestRetransmissions_;
  std::vector<sentInterest> inflightInterests_;
  uint32_t lastSegNacked_; //indicates the segment id in the last received
                           // past Nack. we do not ask for retransmissions
                           //for samething that is older than this value.
  uint32_t lastReceived_; //segment of the last content object received
                          //indicates the base of the window on the client
  uint32_t nackedByProducerMaxSize_;
  std::set<uint32_t>
      nackedByProducer_;  // this is used to avoid retransmissions from the
                          // application for pakets for which we already got a
                          // past NACK by the producer these packet are too old,
                          // they will never be retrived
  bool nack_timer_used_;
  std::unique_ptr<asio::steady_timer> nack_timer_;  // timer used to schedule
  // a nack retransmission in
  // of inactive prod socket

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
  uint64_t minRtt_;

  // CC var
  double estimatedBw_;
  double lossRate_;
  double queuingDelay_;
  unsigned protocolState_;
};

}  // namespace protocol

}  // namespace transport
