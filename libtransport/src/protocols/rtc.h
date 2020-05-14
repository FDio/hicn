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

#include <protocols/datagram_reassembly.h>
#include <protocols/protocol.h>
#include <protocols/rtc_data_path.h>

#include <map>
#include <queue>
#include <unordered_map>

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

// rtt measurement
// normal interests for data goes from 0 to
// HICN_MIN_PROBE_SEQ, the rest is reserverd for
// probes
#define HICN_MIN_PROBE_SEQ 0xefffffff
#define HICN_MAX_PROBE_SEQ 0xffffffff

// controller constant
#define HICN_ROUND_LEN \
  200  // ms interval of time on which
       // we take decisions / measurements
#define HICN_MAX_RTX 10
#define HICN_MAX_RTX_SIZE 1024
#define HICN_MAX_RTX_MAX_AGE 10000
#define HICN_MIN_RTT_WIN 30             // rounds
#define HICN_MIN_INTER_ARRIVAL_GAP 100  // ms

// cwin
#define HICN_INITIAL_CWIN 1           // packets
#define HICN_INITIAL_CWIN_MAX 100000  // packets
#define HICN_MIN_CWIN 10              // packets
#define HICN_WIN_INCREASE_FACTOR 1.5
#define HICN_WIN_DECREASE_FACTOR 0.9

// statistics constants
#define HICN_BANDWIDTH_SLACK_FACTOR 1.8
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

enum packetState { sent_, nacked_, received_, timeout1_, timeout2_, lost_ };

typedef enum packetState packetState_t;

struct sentInterest {
  uint64_t transmissionTime;
  uint32_t sequence;    // sequence number of the interest sent
                        // to handle seq % buffer_size
  packetState_t state;  // see packet state
};

class RTCTransportProtocol : public TransportProtocol,
                             public DatagramReassembly {
 public:
  RTCTransportProtocol(implementation::ConsumerSocket *icnet_socket);

  ~RTCTransportProtocol();

  int start() override;

  void stop() override;

  void resume() override;

  bool verifyKeyPackets() override;

 private:
  // algo functions
  void reset() override;

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
  void sentinelTimer();
  void addRetransmissions(uint32_t val);
  void addRetransmissions(uint32_t start, uint32_t stop);
  uint64_t retransmit();
  void checkRtx();
  void probeRtt();
  void newRound();
  void onTimeout(Interest::Ptr &&interest) override;
  bool onNack(const ContentObject &content_object, bool rtx);
  void onContentObject(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object) override;
  void onPacketDropped(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object) override {}
  void onReassemblyFailed(std::uint32_t missing_segment) override {}

  TRANSPORT_ALWAYS_INLINE virtual void reassemble(
      ContentObject::Ptr &&content_object) override {
    auto read_buffer = content_object->getPayload();
    read_buffer->trimStart(HICN_TIMESTAMP_SIZE);
    Reassembly::read_buffer_ = std::move(read_buffer);
    Reassembly::notifyApplication();
  }

  // controller var
  std::unique_ptr<asio::steady_timer> round_timer_;
  unsigned currentState_;

  // cwin var
  uint32_t currentCWin_;
  uint32_t maxCWin_;

  // names/packets var
  uint32_t actualSegment_;
  uint32_t inflightInterestsCount_;
  // map seq to rtx
  std::map<uint32_t, uint8_t> interestRetransmissions_;
  bool rtx_timer_used_;
  std::unique_ptr<asio::steady_timer> rtx_timer_;
  std::vector<sentInterest> inflightInterests_;
  uint32_t lastSegNacked_;     // indicates the segment id in the last received
                               // past Nack. we do not ask for retransmissions
                               // for samething that is older than this value.
  uint32_t lastReceived_;      // segment of the last content object received
                               // indicates the base of the window on the client
  uint64_t lastReceivedTime_;  // time at which we recevied the
                               // lastReceived_ packet

  // sentinel
  // if all packets in the window get lost we need something that
  // wakes up our consumer socket. Interest timeouts set to 1 sec
  // expire too late. This timers expire much sooner and if it
  // detects that all the interest in the window may be lost
  // it sends all of them again
  std::unique_ptr<asio::steady_timer> sentinel_timer_;
  uint64_t lastEvent_;  // time at which we removed a pending
                        // interest from the window
  std::unordered_map<uint32_t, uint8_t> packets_in_window_;

  // rtt probes
  // the RTC transport tends to overestimate the RTT
  // du to the production time on the server side
  // once per second we send an interest for wich we know
  // we will get a nack. This nack will keep our estimation
  // close to the reality
  std::unique_ptr<asio::steady_timer> probe_timer_;
  uint64_t time_sent_probe_;
  uint32_t probe_seq_number_;
  bool received_probe_;

  uint32_t modMask_;

  // stats
  bool firstPckReceived_;
  uint32_t receivedBytes_;
  uint32_t sentInterest_;
  uint32_t receivedData_;
  int32_t packetLost_;
  int32_t lossRecovered_;
  uint32_t firstSequenceInRound_;
  uint32_t highestReceived_;
  double avgPacketSize_;
  bool gotNack_;
  uint32_t gotFutureNack_;
  uint32_t rounds_;
  uint32_t roundsWithoutNacks_;

  // we keep track of up two paths (if only one path is in use
  // the two values in the vector will be the same)
  // position 0 stores the path with minRTT
  // position 1 stores the path with maxRTT
  uint32_t producerPathLabels_[2];

  std::unordered_map<uint32_t, std::shared_ptr<RTCDataPath>> pathTable_;
  uint32_t roundCounter_;

  // CC var
  double estimatedBw_;
  double lossRate_;
  double queuingDelay_;
  unsigned protocolState_;

  bool initied;
};

}  // namespace protocol

}  // namespace transport
