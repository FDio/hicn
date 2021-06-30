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

#include <protocols/datagram_reassembly.h>
#include <protocols/rtc/rtc_ldr.h>
#include <protocols/rtc/rtc_rc.h>
#include <protocols/rtc/rtc_state.h>
#include <protocols/transport_protocol.h>

#include <unordered_set>
#include <vector>

namespace transport {

namespace protocol {

namespace rtc {

class RTCTransportProtocol : public TransportProtocol {
 public:
  RTCTransportProtocol(implementation::ConsumerSocket *icnet_socket);

  ~RTCTransportProtocol();

  using TransportProtocol::start;

  using TransportProtocol::stop;

  void resume() override;

  std::size_t transportHeaderLength() override;

 private:
  enum class SyncState { catch_up = 0, in_sync = 1, last };

 private:
  // setup functions
  void initParams();
  void reset() override;

  void inactiveProducer();

  // protocol functions
  void discoveredRtt();
  void newRound();

  // window functions
  void computeMaxSyncWindow();
  void updateSyncWindow();
  void decreaseSyncWindow();

  // packet functions
  void sendRtxInterest(uint32_t seq);
  void sendProbeInterest(uint32_t seq);
  void scheduleNextInterests() override;
  void onInterestTimeout(Interest::Ptr &interest, const Name &name) override;
  void onNack(const ContentObject &content_object);
  void onProbe(const ContentObject &content_object);
  void onContentObjectReceived(Interest &interest,
                               ContentObject &content_object,
                               std::error_code &ec) override;
  void onPacketDropped(Interest &interest, ContentObject &content_object,
                       const std::error_code &reason) override {}
  void onReassemblyFailed(std::uint32_t missing_segment) override {}

  // interaction with app functions
  void sendStatsToApp(uint32_t retx_count, uint32_t received_bytes,
                      uint32_t sent_interests, uint32_t lost_data,
                      uint32_t definitely_lost, uint32_t recovered_losses,
                      uint32_t received_nacks, uint32_t received_fec);

  // FEC functions
  void onFecPackets(std::vector<std::pair<uint32_t, fec::buffer>> &packets);

  // protocol state
  bool start_send_interest_;
  SyncState current_state_;
  // cwin vars
  uint32_t current_sync_win_;
  uint32_t max_sync_win_;

  // round timer
  std::unique_ptr<asio::steady_timer> round_timer_;

  // scheduler timer (postpone interest sending to explot aggregated interests)
  std::unique_ptr<asio::steady_timer> scheduler_timer_;
  bool scheduler_timer_on_;
  uint64_t last_interest_sent_time_;
  uint64_t last_interest_sent_seq_;

  // maximum aggregated interest. if the transport is connected to the forwarder
  // we cannot use aggregated interests
  uint32_t max_aggregated_interest_;
  // maximum number of intereset that can be sent in a loop to avoid packets
  // dropped by the kernel
  uint32_t max_sent_int_;

  // pacing timer (do not send too many interests in a short time to avoid
  // packet drops in the kernel)
  std::unique_ptr<asio::steady_timer> pacing_timer_;
  bool pacing_timer_on_;

  // timeouts
  std::unordered_set<uint32_t> timeouts_or_nacks_;

  std::shared_ptr<RTCState> state_;
  std::shared_ptr<RTCRateControl> rc_;
  std::shared_ptr<RTCLossDetectionAndRecovery> ldr_;

  uint32_t number_;
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
