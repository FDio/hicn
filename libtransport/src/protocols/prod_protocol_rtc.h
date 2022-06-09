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

#include <hicn/transport/core/name.h>
#include <protocols/production_protocol.h>
#include <protocols/rtc/rtc_verifier.h>

#include <atomic>
#include <map>
#include <mutex>

namespace transport {
namespace protocol {

class RTCProductionProtocol : public ProductionProtocol {
 public:
  RTCProductionProtocol(implementation::ProducerSocket *icn_socket);
  ~RTCProductionProtocol() override;

  using ProductionProtocol::start;
  using ProductionProtocol::stop;
  void setProducerParam() override;

  void produce(ContentObject &content_object) override;
  uint32_t produceStream(const Name &content_name,
                         std::unique_ptr<utils::MemBuf> &&buffer,
                         bool is_last = true,
                         uint32_t start_offset = 0) override;
  uint32_t produceStream(const Name &content_name, const uint8_t *buffer,
                         size_t buffer_size, bool is_last = true,
                         uint32_t start_offset = 0) override;
  uint32_t produceDatagram(const Name &content_name,
                           std::unique_ptr<utils::MemBuf> &&buffer) override;
  uint32_t produceDatagram(const Name &content_name, const uint8_t *buffer,
                           size_t buffer_size) override {
    return produceDatagram(content_name, utils::MemBuf::wrapBuffer(
                                             buffer, buffer_size, buffer_size));
  }

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  // packet handlers
  void onInterest(Interest &interest) override;
  void onError(const std::error_code &ec) override{};
  void processInterest(uint32_t interest_seg, uint32_t lifetime);
  void producePktInternal(std::shared_ptr<ContentObject> &&content_object,
                          const Name &content_name, bool fec = false);
  void produceInternal(std::shared_ptr<ContentObject> &&content_object,
                       const Name &content_name, bool fec = false);
  void sendNack(uint32_t sequence);
  void sendContentObject(std::shared_ptr<ContentObject> content_object,
                         bool nac = false, bool fec = false);

  // manifests
  void sendManifestProbe(uint32_t sequence);
  void sendManifest(const Name &content_name);
  std::shared_ptr<core::ContentObjectManifest> createManifest(
      const Name &name) const;

  // stats
  void updateStats(bool new_round);
  void scheduleRoundTimer();

  // FEC functions
  void onFecPackets(fec::BufferArray &packets);
  fec::buffer getBuffer(std::size_t size);
  void postponeFecPacket();
  void dispatchFecPacket();
  void flushFecPkts(uint32_t current_seq_num);
  // aggregated data functions
  void emptyQueue();
  void addPacketToQueue(std::unique_ptr<utils::MemBuf> &&buffer);

  core::Name flow_name_;

  std::pair<core::Packet::Format, size_t> data_header_format_;
  std::pair<core::Packet::Format, size_t> manifest_header_format_;
  std::pair<core::Packet::Format, size_t> fec_header_format_;
  std::pair<core::Packet::Format, size_t> nack_header_format_;

  uint32_t current_seg_;  // seq id of the next packet produced
  uint32_t prod_label_;   // path label of the producer
  uint32_t cache_label_;  // path label for content from the producer cache

  uint32_t prev_produced_bytes_;  // XXX clearly explain all these new vars
  uint32_t prev_produced_packets_;

  uint32_t produced_bytes_;    // bytes produced in the last round
  uint32_t produced_packets_;  // packet produed in the last round

  uint32_t max_packet_production_;  // never exceed this number of packets
                                    // without update stats

  uint32_t bytes_production_rate_;    // bytes per sec
  uint32_t packets_production_rate_;  // pps

  uint64_t last_produced_data_ts_;  // ms

  std::unique_ptr<asio::steady_timer> round_timer_;
  std::unique_ptr<asio::steady_timer> fec_pacing_timer_;

  uint64_t last_round_;

  // delayed nacks are used by the producer to avoid to send too
  // many nacks we the producer rate is 0. however, if the producer moves
  // from a production rate higher than 0 to 0 the first round the dealyed
  // should be avoided in order to notify the consumer as fast as possible
  // of the new rate.
  bool allow_delayed_nacks_;

  // Save FEC packets here before sending them
  std::queue<ContentObject::Ptr> pending_fec_packets_;
  std::queue<std::pair<uint64_t, ContentObject::Ptr>> paced_fec_packets_;
  bool pending_fec_pace_;

  // Save application packets if they are small
  std::queue<std::unique_ptr<utils::MemBuf>> waiting_app_packets_;
  uint16_t max_len_;       // len of the largest packet
  uint16_t queue_len_;     // total size of all packet in the queue
  bool data_aggregation_;  // turns on/off data aggregation
  // timer to check the queue len
  std::unique_ptr<asio::steady_timer> app_packets_timer_;
  bool data_aggregation_timer_switch_;  // bool to check if the timer is on

  // Manifest
  std::queue<std::pair<uint32_t, auth::CryptoHash>>
      manifest_entries_;  // map a packet suffix to a packet hash

  // Verifier for aggregated interests
  std::shared_ptr<rtc::RTCVerifier> verifier_;
};

}  // namespace protocol

}  // end namespace transport
