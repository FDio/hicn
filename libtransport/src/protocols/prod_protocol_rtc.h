/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

  void registerNamespaceWithNetwork(const Prefix &producer_namespace) override;

  void setConsumerInSyncCallback(
      interface::ProducerInterestCallback &&callback) {
    on_consumer_in_sync_ = std::move(callback);
  }

 private:
  // packet handlers
  void onInterest(Interest &interest) override;
  void onError(std::error_code ec) override;
  void produceInternal(std::shared_ptr<ContentObject> &&content_object,
                       const Name &content_name);
  void sendNack(uint32_t sequence);

  // stats
  void updateStats();
  void scheduleRoundTimer();

  // pending intersts functions
  void addToInterestQueue(uint32_t interest_seg, uint64_t expiration);
  void sendNacksForPendingInterests();
  void removeFromInterestQueue(uint32_t interest_seg);
  void scheduleQueueTimer(uint64_t wait);
  void interestQueueTimer();

  core::Name flow_name_;

  uint32_t current_seg_;  // seq id of the next packet produced
  uint32_t prod_label_;   // path lable of the producer
  uint16_t header_size_;  // hicn header size

  uint32_t produced_bytes_;    // bytes produced in the last round
  uint32_t produced_packets_;  // packet produed in the last round

  uint32_t max_packet_production_;  // never exceed this number of packets
                                    // without update stats

  uint32_t bytes_production_rate_;    // bytes per sec
  uint32_t packets_production_rate_;  // pps

  std::unique_ptr<asio::steady_timer> round_timer_;
  uint64_t last_round_;

  // delayed nacks are used by the producer to avoid to send too
  // many nacks we the producer rate is 0. however, if the producer moves
  // from a production rate higher than 0 to 0 the first round the dealyed
  // should be avoided in order to notify the consumer as fast as possible
  // of the new rate.
  bool allow_delayed_nacks_;

  // queue for the received interests
  // this map maps the expiration time of an interest to
  // its sequence number. the map is sorted by timeouts
  // the same timeout may be used for multiple sequence numbers
  // but for each sequence number we store only the smallest
  // expiry time. In this way the mapping from seqs_map_ to
  // timers_map_ is unique
  std::multimap<uint64_t, uint32_t> timers_map_;

  // this map does the opposite, this map is not ordered
  std::unordered_map<uint32_t, uint64_t> seqs_map_;
  bool queue_timer_on_;
  std::unique_ptr<asio::steady_timer> interests_queue_timer_;

  // this callback is called when the remote consumer is in sync with high
  // probability. it is called only the first time that the switch happen.
  // XXX this makes sense only in P2P mode, while in standard mode is
  // impossible to know the state of the consumers so it should not be used.
  bool consumer_in_sync_;
  interface::ProducerInterestCallback on_consumer_in_sync_;
};

}  // namespace protocol

}  // end namespace transport
