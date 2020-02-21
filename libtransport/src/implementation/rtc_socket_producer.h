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

#include <implementation/socket_producer.h>
#include <utils/content_store.h>

#include <atomic>
#include <map>
#include <mutex>

namespace transport {
namespace implementation {

class RTCProducerSocket : virtual public ProducerSocket {
 public:
  RTCProducerSocket(interface::ProducerSocket *producer_socket);

  ~RTCProducerSocket();

  void registerPrefix(const Prefix &producer_namespace) override;
  void produce(std::unique_ptr<utils::MemBuf> &&buffer) override;

 private:
  void onInterest(Interest::Ptr &&interest) override;
  void sendNack(uint32_t sequence);
  void updateStats();
  void scheduleCacheTimer(uint64_t wait);
  void scheduleRoundTimer();
  void interestCacheTimer();

  std::atomic<uint32_t> currentSeg_;
  uint32_t prodLabel_;
  uint16_t headerSize_;
  Name flowName_;
  std::atomic<uint32_t> producedBytes_;
  std::atomic<uint32_t> producedPackets_;
  std::atomic<uint32_t> bytesProductionRate_;
  std::atomic<uint32_t> packetsProductionRate_;
  uint32_t perSecondFactor_;

  std::unique_ptr<asio::steady_timer> round_timer_;

  // cache for the received interests
  // this map maps the expiration time of an interest to
  // its sequence number. the map is sorted by timeouts
  // the same timeout may be used for multiple sequence numbers
  // but for each sequence number we store only the smallest
  // expiry time. In this way the mapping from seqs_map_ to
  // timers_map_ is unique
  std::multimap<uint64_t, uint32_t> timers_map_;
  // this map does the opposite, this map is not ordered
  std::unordered_map<uint32_t, uint64_t> seqs_map_;
  bool timer_on_;
  std::unique_ptr<asio::steady_timer> interests_cache_timer_;
  utils::SpinLock interests_cache_lock_;
};

}  // namespace implementation

}  // end namespace transport
