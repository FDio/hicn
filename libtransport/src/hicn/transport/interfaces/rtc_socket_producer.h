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

#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/content_store.h>

#include <atomic>
#include <map>
#include <mutex>

namespace transport {

namespace interface {

class RTCProducerSocket : public ProducerSocket {
 public:
  RTCProducerSocket(asio::io_service &io_service);

  RTCProducerSocket();

  ~RTCProducerSocket();

  void registerPrefix(const Prefix &producer_namespace) override;

  void produce(std::unique_ptr<utils::MemBuf> &&buffer) override;

  void onInterest(Interest::Ptr &&interest) override;

 private:
  void sendNack(uint32_t sequence, bool isActive);
  void updateStats(uint32_t packet_size, uint64_t now);
  void scheduleTimer(uint64_t wait);
  void interestCacheTimer();

  uint32_t currentSeg_;
  uint32_t prodLabel_;
  uint16_t headerSize_;
  Name flowName_;
  uint32_t producedBytes_;
  uint32_t producedPackets_;
  uint32_t bytesProductionRate_;
  std::atomic<uint32_t> packetsProductionRate_;
  uint32_t perSecondFactor_;
  uint64_t lastStats_;

  // cache for the received interests
  // this map maps the expiration time of an interest to
  // its sequence number. the map is sorted by timeouts
  // the same timeout may be used for multiple sequence numbers
  // but for each sequence number we store only the smallest
  // expiry time. In this way the mapping from seqs_map_ to
  // timers_map_ is unique
  std::multimap<uint64_t,uint32_t> timers_map_;
  // this map does the opposite, this map is not ordered
  std::unordered_map<uint32_t,uint64_t> seqs_map_;
  bool timer_on_;
  std::unique_ptr<asio::steady_timer> interests_cache_timer_;
  utils::SpinLock interests_cache_lock_;

  uint64_t lastProduced_;
  bool active_;
  utils::SpinLock lock_;
};

}  // namespace interface

}  // end namespace transport
