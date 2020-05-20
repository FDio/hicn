/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <hicn/transport/core/prefix.h>
#include <hicn/transport/interfaces/publication_options.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/spinlock.h>

#include <asio.hpp>
#include <cassert>
#include <cstring>
#include <queue>
#include <utility>

#include "http_session.h"

namespace transport {

class AsyncConsumerProducer {
  using SegmentProductionPair = std::pair<uint32_t, bool>;
  using ResponseInfoMap = std::unordered_map<core::Name, SegmentProductionPair>;
  using RequestQueue = std::queue<interface::PublicationOptions>;

 public:
  explicit AsyncConsumerProducer(
      asio::io_service& io_service, const std::string& prefix,
      const std::string& first_ipv6_word, const std::string& origin_address,
      const std::string& origin_port, const std::string& cache_size,
      const std::string& mtu, const std::string& content_lifetime,
      bool manifest);

  explicit AsyncConsumerProducer(
      const std::string& prefix, const std::string& first_ipv6_word,
      const std::string& origin_address, const std::string& origin_port,
      const std::string& cache_size, const std::string& mtu,
      const std::string& content_lifetime, bool manifest)
      : AsyncConsumerProducer(internal_io_service_, prefix, first_ipv6_word,
                              origin_address, origin_port, cache_size, mtu,
                              content_lifetime, manifest) {
    external_io_service_ = false;
  }

  void run();

 private:
  void start();

  void doSend();

  void doReceive();

  void publishContent(const uint8_t* data, std::size_t size,
                      bool is_last = true, bool headers = false);

  void manageIncomingInterest(core::Name& name, core::Packet::MemBufPtr& packet,
                              utils::MemBuf* payload);

  core::Prefix prefix_;
  asio::io_service& io_service_;
  asio::io_service internal_io_service_;
  bool external_io_service_;
  interface::ProducerSocket producer_socket_;

  std::string ip_address_;
  std::string port_;
  uint32_t cache_size_;
  uint32_t mtu_;

  uint64_t request_counter_;
  asio::signal_set signals_;

  // std::unordered_map<core::Name, std::shared_ptr<ATSConnector>>
  // connection_map_;
  HTTPSession connector_;

  unsigned long default_content_lifetime_;

  // ResponseInfoMap --> max_seq_number + bool indicating whether request is in
  // production
  ResponseInfoMap chunk_number_map_;
  RequestQueue response_name_queue_;
};

}  // namespace transport
