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

#include "icn_receiver.h"

#include <hicn/transport/core/interest.h>
#include <hicn/transport/http/default_values.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/log.h>

#include <functional>
#include <memory>

#include "HTTP1.xMessageFastParser.h"
#include "utils.h"

namespace transport {

AsyncConsumerProducer::AsyncConsumerProducer(
    asio::io_service& io_service, const std::string& prefix,
    const std::string& first_ipv6_word, const std::string& origin_address,
    const std::string& origin_port, const std::string& cache_size,
    const std::string& mtu, const std::string& content_lifetime, bool manifest)
    : prefix_(core::Prefix(generatePrefix(prefix, first_ipv6_word), 64)),
      io_service_(io_service),
      external_io_service_(true),
      producer_socket_(),
      ip_address_(origin_address),
      port_(origin_port),
      cache_size_(std::stoul(cache_size)),
      mtu_(std::stoul(mtu)),
      request_counter_(0),
      signals_(io_service_, SIGINT, SIGQUIT),
      connector_(io_service_, ip_address_, port_,
                 std::bind(&AsyncConsumerProducer::publishContent, this,
                           std::placeholders::_1, std::placeholders::_2,
                           std::placeholders::_3, std::placeholders::_4),
                 [this](asio::ip::tcp::socket& socket) -> bool {
                   std::queue<interface::PublicationOptions> empty;
                   std::swap(response_name_queue_, empty);

                   return true;
                 }),
      default_content_lifetime_(std::stoul(content_lifetime)) {
  int ret = producer_socket_.setSocketOption(
      interface::GeneralTransportOptions::OUTPUT_BUFFER_SIZE, cache_size_);

  if (ret != SOCKET_OPTION_SET) {
    TRANSPORT_LOGD("Warning: output buffer size has not been set.");
  }

  ret = producer_socket_.setSocketOption(
      interface::GeneralTransportOptions::MAKE_MANIFEST, manifest);

  if (ret != SOCKET_OPTION_SET) {
    TRANSPORT_LOGD("Warning: impossible to enable signatures.");
  }

  ret = producer_socket_.setSocketOption(
      interface::GeneralTransportOptions::DATA_PACKET_SIZE, mtu_);

  if (ret != SOCKET_OPTION_SET) {
    TRANSPORT_LOGD("Warning: mtu has not been set.");
  }

  producer_socket_.registerPrefix(prefix_);

  // Let the main thread to catch SIGINT and SIGQUIT
  signals_.async_wait(
      [this](const std::error_code& errorCode, int signal_number) {
        TRANSPORT_LOGI("Number of requests processed by plugin: %lu",
                       (unsigned long)request_counter_);
        producer_socket_.stop();
        connector_.close();
      });
}

void AsyncConsumerProducer::start() {
  TRANSPORT_LOGD("Starting listening");
  doReceive();
}

void AsyncConsumerProducer::run() {
  start();

  if (!external_io_service_) {
    io_service_.run();
  }
}

void AsyncConsumerProducer::doReceive() {
  producer_socket_.setSocketOption(
      interface::ProducerCallbacksOptions::CACHE_MISS,
      [this](interface::ProducerSocket& producer,
             interface::Interest& interest) {
        // core::Name n(interest.getWritableName(), true);
        io_service_.post(std::bind(
            &AsyncConsumerProducer::manageIncomingInterest, this,
            interest.getWritableName(), interest.acquireMemBufReference(),
            interest.getPayload().release()));
      });

  producer_socket_.connect();
}

void AsyncConsumerProducer::manageIncomingInterest(
    core::Name& name, core::Packet::MemBufPtr& packet, utils::MemBuf* payload) {
  auto seg = name.getSuffix();
  name.setSuffix(0);
  auto _it = chunk_number_map_.find(name);
  auto _end = chunk_number_map_.end();

  if (_it != _end) {
    if (_it->second.second) {
      TRANSPORT_LOGD(
          "Content is in production, interest will be satisfied shortly.");
      return;
    }

    if (seg >= _it->second.first) {
      TRANSPORT_LOGD(
          "Ignoring interest with name %s for a content object which does not "
          "exist. (Request: %u, max: %u)",
          name.toString().c_str(), (uint32_t)seg, (uint32_t)_it->second.first);
      return;
    }
  }

  bool is_mpd =
      HTTPMessageFastParser::isMpdRequest(payload->data(), payload->length());

  auto pair = chunk_number_map_.emplace(name, std::pair<uint32_t, bool>(0, 0));
  if (!pair.second) {
    pair.first->second.first = 0;
  }

  pair.first->second.second = true;

  response_name_queue_.emplace(std::move(name),
                               is_mpd ? 1000 : default_content_lifetime_);

  connector_.send(payload, [packet = std::move(packet)]() {});
}

void AsyncConsumerProducer::publishContent(const uint8_t* data,
                                           std::size_t size, bool is_last,
                                           bool headers) {
  uint32_t start_suffix = 0;

  if (response_name_queue_.empty()) {
    std::cerr << "Aborting due tue empty request queue" << std::endl;
    abort();
  }

  interface::PublicationOptions& options = response_name_queue_.front();

  int ret = producer_socket_.setSocketOption(
      interface::GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
      options.getLifetime());

  if (TRANSPORT_EXPECT_FALSE(ret != SOCKET_OPTION_SET)) {
    TRANSPORT_LOGD("Warning: content object lifetime has not been set.");
  }

  const interface::Name& name = options.getName();

  auto it = chunk_number_map_.find(name);
  if (it == chunk_number_map_.end()) {
    std::cerr << "Aborting due to response not found in ResposeInfo map."
              << std::endl;
    abort();
  }

  start_suffix = it->second.first;

  if (headers) {
    request_counter_++;
  }

  it->second.first +=
      producer_socket_.produce(name, data, size, is_last, start_suffix);

  if (is_last) {
    it->second.second = false;
    response_name_queue_.pop();
  }
}

}  // namespace transport
