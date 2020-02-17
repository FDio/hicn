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

#include "IcnReceiver.h"
#include "HTTP1.xMessageFastParser.h"

#include <hicn/transport/http/default_values.h>
#include <hicn/transport/utils/hash.h>

#include <functional>
#include <memory>

namespace transport {

core::Prefix generatePrefix(const std::string& prefix_url,
                            std::string& first_ipv6_word) {
  const char* str = prefix_url.c_str();
  uint16_t pos = 0;

  if (strncmp("http://", str, 7) == 0) {
    pos = 7;
  } else if (strncmp("https://", str, 8) == 0) {
    pos = 8;
  }

  str += pos;

  uint32_t locator_hash = utils::hash::fnv32_buf(str, strlen(str));

  std::stringstream stream;
  stream << first_ipv6_word << ":0";

  for (uint16_t* word = (uint16_t*)&locator_hash;
       std::size_t(word) < (std::size_t(&locator_hash) + sizeof(locator_hash));
       word++) {
    stream << ":" << std::hex << *word;
  }

  stream << "::0";

  return core::Prefix(stream.str(), 64);
}

AsyncConsumerProducer::AsyncConsumerProducer(
    const std::string& prefix, std::string& ip_address, std::string& port,
    std::string& cache_size, std::string& mtu, std::string& first_ipv6_word,
    unsigned long default_lifetime, bool manifest)
    : prefix_(generatePrefix(prefix, first_ipv6_word)),
      producer_socket_(),
      ip_address_(ip_address),
      port_(port),
      cache_size_(std::stoul(cache_size)),
      mtu_(std::stoul(mtu)),
      request_counter_(0),
      signals_(io_service_, SIGINT, SIGQUIT),
      connector_(io_service_, ip_address_, port_,
                 std::bind(&AsyncConsumerProducer::publishContent, this,
                           std::placeholders::_1, std::placeholders::_2,
                           std::placeholders::_3, std::placeholders::_4),
                 [this]() {
                   std::queue<interface::PublicationOptions> empty;
                   std::swap(response_name_queue_, empty);
                 }),
      default_content_lifetime_(default_lifetime) {
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
  io_service_.run();
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

  std::cout << "Received interest " << seg << std::endl;

  if (_it != _end) {
    if (_it->second.second) {
      // Content is in production
      return;
    }

    if (seg >= _it->second.first) {
      TRANSPORT_LOGI(
          "Ignoring interest with name %s for a content object which does not "
          "exist. (Request: %u, max: %u)",
          name.toString().c_str(), (uint32_t)seg, (uint32_t)_it->second.first);
      return;
    }
  }

  std::cout << "Received interest " << seg << std::endl;

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
