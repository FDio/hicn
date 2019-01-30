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

#include <hicn/transport/http/default_values.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>

#include <functional>
#include <vector>

namespace transport {

namespace http {

using namespace interface;
using namespace core;

class HTTPServerPublisher {
 public:
  HTTPServerPublisher(const core::Name &content_name);

  ~HTTPServerPublisher();

  void publishContent(const uint8_t *buf, size_t buffer_size,
                      std::chrono::milliseconds content_lifetime, bool is_last);

  template <typename Handler>
  void asyncPublishContent(const uint8_t *buf, size_t buffer_size,
                           std::chrono::milliseconds content_lifetime,
                           Handler &&handler, bool is_last);

  void serveClients();

  void stop();

  ProducerSocket &getProducer();

  HTTPServerPublisher &setTimeout(const std::chrono::milliseconds &timeout,
                                  bool timeout_renewal);

  HTTPServerPublisher &attachPublisher();

  void setPublisherName(std::string &name, std::string &mask);

 private:
  Name content_name_;
  std::unique_ptr<asio::steady_timer> timer_;
  asio::io_service io_service_;
  std::unique_ptr<ProducerSocket> producer_;
  ProducerInterestCallback interest_enter_callback_;
  utils::UserCallback wait_callback_;

  utils::SharableVector<uint8_t> receive_buffer_;
};

}  // end namespace http

}  // end namespace transport
