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
#include <hicn/transport/http/request.h>
#include <hicn/transport/http/response.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/uri.h>

#include <vector>

namespace transport {

namespace http {

using namespace interface;
using namespace core;

class HTTPClientConnection {
 public:
  HTTPClientConnection();

  HTTPClientConnection &get(const std::string &url, HTTPHeaders headers = {},
                            HTTPPayload payload = {},
                            std::shared_ptr<HTTPResponse> response = nullptr);

  HTTPClientConnection &sendRequest(
      const std::string &url, HTTPMethod method, HTTPHeaders headers = {},
      HTTPPayload payload = {},
      std::shared_ptr<HTTPResponse> response = nullptr);

  HTTPResponse &&response();

  HTTPClientConnection &stop();

  interface::ConsumerSocket &getConsumer();

  HTTPClientConnection &setTimeout(const std::chrono::seconds &timeout);

  HTTPClientConnection &setCertificate(const std::string &cert_path);

 private:
  void processPayload(interface::ConsumerSocket &c,
                      std::size_t bytes_transferred, const std::error_code &ec);

  std::string sendRequestGetReply(const HTTPRequest &request,
                                  std::shared_ptr<HTTPResponse> &response);

  bool verifyData(interface::ConsumerSocket &c,
                  const core::ContentObject &contentObject);

  void processLeavingInterest(interface::ConsumerSocket &c,
                              const core::Interest &interest,
                              std::string &payload);

  asio::io_service io_service_;

  ConsumerSocket consumer_;

  std::shared_ptr<HTTPResponse> response_;

  std::unique_ptr<asio::steady_timer> timer_;
};

}  // end namespace http

}  // end namespace transport