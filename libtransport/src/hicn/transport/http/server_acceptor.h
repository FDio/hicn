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

#include <hicn/transport/http/callbacks.h>
#include <hicn/transport/http/default_values.h>
#include <hicn/transport/http/request.h>
#include <hicn/transport/http/server_publisher.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>

#include <functional>
#include <vector>

namespace transport {

namespace http {

class HTTPServerAcceptor {
  friend class HTTPServerPublisher;

 public:
  HTTPServerAcceptor(std::string &&server_locator, OnHttpRequest callback);
  HTTPServerAcceptor(std::string &server_locator, OnHttpRequest callback);

  void listen(bool async);

  std::map<int, std::shared_ptr<HTTPServerPublisher>> &getPublishers();

  //  void asyncSendResponse();

  //  HTTPClientConnection& get(std::string &url, HTTPHeaders headers = {},
  //  HTTPPayload payload = {});
  //
  //  HTTPResponse&& response();

 private:
  void processIncomingInterest(ProducerSocket &p, const Interest &interest);

  OnHttpRequest callback_;
  asio::io_service io_service_;
  std::shared_ptr<ProducerSocket> acceptor_producer_;

  std::map<int, std::shared_ptr<HTTPServerPublisher>> publishers_;
};

}  // end namespace http

}  // end namespace transport
