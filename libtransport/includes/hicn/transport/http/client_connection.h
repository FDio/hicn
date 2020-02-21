/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
  static constexpr uint32_t max_buffer_capacity = 64 * 1024;

 public:
  class ReadBytesCallback {
   public:
    virtual void onBytesReceived(std::unique_ptr<utils::MemBuf> &&buffer) = 0;
    virtual void onSuccess(std::size_t bytes) = 0;
    virtual void onError(const std::error_code ec) = 0;
  };

  enum class RC : uint32_t { DOWNLOAD_FAILED, DOWNLOAD_SUCCESS };

  HTTPClientConnection();

  ~HTTPClientConnection();

  RC get(const std::string &url, HTTPHeaders headers = {},
         HTTPPayload &&payload = nullptr,
         std::shared_ptr<HTTPResponse> response = nullptr,
         ReadBytesCallback *callback = nullptr,
         std::string ipv6_first_word = "b001");

  RC sendRequest(const std::string &url, HTTPMethod method,
                 HTTPHeaders headers = {}, HTTPPayload &&payload = nullptr,
                 std::shared_ptr<HTTPResponse> response = nullptr,
                 ReadBytesCallback *callback = nullptr,
                 std::string ipv6_first_word = "b001");

  std::shared_ptr<HTTPResponse> response();

  HTTPClientConnection &stop();

  interface::ConsumerSocket &getConsumer();

  HTTPClientConnection &setTimeout(const std::chrono::seconds &timeout);

  HTTPClientConnection &setCertificate(const std::string &cert_path);

 private:
  class Implementation;
  Implementation *implementation_;
};

}  // end namespace http

}  // end namespace transport