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

#include <hicn/transport/http/message.h>

#include <map>
#include <sstream>
#include <vector>

namespace transport {

namespace http {

class HTTPRequest : public HTTPMessage {
 public:
  HTTPRequest(HTTPMethod method, const std::string &url,
              const HTTPHeaders &headers, const HTTPPayload &payload);

  const std::string &getQueryString() const;

  const std::string &getPath() const;

  const std::string &getProtocol() const;

  const std::string &getLocator() const;

  const std::string &getPort() const;

  const std::string &getRequestString() const;

  const HTTPHeaders &getHeaders() override;

  const HTTPPayload &getPayload() override;

  const std::string &getHttpVersion() const override;

 private:
  std::string query_string_, path_, protocol_, locator_, port_;
  std::string request_string_;
  HTTPHeaders headers_;
  HTTPPayload payload_;
};

}  // end namespace http

}  // end namespace transport