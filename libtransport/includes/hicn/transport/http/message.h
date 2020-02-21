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

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

#include <hicn/transport/utils/membuf.h>

#include <map>
#include <sstream>
#include <vector>

#define HTTP_VERSION "1.1"

namespace transport {

namespace http {

typedef enum { GET, POST, PUT, PATCH, DELETE } HTTPMethod;

static std::map<HTTPMethod, std::string> method_map = {
    {GET, "GET"},     {POST, "POST"},     {PUT, "PUT"},
    {PATCH, "PATCH"}, {DELETE, "DELETE"},
};

typedef std::map<std::string, std::string> HTTPHeaders;
typedef std::unique_ptr<utils::MemBuf> HTTPPayload;

class HTTPMessage {
 public:
  virtual ~HTTPMessage() = default;

  const HTTPHeaders getHeaders() { return headers_; };

  void coalescePayloadBuffer() {
    auto it = headers_.find("Content-Length");
    if (it != headers_.end()) {
      auto content_length = std::stoul(it->second);
      payload_->gather(content_length);
    }
  }

  HTTPPayload &&getPayload() { return std::move(payload_); }

  std::string getHttpVersion() const { return http_version_; };

 protected:
  HTTPHeaders headers_;
  HTTPPayload payload_;
  std::string http_version_;
};

}  // end namespace http

}  // end namespace transport