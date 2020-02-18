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
#include <hicn/transport/utils/array.h>

#include <map>
#include <sstream>
#include <vector>

namespace transport {

namespace http {

class HTTPResponse : public HTTPMessage {
 public:
  HTTPResponse();

  HTTPResponse(std::unique_ptr<utils::MemBuf> &&response);

  void appendResponseChunk(std::unique_ptr<utils::MemBuf> &&response_chunk);

  const std::string &getStatusCode() const;

  const std::string &getStatusString() const;

  void parse(std::unique_ptr<utils::MemBuf> &&response);

  bool parseHeaders(std::unique_ptr<utils::MemBuf> &&buffer);

 private:
  std::string status_code_;
  std::string status_string_;
};

}  // end namespace http

}  // end namespace transport