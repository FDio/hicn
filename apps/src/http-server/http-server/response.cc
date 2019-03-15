/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include "common.h"
#include "response.h"

#define DEFAULT_LIFETIME 1000 * 1000

namespace icn_httpserver {

Response::Response()
    : std::ostream(&streambuf_),
      is_last_(false),
      response_length_(0),
      response_lifetime_(DEFAULT_LIFETIME) {
}

Response::~Response() {
}

std::size_t Response::size() {
  return streambuf_.size();
}

bool Response::isIsLast() const {
  return is_last_;
}

void Response::setIsLast(bool is_last) {
  Response::is_last_ = is_last;
}

const std::chrono::milliseconds &Response::getResponseLifetime() const {
  return response_lifetime_;
}

void Response::setResponseLifetime(const std::chrono::milliseconds &response_lifetime) {
  Response::response_lifetime_ = response_lifetime;
}

void Response::setResponseLength(std::size_t length) {
  response_length_ = length;
}

} // end namespace icn_httpserver
