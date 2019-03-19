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

#pragma once

#include "common.h"

namespace icn_httpserver {

class Response : public std::ostream {
public:
  Response();

  virtual ~Response();

  size_t size();

  virtual void send(const SendCallback &callback = nullptr){};

  bool isIsLast() const;

  void setIsLast(bool is_last);

  void setResponseLength(std::size_t length);

  const std::chrono::milliseconds &getResponseLifetime() const;

  virtual void
  setResponseLifetime(const std::chrono::milliseconds &response_lifetime);

protected:
  asio::streambuf streambuf_;
  bool is_last_;
  std::size_t response_length_;
  std::chrono::milliseconds response_lifetime_;
};

} // end namespace icn_httpserver