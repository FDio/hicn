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

#include <algorithm>
#include <string>

#include <hicn/transport/http/message.h>

using transport::http::HTTPHeaders;

class HTTPMessageFastParser {
 public:
  static HTTPHeaders getHeaders(const uint8_t* headers, std::size_t length);
  static std::size_t hasBody(const uint8_t* headers, std::size_t length);
  static bool isMpdRequest(const uint8_t* headers, std::size_t length);
  static uint32_t parseCacheControl(const uint8_t* headers, std::size_t length);

  static std::string numbers;
  static std::string content_length;
  static std::string transfer_encoding;
  static std::string chunked;
  static std::string cache_control;
  static std::string connection;
  static std::string mpd;
  static std::string separator;
};
