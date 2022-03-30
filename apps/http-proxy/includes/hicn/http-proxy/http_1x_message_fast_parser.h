/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <algorithm>
#include <string>

using transport::http::HTTPHeaders;

namespace transport {
struct Metadata;
}

class HTTPMessageFastParser {
 public:
  static constexpr char http_ok[] =
      "HTTP/1.1 200 OK\r\n"
      "Access-Control-Allow-Origin: *\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n\r\n";

  static constexpr char http_cors[] =
      "HTTP/1.1 200 OK\r\n"
      "Date: %s\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n"
      "Access-Control-Allow-Origin: *\r\n"
      "Access-Control-Allow-Methods: GET\r\n"
      "Access-Control-Allow-Headers: hicn\r\n"
      "Access-Control-Max-Age: 1800\r\n\r\n";

  static constexpr char http_failed[] =
      "HTTP/1.1 500 Internal Server Error\r\n"
      "Date: %s\r\n"
      "Content-Length: 0\r\nConnection: "
      "close\r\n\r\n";

  static void getHeaders(const uint8_t* headers, std::size_t length,
                         bool request, transport::Metadata* metadata);
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
