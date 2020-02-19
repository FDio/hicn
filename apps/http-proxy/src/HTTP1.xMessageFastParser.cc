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

#include "HTTP1.xMessageFastParser.h"

#include <hicn/transport/http/response.h>

#include <experimental/algorithm>
#include <experimental/functional>
#include <iostream>

std::string HTTPMessageFastParser::numbers = "0123456789";
std::string HTTPMessageFastParser::content_length = "Content-Length";
std::string HTTPMessageFastParser::transfer_encoding = "Transfer-Encoding";
std::string HTTPMessageFastParser::chunked = "chunked";
std::string HTTPMessageFastParser::cache_control = "Cache-Control";
std::string HTTPMessageFastParser::mpd = "mpd";
std::string HTTPMessageFastParser::connection = "Connection";
std::string HTTPMessageFastParser::separator = "\r\n\r\n";

HTTPHeaders HTTPMessageFastParser::getHeaders(const uint8_t *headers,
                                              std::size_t length) {
  HTTPHeaders ret;
  std::string http_version;
  std::string status_code;
  std::string status_string;

  if (transport::http::HTTPResponse::parseHeaders(headers, length, ret, http_version,
                                                  status_code, status_string)) {
    return ret;
  }

  throw std::runtime_error("Error parsing response headers.");
}

std::size_t HTTPMessageFastParser::hasBody(const uint8_t *headers,
                                           std::size_t length) {
  const char *buffer = reinterpret_cast<const char *>(headers);
  const char *begin = buffer;
  const char *end = buffer + length;

  using std::experimental::make_boyer_moore_searcher;
  auto it = std::experimental::search(
      begin, end,
      make_boyer_moore_searcher(content_length.begin(), content_length.end()));

  if (it != end) {
    // Read header line
    auto it2 = std::find_first_of(it, end, numbers.begin(), numbers.end());
    auto it3 = std::find(it2, end, '\n');

    return std::stoul(std::string(it2, it3));
  }

  return 0;
}

bool HTTPMessageFastParser::isMpdRequest(const uint8_t *headers,
                                         std::size_t length) {
  const char *buffer = reinterpret_cast<const char *>(headers);
  const char *begin = buffer;
  const char *end = buffer + length;

  using std::experimental::make_boyer_moore_searcher;
  auto it = std::experimental::search(
      begin, end, make_boyer_moore_searcher(mpd.begin(), mpd.end()));

  if (it != end) {
    return true;
  }

  return false;
}

uint32_t HTTPMessageFastParser::parseCacheControl(const uint8_t *headers,
                                                  std::size_t length) {
  return 0;
}
