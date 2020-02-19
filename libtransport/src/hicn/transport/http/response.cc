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

#include <hicn/transport/errors/errors.h>
#include <hicn/transport/http/response.h>

#include <experimental/algorithm>
#include <experimental/functional>

#include <cstring>

namespace transport {

namespace http {

HTTPResponse::HTTPResponse() {}

HTTPResponse::HTTPResponse(std::unique_ptr<utils::MemBuf> &&response) {
  parse(std::move(response));
}

void HTTPResponse::appendResponseChunk(
    std::unique_ptr<utils::MemBuf> &&response_chunk) {
  if (headers_.empty()) {
    parse(std::move(response_chunk));
  } else {
    payload_->prependChain(std::move(response_chunk));
  }
}

bool HTTPResponse::parseHeaders(std::unique_ptr<utils::MemBuf> &&buffer) {
  auto ret =
      HTTPResponse::parseHeaders(buffer->data(), buffer->length(), headers_,
                                 http_version_, status_code_, status_string_);

  if (ret) {
    buffer->trimStart(ret);
    payload_ = std::move(buffer);
    return true;
  }

  return false;
}

std::size_t HTTPResponse::parseHeaders(const uint8_t *buffer, std::size_t size,
                                       HTTPHeaders &headers,
                                       std::string &http_version,
                                       std::string &status_code,
                                       std::string &status_string) {
  const char *crlf2 = "\r\n\r\n";
  const char *begin = (const char *)buffer;
  const char *end = begin + size;
  auto it =
      std::experimental::search(begin, end,
                                std::experimental::make_boyer_moore_searcher(
                                    crlf2, crlf2 + strlen(crlf2)));

  if (it != end) {
    std::stringstream ss;
    ss.str(std::string(begin, it));

    std::string line;
    getline(ss, line);
    std::istringstream line_s(line);
    std::string _http_version;

    line_s >> _http_version;
    std::size_t separator;
    if ((separator = _http_version.find('/')) != std::string::npos) {
      if (_http_version.substr(0, separator) != "HTTP") {
        return 0;
      }
      http_version =
          line.substr(separator + 1, _http_version.length() - separator - 1);
    } else {
      return 0;
    }

    std::string _status_string;

    line_s >> status_code;
    line_s >> _status_string;

    auto _it = std::search(line.begin(), line.end(), status_string.begin(),
                           status_string.end());

    status_string = std::string(_it, line.end() - 1);

    std::size_t param_end;
    std::size_t value_start;
    while (getline(ss, line)) {
      if ((param_end = line.find(':')) != std::string::npos) {
        value_start = param_end + 1;
        if ((value_start) < line.size()) {
          if (line[value_start] == ' ') {
            value_start++;
          }
          if (value_start < line.size()) {
            headers[line.substr(0, param_end)] =
                line.substr(value_start, line.size() - value_start - 1);
          }
        }
      } else {
        return 0;
      }
    }
  }

  return it + strlen(crlf2) - begin;
}

void HTTPResponse::parse(std::unique_ptr<utils::MemBuf> &&response) {
  if (!parseHeaders(std::move(response))) {
    throw errors::RuntimeException("Malformed HTTP response");
  }
}

const std::string &HTTPResponse::getStatusCode() const { return status_code_; }

const std::string &HTTPResponse::getStatusString() const {
  return status_string_;
}

}  // namespace http

}  // namespace transport