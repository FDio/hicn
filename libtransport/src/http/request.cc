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

#include <hicn/transport/http/request.h>
#include <hicn/transport/utils/uri.h>

namespace transport {

namespace http {

HTTPRequest::HTTPRequest() {}

HTTPRequest::HTTPRequest(HTTPMethod method, const std::string &url,
                         const HTTPHeaders &headers, HTTPPayload &&payload) {
  init(method, url, headers, std::move(payload));
}

void HTTPRequest::init(HTTPMethod method, const std::string &url,
                       const HTTPHeaders &headers, HTTPPayload &&payload) {
  utils::Uri uri;
  uri.parse(url);

  path_ = uri.getPath();
  query_string_ = uri.getQueryString();
  protocol_ = uri.getProtocol();
  locator_ = uri.getLocator();
  port_ = uri.getPort();
  http_version_ = HTTP_VERSION;

  headers_ = headers;
  payload_ = std::move(payload);

  std::transform(locator_.begin(), locator_.end(), locator_.begin(), ::tolower);

  std::transform(protocol_.begin(), protocol_.end(), protocol_.begin(),
                 ::tolower);

  std::stringstream stream;
  stream << method_map[method] << " " << uri.getPath() << " HTTP/"
         << HTTP_VERSION << "\r\n";
  for (auto &item : headers) {
    stream << item.first << ": " << item.second << "\r\n";
  }
  stream << "\r\n";
  request_string_ = stream.str();
}

std::string HTTPRequest::getPort() const { return port_; }

std::string HTTPRequest::getLocator() const { return locator_; }

std::string HTTPRequest::getProtocol() const { return protocol_; }

std::string HTTPRequest::getPath() const { return path_; }

std::string HTTPRequest::getQueryString() const { return query_string_; }

std::string HTTPRequest::getRequestString() const { return request_string_; }

std::size_t HTTPRequest::parseHeaders(const uint8_t *buffer, std::size_t size,
                                      HTTPHeaders &headers,
                                      std::string &http_version,
                                      std::string &method, std::string &url) {
  const char *crlf2 = "\r\n\r\n";
  const char *begin = (const char *)buffer;
  const char *end = begin + size;
  const char *begincrlf2 = (const char *)crlf2;
  const char *endcrlf2 = begincrlf2 + strlen(crlf2);
  auto it = std::search(begin, end, begincrlf2, endcrlf2);

  if (it != end) {
    std::stringstream ss;
    ss.str(std::string(begin, it + 2));

    std::string line;
    getline(ss, line);
    std::istringstream line_s(line);
    std::string _http_version;

    line_s >> method;
    line_s >> url;
    line_s >> _http_version;
    std::size_t separator;
    if ((separator = _http_version.find('/')) != std::string::npos) {
      if (_http_version.substr(0, separator) != "HTTP") {
        return 0;
      }
      http_version = _http_version.substr(
          separator + 1, _http_version.length() - separator - 1);
    } else {
      return 0;
    }

    std::size_t param_end;
    std::size_t value_start;
    std::string header_key, header_value;
    while (getline(ss, line)) {
      if ((param_end = line.find(':')) != std::string::npos) {
        value_start = param_end + 1;
        if ((value_start) < line.size()) {
          if (line[value_start] == ' ') {
            value_start++;
          }
          if (value_start < line.size()) {
            header_key = line.substr(0, param_end);
            header_value =
                line.substr(value_start, line.size() - value_start - 1);
            std::transform(header_key.begin(), header_key.end(),
                           header_key.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            std::transform(header_value.begin(), header_value.end(),
                           header_value.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            headers[header_key] = header_value;
          }
        }
      } else {
        return 0;
      }
    }
  }

  return it + strlen(crlf2) - begin;
}

}  // namespace http

}  // namespace transport