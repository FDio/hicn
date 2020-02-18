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

}  // namespace http

}  // namespace transport