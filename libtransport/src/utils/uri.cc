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

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/utils/uri.h>

namespace utils {

Uri::Uri() {}

Uri &Uri::parse(const std::string &uri) {
  if (uri.length() == 0) {
    throw errors::RuntimeException("Malformed URI.");
  }

  iterator_t uri_end = uri.end();

  // get query start
  iterator_t query_start = std::find(uri.begin(), uri_end, '?');

  // protocol
  iterator_t protocol_start = uri.begin();
  iterator_t protocol_end = std::find(protocol_start, uri_end, ':');  //"://");

  if (protocol_end != uri_end) {
    std::string prot = &*(protocol_end);
    if ((prot.length() > 3) && (prot.substr(0, 3) == "://")) {
      protocol_ = std::string(protocol_start, protocol_end);
      protocol_end += 3;  //      ://
    } else {
      protocol_end = uri.begin();  // no protocol
    }
  } else {
    protocol_end = uri.begin();  // no protocol
  }
  // host
  iterator_t host_start = protocol_end;
  iterator_t path_start =
      std::find(host_start, uri_end, '/');  // get path_start

  iterator_t host_end = std::find(
      protocol_end, (path_start != uri_end) ? path_start : query_start,
      ':');  // check for port

  locator_ = std::string(host_start, host_end);

  // port
  if ((host_end != uri_end) && ((&*(host_end))[0] == ':')) {
    host_end++;
    iterator_t port_end = (path_start != uri_end) ? path_start : query_start;
    port_ = std::string(host_end, port_end);
  }

  // path
  if (path_start != uri_end) {
    path_ = std::string(path_start, query_start);
  }
  // query
  if (query_start != uri_end) {
    query_string_ = std::string(query_start, uri.end());
  }

  return *this;
}

Uri &Uri::parseProtocolAndLocator(const std::string &locator) {
  iterator_t total_end = locator.end();

  // protocol
  iterator_t protocol_start = locator.begin();
  iterator_t protocol_end =
      std::find(protocol_start, total_end, ':');  //"://");

  if (protocol_end != total_end) {
    std::string prot = &*(protocol_end);
    if ((prot.length() > 3) && (prot.substr(0, 3) == "://")) {
      protocol_ = std::string(protocol_start, protocol_end);
      protocol_end += 3;  //      ://
    } else {
      throw errors::RuntimeException("Malformed locator. (Missing \"://\")");
    }
  } else {
    throw errors::RuntimeException("Malformed locator. No protocol specified.");
  }

  // locator
  iterator_t host_start = protocol_end;
  iterator_t host_end = std::find(protocol_end, total_end, '/');

  if (host_start == host_end) {
    throw errors::RuntimeException(
        "Malformed locator. Locator name is missing");
  }

  locator_ = std::string(host_start, host_end);

  return *this;
}

std::string Uri::getLocator() { return locator_; }

std::string Uri::getPath() { return path_; }

std::string Uri::getPort() { return port_; }

std::string Uri::getProtocol() { return protocol_; }

std::string Uri::getQueryString() { return query_string_; }

}  // end namespace utils
