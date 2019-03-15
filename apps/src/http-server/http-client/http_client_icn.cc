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

#include "http_client_icn.h"
#include "response.h"

#include <curl/curl.h>

using namespace std;

HTTPClientIcn::HTTPClientIcn(uint32_t timeout) {
  std::chrono::seconds _timeout(timeout);
  connection_.setTimeout(_timeout);
}

void HTTPClientIcn::setTcp() {

}

HTTPClientIcn::~HTTPClientIcn() {

}

bool HTTPClientIcn::download(const std::string& url, std::ostream& out) {
  connection_.get(url);
  libl4::http::HTTPResponse r = connection_.response();
  out.write(reinterpret_cast<const char*>(r.data()), r.size());
  return true;
}
