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

#pragma once

#include <algorithm>  // find
#include <string>

namespace utils {

class Uri {
  typedef std::string::const_iterator iterator_t;

 public:
  Uri();

  Uri &parse(const std::string &uri);

  Uri &parseProtocolAndLocator(const std::string &locator);

  std::string getQueryString();

  std::string getPath();

  std::string getProtocol();

  std::string getLocator();

  std::string getPort();

 private:
  std::string query_string_, path_, protocol_, locator_, port_;
};  // uri

}  // namespace utils
