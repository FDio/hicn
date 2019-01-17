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

#include <string>

namespace utils {

class StringTokenizer {
 public:
  StringTokenizer(const std::string &str);
  StringTokenizer(const std::string &str, const std::string &delim);

  bool hasMoreTokens();
  std::string nextToken();

 private:
  std::string str_;
  std::string delimiter_;
};

}  // namespace utils
