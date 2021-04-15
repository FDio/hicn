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

#include <algorithm>
#include <cctype>
#include <locale>
#include <string>

namespace utils {

/**
 * Trim from start (in place)
 */
static inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                  [](int ch) { return !std::isspace(ch); }));
}

/**
 * Trim from end (in place)
 */
static inline void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](int ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

/**
 * Trim from both ends (in place)
 */
static inline void trim(std::string &s) {
  ltrim(s);
  rtrim(s);
}

/**
 * Trim from start (make a copy)
 */
static inline std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

/**
 * Trim from end (make a copy)
 */
static inline std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}

/**
 * Trim from both ends (make a copy)
 */
static inline std::string trim_copy(std::string s) {
  trim(s);
  return s;
}

}  // namespace utils