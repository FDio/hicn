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

#include <streambuf>

namespace utils {

template <typename char_type>
struct ostreambuf
    : public std::basic_streambuf<char_type, std::char_traits<char_type> > {
  ostreambuf(char_type* buffer, std::streamsize buffer_length) {
    // set the "put" pointer the start of the buffer and record it's length.
    setp(buffer, buffer + buffer_length);
  }
};

}  // namespace utils