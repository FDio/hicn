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

#pragma once

#include "common.h"
#include "content.h"

using namespace std;

inline bool caseInsCharCompareN(char a, char b);

inline bool caseInsCharCompareW(wchar_t a, wchar_t b);

bool caseInsCompare(const string& s1, const string& s2);

bool caseInsCompare(const wstring& s1, const wstring& s2);

namespace icn_httpserver {

class iequal_to {
 public:
  bool operator()(const std::string &key1, const std::string &key2) const {
    return caseInsCompare(key1, key2);
  }
};

class ihash {
 public:
  size_t operator()(const std::string &key) const {
    std::size_t seed = 0;
    for (auto &c: key) {
      std::hash<char> hasher;
      seed ^= hasher(c) + 0x9e3779b9 + (seed<<6) + (seed>>2);
    }
    return seed;
  }
};

class Request {
 public:

  Request();

  virtual void read_remote_endpoint_data(socket_type &socket) {
  };

  virtual ~Request() = default;

  const std::string &getMethod() const;

  void setMethod(const std::string &method);

  const std::string &getPath() const;

  void setPath(const std::string &path);

  const std::string &getHttp_version() const;

  void setHttp_version(const std::string &http_version);

  std::unordered_multimap<std::string, std::string, ihash, iequal_to> &getHeader();

  asio::streambuf &getStreambuf() {
    return streambuf_;
  }

  Content &getContent();

  const std::smatch &getPath_match() const;

  void setPath_match(const std::smatch &path_match);

 protected:
  std::string method_, path_, http_version_;
  Content content_;
  std::unordered_multimap<std::string, std::string, ihash, iequal_to> header_;
  std::smatch path_match_;
  asio::streambuf streambuf_;
};

} // end namespace icn_httpserver
