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

#include "request.h"

using namespace std;

inline bool caseInsCharCompareN(char a, char b) {
   return(toupper(a) == toupper(b));
}

inline bool caseInsCharCompareW(wchar_t a, wchar_t b) {
   return(towupper(a) == towupper(b));
}

bool caseInsCompare(const string& s1, const string& s2) {
   return((s1.size() == s2.size()) &&
          equal(s1.begin(), s1.end(), s2.begin(), caseInsCharCompareN));
}

bool caseInsCompare(const wstring& s1, const wstring& s2) {
   return((s1.size() == s2.size()) &&
          equal(s1.begin(), s1.end(), s2.begin(), caseInsCharCompareW));
}

namespace icn_httpserver {

Request::Request()
    : content_(streambuf_) {
}

const std::string &Request::getMethod() const {
  return method_;
}

void Request::setMethod(const std::string &method) {
  Request::method_ = method;
}

const std::string &Request::getPath() const {
  return path_;
}

void Request::setPath(const std::string &path) {
  Request::path_ = path;
}

const std::string &Request::getHttp_version() const {
  return http_version_;
}

void Request::setHttp_version(const std::string &http_version) {
  Request::http_version_ = http_version;
}

std::unordered_multimap<std::string, std::string, ihash, iequal_to> &Request::getHeader() {
  return header_;
}

Content &Request::getContent() {
  return content_;
}

const std::smatch &Request::getPath_match() const {
  return path_match_;
}

void Request::setPath_match(const std::smatch &path_match) {
  Request::path_match_ = path_match;
}

} // end namespace icn_httpserver
