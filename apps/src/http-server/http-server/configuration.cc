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

#include "configuration.h"

namespace icn_httpserver {

Configuration::Configuration(unsigned short port, size_t num_threads)
    : num_threads_(num_threads), port_(port), reuse_address_(true) {
}

size_t Configuration::getNum_threads() const {
  return num_threads_;
}

void Configuration::setNum_threads(size_t num_threads) {
  Configuration::num_threads_ = num_threads;
}

unsigned short Configuration::getPort() const {
  return port_;
}

void Configuration::setPort(unsigned short port) {
  Configuration::port_ = port;
}

const std::string &Configuration::getAddress() const {
  return address_;
}

void Configuration::setAddress(const std::string &address) {
  Configuration::address_ = address;
}

bool Configuration::isReuse_address() const {
  return reuse_address_;
}

void Configuration::setReuse_address(bool reuse_address) {
  Configuration::reuse_address_ = reuse_address;
}

} // end namespace icn_httpserver