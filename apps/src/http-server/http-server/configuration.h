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

namespace icn_httpserver {

class Configuration {
 public:
  Configuration(unsigned short port, size_t num_threads);

  size_t getNum_threads() const;

  void setNum_threads(size_t num_threads);

  unsigned short getPort() const;

  void setPort(unsigned short port);

  const std::string &getAddress() const;

  void setAddress(const std::string &address);

  bool isReuse_address() const;

  void setReuse_address(bool reuse_address);

 private:
  size_t num_threads_;
  unsigned short port_;
  std::string address_;
  bool reuse_address_;
};

} // end namespace icn_httpserver
