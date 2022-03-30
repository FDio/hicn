/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <hicn/transport/core/name.h>

namespace transport {

namespace core {

class Prefix {
 public:
  Prefix();

  Prefix(const char *prefix);

  Prefix(const std::string &prefix);

  Prefix(std::string &&prefix);

  Prefix(std::string &prefix, uint16_t prefix_length);

  Prefix(const core::Name &content_name, uint16_t prefix_length);

  bool operator<(const Prefix &prefix) const;

  bool operator==(const Prefix &prefix) const;

  std::unique_ptr<Sockaddr> toSockaddr() const;

  uint16_t getPrefixLength() const;

  Prefix &setPrefixLength(uint16_t prefix_length);

  std::string getNetwork() const;

  int contains(const ip_address_t &content_name) const;

  int contains(const core::Name &content_name) const;

  Name getName() const;

  Name getRandomName() const;

  Name getName(const core::Name &mask, const core::Name &components,
               const core::Name &content_name) const;

  Name mapName(const core::Name &content_name) const;

  Prefix &setNetwork(std::string &network);

  int getAddressFamily() const;

  Prefix &setAddressFamily(int address_family);

  Name makeRandomName() const;

  const ip_prefix_t &toIpPrefixStruct() const;

 private:
  static bool checkPrefixLengthAndAddressFamily(uint16_t prefix_length,
                                                int family);

  void buildPrefix(std::string &prefix, uint16_t prefix_length, int family);

  ip_prefix_t ip_prefix_;
};

}  // end namespace core

}  // end namespace transport
