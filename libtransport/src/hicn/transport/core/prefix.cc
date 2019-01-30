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

#include <hicn/transport/core/prefix.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/string_tokenizer.h>

#ifndef _WIN32
extern "C" {
#include <arpa/inet.h>
}
#else
#include <hicn/transport/portability/win_portability.h>
#endif

#include <cstring>
#include <memory>
#include <random>

namespace transport {

namespace core {

Prefix::Prefix() { std::memset(&ip_address_, 0, sizeof(ip_address_t)); }

Prefix::Prefix(const char *prefix) : Prefix(std::string(prefix)) {}

Prefix::Prefix(std::string &&prefix) : Prefix(prefix) {}

Prefix::Prefix(const std::string &prefix) {
  utils::StringTokenizer st(prefix, "/");

  std::string ip_address = st.nextToken();
  int family = get_addr_family(ip_address.c_str());

  std::string prefix_length = family == AF_INET6 ? "128" : "32";

  if (st.hasMoreTokens()) {
    prefix_length = st.nextToken();
  }

  buildPrefix(ip_address, uint16_t(atoi(prefix_length.c_str())), family);
}

Prefix::Prefix(std::string &prefix, uint16_t prefix_length) {
  int family = get_addr_family(prefix.c_str());
  buildPrefix(prefix, prefix_length, family);
}

Prefix::Prefix(const core::Name &content_name, uint16_t prefix_length) {
  int family = content_name.getAddressFamily();

  if (!checkPrefixLengthAndAddressFamily(prefix_length, family)) {
    throw errors::InvalidIpAddressException();
  }

  ip_address_ = content_name.toIpAddress();
  ip_address_.prefix_len = prefix_length;
  ip_address_.family = family;
}

void Prefix::buildPrefix(std::string &prefix, uint16_t prefix_length,
                         int family) {
  if (!checkPrefixLengthAndAddressFamily(prefix_length, family)) {
    throw errors::InvalidIpAddressException();
  }

  int ret = inet_pton(family, prefix.c_str(), ip_address_.buffer);

  if (ret != 1) {
    throw errors::InvalidIpAddressException();
  }

  ip_address_.prefix_len = prefix_length;
  ip_address_.family = family;
}

std::unique_ptr<Sockaddr> Prefix::toSockaddr() {
  Sockaddr *ret = nullptr;

  switch (ip_address_.family) {
    case AF_INET6:
      ret = (Sockaddr *)new Sockaddr6;
      break;
    case AF_INET:
      ret = (Sockaddr *)new Sockaddr4;
      break;
    default:
      throw errors::InvalidIpAddressException();
  }

  if (hicn_ip_to_sockaddr_address(&ip_address_, ret) < 0) {
    throw errors::InvalidIpAddressException();
  }

  return std::unique_ptr<Sockaddr>(ret);
}

uint16_t Prefix::getPrefixLength() { return ip_address_.prefix_len; }

Prefix &Prefix::setPrefixLength(uint16_t prefix_length) {
  ip_address_.prefix_len = prefix_length;
  return *this;
}

int Prefix::getAddressFamily() { return ip_address_.family; }

Prefix &Prefix::setAddressFamily(int address_family) {
  ip_address_.family = address_family;
  return *this;
}

std::string Prefix::getNetwork() const {
  if (!checkPrefixLengthAndAddressFamily(ip_address_.prefix_len,
                                         ip_address_.family)) {
    throw errors::InvalidIpAddressException();
  }

  std::size_t size =
      ip_address_.family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

  std::string network(size, 0);

  if (hicn_ip_ntop(&ip_address_, (char *)network.c_str(), size) < 0) {
    throw errors::RuntimeException(
        "Impossible to retrieve network from ip address.");
  }

  return network;
}

Name Prefix::getName() const {
  std::string s(getNetwork());
  return Name(s);
}

Prefix &Prefix::setNetwork(std::string &network) {
  if (!inet_pton(AF_INET6, network.c_str(), ip_address_.buffer)) {
    throw errors::RuntimeException("The network name is not valid.");
  }

  return *this;
}

Name Prefix::makeRandomName() const {
  srand(time(nullptr));

  if (ip_address_.family == AF_INET6) {
    std::default_random_engine eng((std::random_device())());
    std::uniform_int_distribution<uint32_t> idis(
        0, std::numeric_limits<uint32_t>::max());
    uint64_t random_number = idis(eng);

    uint32_t hash_size_bits = IPV6_ADDR_LEN_BITS - ip_address_.prefix_len;
    uint64_t ip_address[2];
    memcpy(ip_address, ip_address_.buffer, sizeof(uint64_t));
    memcpy(ip_address + 1, ip_address_.buffer + 8, sizeof(uint64_t));
    std::string network(IPV6_ADDR_LEN * 3, 0);

    // Let's do the magic ;)
    int shift_size = hash_size_bits > sizeof(random_number) * 8
                         ? sizeof(random_number) * 8
                         : hash_size_bits;

    ip_address[1] >>= shift_size;
    ip_address[1] <<= shift_size;

    ip_address[1] |= random_number >> (sizeof(uint64_t) * 8 - shift_size);

    if (!inet_ntop(ip_address_.family, ip_address, (char *)network.c_str(),
                   IPV6_ADDR_LEN * 3)) {
      throw errors::RuntimeException(
          "Impossible to retrieve network from ip address.");
    }

    return Name(network);
  }

  return Name();
}

bool Prefix::checkPrefixLengthAndAddressFamily(uint16_t prefix_length,
                                               int family) {
  // First check the family
  if (family != AF_INET6 && family != AF_INET) {
    return false;
  }

  int max_addr_len_bits =
      family == AF_INET6 ? IPV6_ADDR_LEN_BITS : IPV4_ADDR_LEN_BITS;

  if (prefix_length > max_addr_len_bits) {
    return false;
  }

  return true;
}

ip_address_t &Prefix::toIpAddressStruct() { return ip_address_; }

}  // namespace core

}  // namespace transport
