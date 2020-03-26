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

#include <openssl/rand.h>

namespace transport {

namespace core {

Prefix::Prefix() { std::memset(&ip_prefix_, 0, sizeof(ip_prefix_t)); }

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

  ip_prefix_ = content_name.toIpAddress();
  ip_prefix_.len = prefix_length;
  ip_prefix_.family = family;
}

void Prefix::buildPrefix(std::string &prefix, uint16_t prefix_length,
                         int family) {
  if (!checkPrefixLengthAndAddressFamily(prefix_length, family)) {
    throw errors::InvalidIpAddressException();
  }

  int ret;
  switch (family) {
    case AF_INET:
      ret = inet_pton(AF_INET, prefix.c_str(), ip_prefix_.address.v4.buffer);
      break;
    case AF_INET6:
      ret = inet_pton(AF_INET6, prefix.c_str(), ip_prefix_.address.v6.buffer);
      break;
    default:
      throw errors::InvalidIpAddressException();
  }

  if (ret != 1) {
    throw errors::InvalidIpAddressException();
  }

  ip_prefix_.len = prefix_length;
  ip_prefix_.family = family;
}

std::unique_ptr<Sockaddr> Prefix::toSockaddr() {
  Sockaddr *ret = nullptr;

  switch (ip_prefix_.family) {
    case AF_INET6:
      ret = (Sockaddr *)new Sockaddr6;
      break;
    case AF_INET:
      ret = (Sockaddr *)new Sockaddr4;
      break;
    default:
      throw errors::InvalidIpAddressException();
  }

  if (ip_prefix_to_sockaddr(&ip_prefix_, ret) < 0) {
    throw errors::InvalidIpAddressException();
  }

  return std::unique_ptr<Sockaddr>(ret);
}

uint16_t Prefix::getPrefixLength() { return ip_prefix_.len; }

Prefix &Prefix::setPrefixLength(uint16_t prefix_length) {
  ip_prefix_.len = prefix_length;
  return *this;
}

int Prefix::getAddressFamily() { return ip_prefix_.family; }

Prefix &Prefix::setAddressFamily(int address_family) {
  ip_prefix_.family = address_family;
  return *this;
}

std::string Prefix::getNetwork() const {
  if (!checkPrefixLengthAndAddressFamily(ip_prefix_.len, ip_prefix_.family)) {
    throw errors::InvalidIpAddressException();
  }

  std::size_t size =
      ip_prefix_.family == 4 + AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

  std::string network(size, 0);

  if (ip_prefix_ntop_short(&ip_prefix_, (char *)network.c_str(), size) < 0) {
    throw errors::RuntimeException(
        "Impossible to retrieve network from ip address.");
  }

  return network;
}

int Prefix::contains(const ip_address_t &content_name) const {
  int res =
      ip_address_cmp(&content_name, &(ip_prefix_.address), ip_prefix_.family);

  if (ip_prefix_.len != (ip_prefix_.family == AF_INET6 ? IPV6_ADDR_LEN_BITS
                                                       : IPV4_ADDR_LEN_BITS)) {
    const u8 *ip_prefix_buffer =
        ip_address_get_buffer(&(ip_prefix_.address), ip_prefix_.family);
    const u8 *content_name_buffer =
        ip_address_get_buffer(&content_name, ip_prefix_.family);
    uint8_t mask = 0xFF >> (ip_prefix_.len % 8);
    mask = ~mask;

    res += (ip_prefix_buffer[ip_prefix_.len] & mask) ==
           (content_name_buffer[ip_prefix_.len] & mask);
  }

  return res;
}

int Prefix::contains(const core::Name &content_name) const {
  return contains(content_name.toIpAddress().address);
}

Name Prefix::getName() const {
  std::string s(getNetwork());
  return Name(s);
}

/*
 * Mask is used to apply the components to a content name that belong to this
 * prefix
 */
Name Prefix::getName(const core::Name &mask, const core::Name &components,
                     const core::Name &content_name) const {
  if (ip_prefix_.family != mask.getAddressFamily() ||
      ip_prefix_.family != components.getAddressFamily() ||
      ip_prefix_.family != content_name.getAddressFamily())
    throw errors::RuntimeException(
        "Prefix, mask, components and content name are not of the same address "
        "family");

  ip_address_t mask_ip = mask.toIpAddress().address;
  ip_address_t component_ip = components.toIpAddress().address;
  ip_address_t name_ip = content_name.toIpAddress().address;
  const u8 *mask_ip_buffer = ip_address_get_buffer(&mask_ip, ip_prefix_.family);
  const u8 *component_ip_buffer =
      ip_address_get_buffer(&component_ip, ip_prefix_.family);
  u8 *name_ip_buffer =
      const_cast<u8 *>(ip_address_get_buffer(&name_ip, ip_prefix_.family));

  int addr_len = ip_prefix_.family == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN;

  for (int i = 0; i < addr_len; i++) {
    if (mask_ip_buffer[i]) {
      name_ip_buffer[i] = component_ip_buffer[i] & mask_ip_buffer[i];
    }
  }

  if (this->contains(name_ip))
    throw errors::RuntimeException("Mask overrides the prefix");
  return Name(ip_prefix_.family, (uint8_t *)&name_ip);
}

Name Prefix::getRandomName() const {
  ip_address_t name_ip = ip_prefix_.address;
  u8 *name_ip_buffer =
      const_cast<u8 *>(ip_address_get_buffer(&name_ip, ip_prefix_.family));

  int addr_len =
      (ip_prefix_.family == AF_INET6 ? IPV6_ADDR_LEN * 8 : IPV4_ADDR_LEN * 8) -
      ip_prefix_.len;

  size_t size = (size_t)ceil((float)addr_len / 8.0);
  uint8_t *buffer = (uint8_t *) malloc(sizeof(uint8_t) * size);

  RAND_bytes(buffer, size);

  int j = 0;
  for (uint8_t i = (uint8_t)ceil((float)ip_prefix_.len / 8.0);
       i < (ip_prefix_.family == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);
       i++) {
    name_ip_buffer[i] = buffer[j];
    j++;
  }
  free(buffer);

  return Name(ip_prefix_.family, (uint8_t *)&name_ip);
}

/*
 * Map a name in a different name prefix to this name prefix
 */
Name Prefix::mapName(const core::Name &content_name) const {
  if (ip_prefix_.family != content_name.getAddressFamily())
    throw errors::RuntimeException(
        "Prefix content name are not of the same address "
        "family");

  ip_address_t name_ip = content_name.toIpAddress().address;
  const u8 *ip_prefix_buffer =
      ip_address_get_buffer(&(ip_prefix_.address), ip_prefix_.family);
  u8 *name_ip_buffer =
      const_cast<u8 *>(ip_address_get_buffer(&name_ip, ip_prefix_.family));

  memcpy(name_ip_buffer, ip_prefix_buffer, ip_prefix_.len / 8);

  if (ip_prefix_.len != (ip_prefix_.family == AF_INET6 ? IPV6_ADDR_LEN_BITS
                                                       : IPV4_ADDR_LEN_BITS)) {
    uint8_t mask = 0xFF >> (ip_prefix_.len % 8);
    name_ip_buffer[ip_prefix_.len / 8 + 1] =
        (name_ip_buffer[ip_prefix_.len / 8 + 1] & mask) |
        (ip_prefix_buffer[ip_prefix_.len / 8 + 1] & ~mask);
  }

  return Name(ip_prefix_.family, (uint8_t *)&name_ip);
}

Prefix &Prefix::setNetwork(std::string &network) {
  if (!inet_pton(AF_INET6, network.c_str(), ip_prefix_.address.v6.buffer)) {
    throw errors::RuntimeException("The network name is not valid.");
  }

  return *this;
}

Name Prefix::makeRandomName() const {
  srand((unsigned int)time(nullptr));

  if (ip_prefix_.family == AF_INET6) {
    std::default_random_engine eng((std::random_device())());
    std::uniform_int_distribution<uint32_t> idis(
        0, std::numeric_limits<uint32_t>::max());
    uint64_t random_number = idis(eng);

    uint32_t hash_size_bits = IPV6_ADDR_LEN_BITS - ip_prefix_.len;
    uint64_t ip_address[2];
    memcpy(ip_address, ip_prefix_.address.v6.buffer, sizeof(uint64_t));
    memcpy(ip_address + 1, ip_prefix_.address.v6.buffer + 8, sizeof(uint64_t));
    std::string network(IPV6_ADDR_LEN * 3, 0);

    // Let's do the magic ;)
    int shift_size = hash_size_bits > sizeof(random_number) * 8
                         ? sizeof(random_number) * 8
                         : hash_size_bits;

    ip_address[1] >>= shift_size;
    ip_address[1] <<= shift_size;

    ip_address[1] |= random_number >> (sizeof(uint64_t) * 8 - shift_size);

    if (!inet_ntop(ip_prefix_.family, ip_address, (char *)network.c_str(),
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

ip_prefix_t &Prefix::toIpPrefixStruct() { return ip_prefix_; }

}  // namespace core

}  // namespace transport
