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

#include <glog/logging.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/portability/endianess.h>
#include <hicn/transport/utils/string_tokenizer.h>

#ifndef _WIN32
extern "C" {
#include <arpa/inet.h>
}
#else
#include <hicn/transport/portability/win_portability.h>
#endif

#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <random>

namespace transport {

namespace core {

Prefix::Prefix() { std::memset(&ip_prefix_, 0, sizeof(ip_prefix_t)); }

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

Prefix::Prefix(const std::string &prefix, uint16_t prefix_length) {
  int family = get_addr_family(prefix.c_str());
  buildPrefix(prefix, prefix_length, family);
}

Prefix::Prefix(const core::Name &content_name, uint16_t prefix_length) {
  int family = content_name.getAddressFamily();

  if (!checkPrefixLengthAndAddressFamily(prefix_length, family)) {
    throw errors::InvalidIpAddressException();
  }

  ip_prefix_ = content_name.toIpAddress();
  ip_prefix_.len = (u8)prefix_length;
  ip_prefix_.family = family;
}

void Prefix::buildPrefix(const std::string &prefix, uint16_t prefix_length,
                         int family) {
  if (!checkPrefixLengthAndAddressFamily(prefix_length, family)) {
    throw errors::InvalidIpAddressException();
  }

  std::memset(&ip_prefix_, 0, sizeof(ip_prefix_t));

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

  ip_prefix_.len = (u8)prefix_length;
  ip_prefix_.family = family;
}

bool Prefix::operator<(const Prefix &other) const {
  return ip_prefix_cmp(&ip_prefix_, &other.ip_prefix_) < 0;
}

bool Prefix::operator==(const Prefix &other) const {
  return ip_prefix_cmp(&ip_prefix_, &other.ip_prefix_) == 0;
}

std::unique_ptr<Sockaddr> Prefix::toSockaddr() const {
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

uint16_t Prefix::getPrefixLength() const { return ip_prefix_.len; }

Prefix &Prefix::setPrefixLength(uint16_t prefix_length) {
  if (!checkPrefixLengthAndAddressFamily(prefix_length, ip_prefix_.family)) {
    throw errors::InvalidIpAddressException();
  }

  ip_prefix_.len = (u8)prefix_length;
  return *this;
}

int Prefix::getAddressFamily() const { return ip_prefix_.family; }

std::string Prefix::getNetwork() const {
  if (!checkPrefixLengthAndAddressFamily(ip_prefix_.len, ip_prefix_.family)) {
    throw errors::InvalidIpAddressException();
  }

  char buffer[INET6_ADDRSTRLEN];

  if (ip_prefix_ntop_short(&ip_prefix_, buffer, INET6_ADDRSTRLEN) < 0) {
    throw errors::RuntimeException(
        "Impossible to retrieve network from ip address.");
  }

  return buffer;
}

bool Prefix::contains(const ip_address_t &content_name) const {
  uint64_t mask[2] = {0, 0};
  auto content_name_copy = content_name;
  auto network_copy = ip_prefix_.address;

  auto prefix_length = getPrefixLength();
  if (ip_prefix_.family == AF_INET) {
    prefix_length += 3 * IPV4_ADDR_LEN_BITS;
  }

  if (prefix_length == 0) {
    mask[0] = mask[1] = 0;
  } else if (prefix_length <= 64) {
    mask[0] = portability::host_to_net((uint64_t)(~0) << (64 - prefix_length));
    mask[1] = 0;
  } else if (prefix_length == 128) {
    mask[0] = mask[1] = 0xffffffffffffffff;
  } else {
    prefix_length -= 64;
    mask[0] = 0xffffffffffffffff;
    mask[1] = portability::host_to_net((uint64_t)(~0) << (64 - prefix_length));
  }

  // Apply mask
  content_name_copy.v6.as_u64[0] &= mask[0];
  content_name_copy.v6.as_u64[1] &= mask[1];

  network_copy.v6.as_u64[0] &= mask[0];
  network_copy.v6.as_u64[1] &= mask[1];

  return ip_address_cmp(&network_copy, &content_name_copy, ip_prefix_.family) ==
         0;
}

bool Prefix::contains(const core::Name &content_name) const {
  return contains(content_name.toIpAddress().address);
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
        "Prefix, mask, components and content name are not of the same"
        "address family");

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

Prefix &Prefix::setNetwork(const std::string &network) {
  if (!ip_address_pton(network.c_str(), &ip_prefix_.address)) {
    throw errors::RuntimeException("The network name is not valid.");
  }

  return *this;
}

Name Prefix::makeName() const { return makeNameWithIndex(0); }

Name Prefix::makeRandomName() const {
  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint32_t> idis(
      0, std::numeric_limits<uint32_t>::max());
  uint64_t random_number = idis(eng);

  return makeNameWithIndex(random_number);
}

Name Prefix::makeNameWithIndex(std::uint64_t index) const {
  uint16_t prefix_length = getPrefixLength();

  Name ret;

  // Adjust prefix length depending on the address family
  if (getAddressFamily() == AF_INET) {
    // Sanity check
    DCHECK(prefix_length <= 32);
    // Convert prefix length to ip46_address_t prefix length
    prefix_length += IPV4_ADDR_LEN_BITS * 3;
  }

  std::memcpy(ret.getStructReference().prefix.v6.as_u8,
              ip_prefix_.address.v6.as_u8, sizeof(ip_address_t));

  // Convert index in network byte order
  index = portability::host_to_net(index);

  // Apply mask
  uint64_t mask;
  if (prefix_length == 0) {
    mask = 0;
  } else if (prefix_length <= 64) {
    mask = 0;
  } else if (prefix_length == 128) {
    mask = 0xffffffffffffffff;
  } else {
    prefix_length -= 64;
    mask = portability::host_to_net((uint64_t)(~0) << (64 - prefix_length));
  }

  ret.getStructReference().prefix.v6.as_u64[1] &= mask;
  // Eventually truncate index if too big
  index &= ~mask;

  // Apply index
  ret.getStructReference().prefix.v6.as_u64[1] |= index;

  // Done
  return ret;
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

const ip_prefix_t &Prefix::toIpPrefixStruct() const { return ip_prefix_; }

}  // namespace core

}  // namespace transport
