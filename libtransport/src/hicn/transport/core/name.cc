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

#include <hicn/transport/core/manifest_format.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/errors/tokenizer_exception.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/string_tokenizer.h>

namespace transport {

namespace core {

Name::Name() { name_ = {}; }

Name::Name(int family, const uint8_t *ip_address, std::uint32_t suffix)
    : name_({}) {
  name_.type = HNT_UNSPEC;
  std::size_t length;
  uint8_t *dst = NULL;

  if (family == AF_INET) {
    dst = name_.ip4.prefix_as_u8;
    length = IPV4_ADDR_LEN;
    name_.type = HNT_CONTIGUOUS_V4;
  } else if (family == AF_INET6) {
    dst = name_.ip6.prefix_as_u8;
    length = IPV6_ADDR_LEN;
    name_.type = HNT_CONTIGUOUS_V6;
  } else {
    throw errors::RuntimeException("Specified name family does not exist.");
  }

  std::memcpy(dst, ip_address, length);
  *reinterpret_cast<std::uint32_t *>(dst + length) = suffix;
}

Name::Name(const char *name, uint32_t segment) {
  name_.type = HNT_UNSPEC;
  if (hicn_name_create(name, segment, &name_) < 0) {
    throw errors::InvalidIpAddressException();
  }
}

Name::Name(const std::string &uri, uint32_t segment)
    : Name(uri.c_str(), segment) {}

Name::Name(const std::string &uri) {
  name_.type = HNT_UNSPEC;
  utils::StringTokenizer tokenizer(uri, "|");
  std::string ip_address;
  std::string seq_number;

  ip_address = tokenizer.nextToken();

  try {
    seq_number = tokenizer.nextToken();
  } catch (errors::TokenizerException &) {
    seq_number = "0";
  }

  if (hicn_name_create(ip_address.c_str(), (uint32_t)atoi(seq_number.c_str()),
                       &name_) < 0) {
    throw errors::InvalidIpAddressException();
  }
}

Name::Name(const Name &name) { this->name_ = name.name_; }

Name &Name::operator=(const Name &name) {
  if (hicn_name_copy(&this->name_, &name.name_) < 0) {
    throw errors::MalformedNameException();
  }

  return *this;
}

bool Name::operator==(const Name &name) const {
  return this->equals(name, true);
}

bool Name::operator!=(const Name &name) const {
  return !this->operator==(name);
}

Name::operator bool() const {
  return bool(hicn_name_empty((hicn_name_t *)&name_));
}

bool Name::equals(const Name &name, bool consider_segment) const {
  return !hicn_name_compare(&name_, &name.name_, consider_segment);
}

std::string Name::toString() const {
  char *name = new char[100];
  int ret = hicn_name_ntop(&name_, name, standard_name_string_length);
  if (ret < 0) {
    throw errors::MalformedNameException();
  }
  std::string name_string(name);
  delete[] name;

  return name_string;
}

uint32_t Name::getHash32(bool consider_suffix) const {
  uint32_t hash;
  if (hicn_name_hash(&name_, &hash, consider_suffix) < 0) {
    throw errors::RuntimeException("Error computing the hash of the name!");
  }
  return hash;
}

void Name::clear() { name_.type = HNT_UNSPEC; };

Name::Type Name::getType() const { return name_.type; }

uint32_t Name::getSuffix() const {
  uint32_t ret = 0;
  if (hicn_name_get_seq_number((hicn_name_t *)&name_, &ret) < 0) {
    throw errors::RuntimeException(
        "Impossible to retrieve the sequence number from the name.");
  }
  return ret;
}

Name &Name::setSuffix(uint32_t seq_number) {
  if (hicn_name_set_seq_number(&name_, seq_number) < 0) {
    throw errors::RuntimeException(
        "Impossible to set the sequence number to the name.");
  }

  return *this;
}

std::shared_ptr<Sockaddr> Name::getAddress() const {
  Sockaddr *ret = nullptr;

  switch (name_.type) {
    case HNT_CONTIGUOUS_V4:
    case HNT_IOV_V4:
      ret = (Sockaddr *)new Sockaddr4;
      break;
    case HNT_CONTIGUOUS_V6:
    case HNT_IOV_V6:
      ret = (Sockaddr *)new Sockaddr6;
      break;
    default:
      throw errors::MalformedNameException();
  }

  if (hicn_name_to_sockaddr_address((hicn_name_t *)&name_, ret) < 0) {
    throw errors::MalformedNameException();
  }

  return std::shared_ptr<Sockaddr>(ret);
}

ip_prefix_t Name::toIpAddress() const {
  ip_prefix_t ret;
  std::memset(&ret, 0, sizeof(ret));

  if (hicn_name_to_ip_prefix(&name_, &ret) < 0) {
    throw errors::InvalidIpAddressException();
  }

  return ret;
}

int Name::getAddressFamily() const {
  int ret = 0;

  if (hicn_name_get_family(&name_, &ret) < 0) {
    throw errors::InvalidIpAddressException();
  }

  return ret;
}

void Name::copyToDestination(uint8_t *destination, bool include_suffix) const {
  if (hicn_name_copy_to_destination(destination, &name_, include_suffix) < 0) {
    throw errors::RuntimeException(
        "Impossibe to copy the name into the "
        "provided destination");
  }
}

std::ostream &operator<<(std::ostream &os, const Name &name) {
  const std::string &str = name.toString();
  //  os << "core:/";
  os << str;

  return os;
}

size_t hash<transport::core::Name>::operator()(
    const transport::core::Name &name) const {
  return name.getHash32(false);
}

size_t compare2<transport::core::Name>::operator()(
  const transport::core::Name &name1, const transport::core::Name &name2) const {
    return name1.equals(name2, false);

}

}  // end namespace core

}  // end namespace transport

namespace std {
size_t hash<transport::core::Name>::operator()(
    const transport::core::Name &name) const {
  return name.getHash32();
}

}  // end namespace std
