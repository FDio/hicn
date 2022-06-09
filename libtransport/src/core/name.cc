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

#include <core/manifest_format.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/errors/tokenizer_exception.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/string_tokenizer.h>

namespace transport {

namespace core {

Name::Name() { std::memset(&name_, 0, sizeof(name_)); }

/**
 * XXX This function does not use the name API provided by libhicn
 */
Name::Name(int family, const uint8_t *ip_address, std::uint32_t suffix)
    : name_({}) {
  std::size_t length;
  uint8_t *dst = NULL;

  if (family == AF_INET) {
    dst = name_.prefix.v4.as_u8;
    length = IPV4_ADDR_LEN;
  } else if (family == AF_INET6) {
    dst = name_.prefix.v6.as_u8;
    length = IPV6_ADDR_LEN;
  } else {
    throw errors::RuntimeException("Specified name family does not exist.");
  }

  std::memcpy(dst, ip_address, length);
  name_.suffix = suffix;
}

Name::Name(const char *name, uint32_t segment) {
  if (hicn_name_create(name, segment, &name_) < 0) {
    throw errors::InvalidIpAddressException();
  }
}

Name::Name(const std::string &uri, uint32_t segment)
    : Name(uri.c_str(), segment) {}

Name::Name(const std::string &uri) {
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

Name::~Name() {}

Name &Name::operator=(const Name &name) {
  if (this != &name) {
    if (hicn_name_copy(&this->name_, &name.name_) < 0) {
      throw errors::MalformedNameException();
    }
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
  auto ret = isValid();
  return ret;
}

bool Name::isValid() const {
  return bool(!hicn_name_empty((hicn_name_t *)&name_));
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

void Name::clear() { std::memset(&name_, 0, sizeof(name_)); };

Name::Type Name::getType() const {
  int family;
  hicn_name_get_family(&name_, &family);
  return family == AF_INET ? Name::Type::V4 : Name::Type::V6;
}

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

void Name::copyPrefixToDestination(uint8_t *destination) const {
  if (hicn_name_copy_prefix_to_destination(destination, &name_) < 0) {
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
    const transport::core::Name &name1,
    const transport::core::Name &name2) const {
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
