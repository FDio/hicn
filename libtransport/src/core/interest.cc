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

#include <hicn/transport/core/interest.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/hash.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
}

#include <cstring>
#include <memory>

namespace transport {

namespace core {

Interest::Interest(const Name &interest_name, Packet::Format format,
                   std::size_t additional_header_size)
    : Packet(format, additional_header_size) {
  if (hicn_interest_set_name(format_, packet_start_,
                             interest_name.getConstStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }

  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

#ifdef __ANDROID__
Interest::Interest(hicn_format_t format, std::size_t additional_header_size)
    : Interest(Name("0::0|0"), format, additional_header_size) {}
#else
Interest::Interest(hicn_format_t format, std::size_t additional_header_size)
    : Interest(base_name, format, additional_header_size) {}
#endif

Interest::Interest(MemBuf &&buffer) : Packet(std::move(buffer)) {
  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

Interest::Interest(Interest &&other_interest)
    : Packet(std::move(other_interest)) {
  name_ = std::move(other_interest.name_);
}

Interest::Interest(const Interest &other_interest) : Packet(other_interest) {
  name_ = other_interest.name_;
}

Interest &Interest::operator=(const Interest &other) {
  return (Interest &)Packet::operator=(other);
}

Interest::~Interest() {}

const Name &Interest::getName() const {
  if (!name_) {
    if (hicn_interest_get_name(format_, packet_start_,
                               (hicn_name_t *)name_.getConstStructReference()) <
        0) {
      throw errors::MalformedPacketException();
    }
  }

  return name_;
}

Name &Interest::getWritableName() { return const_cast<Name &>(getName()); }

void Interest::setName(const Name &name) {
  if (hicn_interest_set_name(format_, packet_start_,
                             name.getConstStructReference()) < 0) {
    throw errors::RuntimeException("Error setting interest name.");
  }

  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

void Interest::setName(Name &&name) {
  if (hicn_interest_set_name(format_, packet_start_,
                             name.getStructReference()) < 0) {
    throw errors::RuntimeException("Error setting interest name.");
  }

  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

void Interest::setLocator(const ip_address_t &ip_address) {
  if (hicn_interest_set_locator(format_, packet_start_, &ip_address) < 0) {
    throw errors::RuntimeException("Error setting interest locator.");
  }

  return;
}

ip_address_t Interest::getLocator() const {
  ip_address_t ip;

  if (hicn_interest_get_locator(format_, packet_start_, &ip) < 0) {
    throw errors::RuntimeException("Error getting interest locator.");
  }

  return ip;
}

void Interest::setLifetime(uint32_t lifetime) {
  if (hicn_interest_set_lifetime(packet_start_, lifetime) < 0) {
    throw errors::MalformedPacketException();
  }
}

uint32_t Interest::getLifetime() const {
  uint32_t lifetime = 0;

  if (hicn_interest_get_lifetime(packet_start_, &lifetime) < 0) {
    throw errors::MalformedPacketException();
  }

  return lifetime;
}

void Interest::resetForHash() {
  if (hicn_interest_reset_for_hash(
          format_, reinterpret_cast<hicn_header_t *>(packet_start_)) < 0) {
    throw errors::RuntimeException(
        "Error resetting interest fields for hash computation.");
  }
}

bool Interest::hasManifest() {
  return (getPayloadType() == PayloadType::MANIFEST);
}

void Interest::appendSuffix(std::uint32_t suffix) {
  if (TRANSPORT_EXPECT_FALSE(suffix_set_.empty())) {
    setPayloadType(PayloadType::MANIFEST);
  }

  suffix_set_.emplace(suffix);
}

void Interest::encodeSuffixes() {
  if (!hasManifest()) {
    return;
  }

  // We assume interest does not hold signature for the moment.
  auto int_manifest_header =
      (InterestManifestHeader *)(writableData() + headerSize());
  int_manifest_header->n_suffixes = (uint32_t)suffix_set_.size();
  std::size_t additional_length =
      int_manifest_header->n_suffixes * sizeof(uint32_t);

  uint32_t *suffix = (uint32_t *)(int_manifest_header + 1);
  for (auto it = suffix_set_.begin(); it != suffix_set_.end(); it++, suffix++) {
    *suffix = *it;
  }

  updateLength(additional_length);
}

uint32_t *Interest::firstSuffix() {
  if (!hasManifest()) {
    return nullptr;
  }

  auto ret = (InterestManifestHeader *)(writableData() + headerSize());
  ret += 1;

  return (uint32_t *)ret;
}

uint32_t Interest::numberOfSuffixes() {
  if (!hasManifest()) {
    return 0;
  }

  auto header = (InterestManifestHeader *)(writableData() + headerSize());

  return header->n_suffixes;
}

}  // end namespace core

}  // end namespace transport
