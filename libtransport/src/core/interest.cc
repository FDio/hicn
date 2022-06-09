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

#include <hicn/transport/core/interest.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/hash.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/base.h>
#include <hicn/hicn.h>
}

#include <cstring>
#include <memory>

namespace transport {

namespace core {

Interest::Interest(const Name &interest_name, Packet::Format format,
                   std::size_t additional_header_size)
    : Packet(format, additional_header_size) {
  if (hicn_packet_set_interest(format_, packet_start_) < 0) {
    throw errors::MalformedPacketException();
  }

  if (hicn_interest_set_name(format_, packet_start_,
                             &interest_name.getConstStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }

  if (hicn_interest_get_name(format_, packet_start_,
                             &name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

Interest::Interest(hicn_format_t format, std::size_t additional_header_size)
    : Interest(
#ifdef __ANDROID__
          Name("0::0|0"),
#else
          base_name,
#endif
          format, additional_header_size) {
  if (hicn_packet_set_interest(format_, packet_start_) < 0) {
    throw errors::MalformedPacketException();
  }
}

Interest::Interest(MemBuf &&buffer) : Packet(std::move(buffer)) {
  if (hicn_interest_get_name(format_, packet_start_,
                             &name_.getStructReference()) < 0) {
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
    if (hicn_interest_get_name(
            format_, packet_start_,
            (hicn_name_t *)&name_.getConstStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  return name_;
}

Name &Interest::getWritableName() { return const_cast<Name &>(getName()); }

void Interest::setName(const Name &name) {
  if (hicn_interest_set_name(format_, packet_start_,
                             &name.getConstStructReference()) < 0) {
    throw errors::RuntimeException("Error setting interest name.");
  }

  if (hicn_interest_get_name(format_, packet_start_,
                             &name_.getStructReference()) < 0) {
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

  // Reset request bitmap in manifest
  if (hasManifest()) {
    auto int_manifest_header =
        (interest_manifest_header_t *)(writableData() + headerSize());
    memset(int_manifest_header->request_bitmap, 0, BITMAP_SIZE * sizeof(u32));
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
      (interest_manifest_header_t *)(writableData() + headerSize());
  int_manifest_header->n_suffixes = (uint32_t)suffix_set_.size();
  memset(int_manifest_header->request_bitmap, 0xFFFFFFFF,
         BITMAP_SIZE * sizeof(u32));

  uint32_t *suffix = (uint32_t *)(int_manifest_header + 1);
  for (auto it = suffix_set_.begin(); it != suffix_set_.end(); it++, suffix++) {
    *suffix = *it;
  }

  std::size_t additional_length =
      sizeof(interest_manifest_header_t) +
      int_manifest_header->n_suffixes * sizeof(uint32_t);
  append(additional_length);
  updateLength();
}

uint32_t *Interest::firstSuffix() {
  if (!hasManifest()) {
    return nullptr;
  }

  auto ret = (interest_manifest_header_t *)(writableData() + headerSize());
  ret += 1;

  return (uint32_t *)ret;
}

uint32_t Interest::numberOfSuffixes() {
  if (!hasManifest()) {
    return 0;
  }

  auto header = (interest_manifest_header_t *)(writableData() + headerSize());

  return header->n_suffixes;
}

uint32_t *Interest::getRequestBitmap() {
  if (!hasManifest()) return nullptr;

  auto header = (interest_manifest_header_t *)(writableData() + headerSize());
  return header->request_bitmap;
}

void Interest::setRequestBitmap(const uint32_t *request_bitmap) {
  if (!hasManifest()) return;

  auto header = (interest_manifest_header_t *)(writableData() + headerSize());
  memcpy(header->request_bitmap, request_bitmap,
         BITMAP_SIZE * sizeof(uint32_t));
}

bool Interest::isValid() {
  if (!hasManifest()) return true;

  auto header = (interest_manifest_header_t *)(writableData() + headerSize());

  if (header->n_suffixes == 0 ||
      header->n_suffixes > MAX_SUFFIXES_IN_MANIFEST) {
    std::cerr << "Manifest with invalid number of suffixes "
              << header->n_suffixes;
    return false;
  }

  uint32_t empty_bitmap[BITMAP_SIZE];
  memset(empty_bitmap, 0, sizeof(empty_bitmap));
  if (memcmp(empty_bitmap, header->request_bitmap, sizeof(empty_bitmap)) == 0) {
    std::cerr << "Manifest with empty bitmap";
    return false;
  }

  return true;
}

}  // end namespace core

}  // end namespace transport
