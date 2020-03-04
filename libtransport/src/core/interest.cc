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

Interest::Interest(const Name &interest_name, Packet::Format format)
    : Packet(format) {
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
Interest::Interest(hicn_format_t format) : Interest(Name("0::0|0"), format) {}
#else
Interest::Interest(hicn_format_t format) : Interest(base_name, format) {}
#endif

Interest::Interest(const uint8_t *buffer, std::size_t size)
    : Packet(buffer, size) {
  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

Interest::Interest(MemBufPtr &&buffer) : Packet(std::move(buffer)) {
  if (hicn_interest_get_name(format_, packet_start_,
                             name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

Interest::Interest(Interest &&other_interest)
    : Packet(std::move(other_interest)) {
  name_ = std::move(other_interest.name_);
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

}  // end namespace core

}  // end namespace transport
