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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/branch_prediction.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/hicn.h>
#include <hicn/util/ip_address.h>
}

#include <cstring>
#include <memory>

namespace transport {

namespace core {

ContentObject::ContentObject(const Name &name, Packet::Format format)
    : Packet(format) {
  if (TRANSPORT_EXPECT_FALSE(
          hicn_data_set_name(format, packet_start_, &name.name_) < 0)) {
    throw errors::RuntimeException("Error filling the packet name.");
  }

  if (TRANSPORT_EXPECT_FALSE(hicn_data_get_name(format_, packet_start_,
                                                name_.getStructReference()) <
                             0)) {
    throw errors::MalformedPacketException();
  }
}

#ifdef __ANDROID__
ContentObject::ContentObject(hicn_format_t format)
    : ContentObject(Name("0::0|0"), format) {}
#else
ContentObject::ContentObject(hicn_format_t format)
    : ContentObject(Packet::base_name, format) {}
#endif

ContentObject::ContentObject(const Name &name, hicn_format_t format,
                             const uint8_t *payload, std::size_t size)
    : ContentObject(name, format) {
  appendPayload(payload, size);
}

ContentObject::ContentObject(const uint8_t *buffer, std::size_t size)
    : Packet(buffer, size) {
  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::RuntimeException("Error getting name from content object.");
  }
}

ContentObject::ContentObject(MemBufPtr &&buffer) : Packet(std::move(buffer)) {
  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::RuntimeException("Error getting name from content object.");
  }
}

ContentObject::ContentObject(ContentObject &&other) : Packet(std::move(other)) {
  name_ = std::move(other.name_);

  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::MalformedPacketException();
  }
}

ContentObject::~ContentObject() {}

void ContentObject::replace(MemBufPtr &&buffer) {
  Packet::replace(std::move(buffer));

  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::RuntimeException("Error getting name from content object.");
  }
}

const Name &ContentObject::getName() const {
  if (!name_) {
    if (hicn_data_get_name(format_, packet_start_,
                           (hicn_name_t *)name_.getConstStructReference()) <
        0) {
      throw errors::MalformedPacketException();
    }
  }

  return name_;
}

Name &ContentObject::getWritableName() { return const_cast<Name &>(getName()); }

void ContentObject::setName(const Name &name) {
  if (hicn_data_set_name(format_, packet_start_,
                         name.getConstStructReference()) < 0) {
    throw errors::RuntimeException("Error setting content object name.");
  }

  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::MalformedPacketException();
  }
}

void ContentObject::setName(Name &&name) {
  if (hicn_data_set_name(format_, packet_start_, name.getStructReference()) <
      0) {
    throw errors::RuntimeException(
        "Error getting the payload length from content object.");
  }

  if (hicn_data_get_name(format_, packet_start_, name_.getStructReference()) <
      0) {
    throw errors::MalformedPacketException();
  }
}

uint32_t ContentObject::getPathLabel() const {
  uint32_t path_label;
  if (hicn_data_get_path_label(packet_start_, &path_label) < 0) {
    throw errors::RuntimeException(
        "Error retrieving the path label from content object");
  }

  return path_label;
}

ContentObject &ContentObject::setPathLabel(uint32_t path_label) {
  if (hicn_data_set_path_label((hicn_header_t *)packet_start_, path_label) <
      0) {
    throw errors::RuntimeException(
        "Error setting the path label from content object");
  }

  return *this;
}

void ContentObject::setLocator(const ip_address_t &ip_address) {
  if (hicn_data_set_locator(format_, packet_start_, &ip_address) < 0) {
    throw errors::RuntimeException("Error setting content object locator");
  }

  return;
}

ip_address_t ContentObject::getLocator() const {
  ip_address_t ip;

  if (hicn_data_get_locator(format_, packet_start_, &ip) < 0) {
    throw errors::RuntimeException("Error getting content object locator.");
  }

  return ip;
}

void ContentObject::setLifetime(uint32_t lifetime) {
  if (hicn_data_set_expiry_time(packet_start_, lifetime) < 0) {
    throw errors::MalformedPacketException();
  }
}

uint32_t ContentObject::getLifetime() const {
  uint32_t lifetime = 0;

  if (hicn_data_get_expiry_time(packet_start_, &lifetime) < 0) {
    throw errors::MalformedPacketException();
  }

  return lifetime;
}

void ContentObject::resetForHash() {
  if (hicn_data_reset_for_hash(
          format_, reinterpret_cast<hicn_header_t *>(packet_start_)) < 0) {
    throw errors::RuntimeException(
        "Error resetting content object fields for hash computation.");
  }
}

}  // end namespace core

}  // end namespace transport
