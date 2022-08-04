/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
#include <hicn/transport/portability/endianess.h>
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

ContentObject::ContentObject(const Name &name, Packet::Format format,
                             std::size_t additional_header_size)
    : Packet(HICN_PACKET_TYPE_DATA, format, additional_header_size) {
  if (TRANSPORT_EXPECT_FALSE(hicn_data_set_name(&pkbuf_, &name.name_) < 0)) {
    throw errors::RuntimeException("Error filling the packet name.");
  }

  if (TRANSPORT_EXPECT_FALSE(
          hicn_data_get_name(&pkbuf_, &name_.getStructReference()) < 0)) {
    throw errors::MalformedPacketException();
  }
}

ContentObject::ContentObject(hicn_packet_format_t format,
                             std::size_t additional_header_size)
    : ContentObject(
#ifdef __ANDROID__
          Name("0::0|0"),
#else
          Packet::base_name,
#endif
          format, additional_header_size) {
}

ContentObject::ContentObject(const Name &name, hicn_packet_format_t format,
                             std::size_t additional_header_size,
                             const uint8_t *payload, std::size_t size)
    : ContentObject(name, format, additional_header_size) {
  appendPayload(payload, size);
}

ContentObject::ContentObject(ContentObject &&other) : Packet(std::move(other)) {
  name_ = std::move(other.name_);
}

ContentObject::ContentObject(const ContentObject &other) : Packet(other) {
  name_ = other.name_;
}

ContentObject &ContentObject::operator=(const ContentObject &other) {
  return (ContentObject &)Packet::operator=(other);
}

ContentObject::~ContentObject() {}

const Name &ContentObject::getName() const {
  if (!name_) {
    if (hicn_data_get_name(
            &pkbuf_, (hicn_name_t *)&name_.getConstStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  return name_;
}

Name &ContentObject::getWritableName() { return const_cast<Name &>(getName()); }

void ContentObject::setName(const Name &name) {
  if (hicn_data_set_name(&pkbuf_, &name.getConstStructReference()) < 0) {
    throw errors::RuntimeException("Error setting content object name.");
  }

  if (hicn_data_get_name(&pkbuf_, &name_.getStructReference()) < 0) {
    throw errors::MalformedPacketException();
  }
}

hicn_path_label_t ContentObject::getPathLabel() const {
  hicn_path_label_t path_label;
  if (hicn_data_get_path_label(&pkbuf_, &path_label) < 0) {
    throw errors::RuntimeException(
        "Error retrieving the path label from content object");
  }

  return path_label;
}

ContentObject &ContentObject::setPathLabel(hicn_path_label_t path_label) {
  if (hicn_data_set_path_label(&pkbuf_, path_label) < 0) {
    throw errors::RuntimeException(
        "Error setting the path label from content object");
  }

  return *this;
}

void ContentObject::setLocator(const hicn_ip_address_t &ip_address) {
  if (hicn_data_set_locator(&pkbuf_, &ip_address) < 0) {
    throw errors::RuntimeException("Error setting content object locator");
  }

  return;
}

hicn_ip_address_t ContentObject::getLocator() const {
  hicn_ip_address_t ip;

  if (hicn_data_get_locator(&pkbuf_, &ip) < 0) {
    throw errors::RuntimeException("Error getting content object locator.");
  }

  return ip;
}

void ContentObject::setLifetime(uint32_t lifetime) {
  if (hicn_data_set_expiry_time(&pkbuf_, lifetime) < 0) {
    throw errors::MalformedPacketException();
  }
}

uint32_t ContentObject::getLifetime() const {
  uint32_t lifetime = 0;

  if (hicn_data_get_expiry_time(&pkbuf_, &lifetime) < 0) {
    throw errors::MalformedPacketException();
  }

  return lifetime;
}

void ContentObject::resetForHash() {
  if (hicn_data_reset_for_hash(&pkbuf_) < 0) {
    throw errors::RuntimeException(
        "Error resetting content object fields for hash computation.");
  }
}

bool ContentObject::isLast() const {
  int is_last = 0;
  if (hicn_data_is_last(&pkbuf_, &is_last) < 0) {
    throw errors::RuntimeException(
        "Impossible to get last data flag from packet header.");
  }

  return is_last;
}

void ContentObject::setLast() {
  if (hicn_data_set_last(&pkbuf_) < 0) {
    throw errors::RuntimeException(
        "Impossible to set last data flag to packet header.");
  }
}

}  // end namespace core

}  // end namespace transport
