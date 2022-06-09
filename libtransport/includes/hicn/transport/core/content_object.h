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

#pragma once

#include <hicn/transport/core/name.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/shared_ptr_utils.h>

namespace transport {

namespace core {

// This class is used just to transfer buffer pointers
// without making a copy, as std::vector<> would do

class ContentObject : public Packet {
 public:
  using Ptr = std::shared_ptr<ContentObject>;
  using HICNContentObject = hicn_header_t;

  ContentObject(Packet::Format format, std::size_t additional_header_size = 0);

  ContentObject(const Name &name, Packet::Format format,
                std::size_t additional_header_size = 0);

  ContentObject(const Name &name, hicn_format_t format,
                std::size_t additional_header_size, const uint8_t *payload,
                std::size_t payload_size);

  template <typename... Args>
  ContentObject(CopyBufferOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {
    if (hicn_data_get_name(format_, packet_start_,
                           &name_.getStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  template <typename... Args>
  ContentObject(WrapBufferOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {
    if (hicn_data_get_name(format_, packet_start_,
                           &name_.getStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  template <typename... Args>
  ContentObject(CreateOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {
    if (hicn_packet_set_data(format_, packet_start_) < 0) {
      throw errors::MalformedPacketException();
    }

    if (hicn_data_get_name(format_, packet_start_,
                           &name_.getStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  ContentObject(const ContentObject &content_object);

  ContentObject &operator=(const ContentObject &other);

  ContentObject(ContentObject &&content_object);

  ~ContentObject();

  const Name &getName() const override;

  Name &getWritableName() override;

  void setName(const Name &name) override;

  uint32_t getPathLabel() const;

  ContentObject &setPathLabel(uint32_t path_label);

  void setLocator(const ip_address_t &ip_address) override;

  ip_address_t getLocator() const override;

  void setLifetime(uint32_t lifetime) override;

  uint32_t getLifetime() const override;

  auto shared_from_this() { return utils::shared_from(this); }

  bool isLast() const;

  void setLast();

 private:
  void resetForHash() override;
};

}  // end namespace core

}  // end namespace transport
