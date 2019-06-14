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

#pragma once

#include <hicn/transport/core/name.h>
#include <hicn/transport/core/packet.h>

namespace transport {

namespace core {

// This class is used just to transfer buffer pointers
// without making a copy, as std::vector<> would do

class ContentObject : public Packet {
 public:
  using Ptr = utils::ObjectPool<ContentObject>::Ptr;
  using HICNContentObject = hicn_header_t;

  ContentObject(Packet::Format format = HF_INET6_TCP);

  ContentObject(const Name &name, Packet::Format format = HF_INET6_TCP);

  ContentObject(const Name &name, hicn_format_t format, const uint8_t *payload,
                std::size_t payload_size);

  ContentObject(const uint8_t *buffer, std::size_t size);
  ContentObject(MemBufPtr &&buffer);

  ContentObject(const ContentObject &content_object) = delete;

  ContentObject(ContentObject &&content_object);

  ~ContentObject() override;

  void replace(MemBufPtr &&buffer) override;

  const Name &getName() const override;

  Name &getWritableName() override;

  void setName(const Name &name) override;

  void setName(Name &&name) override;

  uint32_t getPathLabel() const;

  ContentObject &setPathLabel(uint32_t path_label);

  void setLocator(const ip_address_t &ip_address) override;

  ip_address_t getLocator() const override;

  void setLifetime(uint32_t lifetime) override;

  uint32_t getLifetime() const override;

 private:
  void resetForHash() override;
};

}  // end namespace core

}  // end namespace transport
