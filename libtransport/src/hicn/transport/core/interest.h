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
#include <hicn/transport/utils/object_pool.h>

namespace transport {

namespace core {

class Interest
    : public Packet /*, public std::enable_shared_from_this<Interest>*/ {
 public:
  using Ptr = utils::ObjectPool<Interest>::Ptr;

  Interest(Packet::Format format = HF_INET6_TCP);

  Interest(const Name &interest_name, Packet::Format format = HF_INET6_TCP);

  Interest(const uint8_t *buffer, std::size_t size);
  Interest(MemBufPtr &&buffer);

  /*
   * Enforce zero-copy.
   */
  Interest(const Interest &other_interest) = delete;
  Interest &operator=(const Interest &other_interest) = delete;

  Interest(Interest &&other_interest);

  ~Interest() override;

  const Name &getName() const;

  Name &getWritableName();

  Interest &setName(const Name &name);

  Interest &setName(Name &&name);

  void setLocator(const ip_address_t &ip_address) override;

  ip_address_t getLocator() const override;

 private:
  void resetForHash() override;
};

}  // end namespace core

}  // end namespace transport
