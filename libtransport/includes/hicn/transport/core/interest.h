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
#include <hicn/transport/utils/shared_ptr_utils.h>

#include <set>

namespace transport {

namespace core {

const uint32_t MAX_AGGREGATED_INTEREST = 128;

class Interest
    : public Packet /*, public std::enable_shared_from_this<Interest>*/ {
 private:
  struct InterestManifestHeader {
    /* This can be 16 bits, but we use 32 bits for alignment */
    uint32_t n_suffixes;
    /* Followed by the list of prefixes to ask */
    /* ... */
  };

 public:
  using Ptr = std::shared_ptr<Interest>;

  Interest(Packet::Format format = HF_INET6_TCP,
           std::size_t additional_header_size = 0);

  Interest(const Name &interest_name, Packet::Format format = HF_INET6_TCP,
           std::size_t additional_header_size = 0);

  Interest(MemBuf &&buffer);

  template <typename... Args>
  Interest(CopyBufferOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {
    if (hicn_interest_get_name(format_, packet_start_,
                               name_.getStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  template <typename... Args>
  Interest(WrapBufferOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {
    if (hicn_interest_get_name(format_, packet_start_,
                               name_.getStructReference()) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  template <typename... Args>
  Interest(CreateOp op, Args &&...args)
      : Packet(op, std::forward<Args>(args)...) {}

  /* Move constructor */
  Interest(Interest &&other_interest);

  /* Copy constructor */
  Interest(const Interest &other_interest);

  /* Assginemnt operator */
  Interest &operator=(const Interest &other);

  ~Interest();

  const Name &getName() const override;

  Name &getWritableName() override;

  void setName(const Name &name) override;

  void setLocator(const ip_address_t &ip_address) override;

  ip_address_t getLocator() const override;

  void setLifetime(uint32_t lifetime) override;

  uint32_t getLifetime() const override;

  bool hasManifest();

  void appendSuffix(std::uint32_t suffix);

  void encodeSuffixes();

  uint32_t *firstSuffix();

  uint32_t numberOfSuffixes();

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  void resetForHash() override;
  std::set<uint32_t> suffix_set_;
};

}  // end namespace core

}  // end namespace transport
