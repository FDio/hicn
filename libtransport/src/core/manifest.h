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

#include <core/manifest_format.h>
#include <glog/logging.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/core/packet.h>

namespace transport {
namespace core {

template <typename FormatTraits>
class Manifest : public FormatTraits::Encoder, public FormatTraits::Decoder {
 public:
  using Ptr = std::shared_ptr<Manifest>;

  using Encoder = typename FormatTraits::Encoder;
  using Decoder = typename FormatTraits::Decoder;

  using Hash = typename FormatTraits::Hash;
  using HashType = typename FormatTraits::HashType;
  using Suffix = typename FormatTraits::Suffix;
  using SuffixList = typename FormatTraits::SuffixList;
  using HashEntry = std::pair<auth::CryptoHashType, std::vector<uint8_t>>;

  Manifest(Packet::Ptr packet, bool clear = false)
      : Encoder(packet, clear), Decoder(packet), packet_(packet) {
    packet->setPayloadType(PayloadType::MANIFEST);
  }

  virtual ~Manifest() = default;

  Packet::Ptr getPacket() const { return packet_; }

  void setHeaders(ManifestType type, uint8_t max_capacity, HashType hash_algo,
                  bool is_last, const Name &base_name) {
    Encoder::setType(type);
    Encoder::setMaxCapacity(max_capacity);
    Encoder::setHashAlgorithm(hash_algo);
    Encoder::setIsLast(is_last);
    Encoder::setBaseName(base_name);
  }

  auth::Verifier::SuffixMap getSuffixMap() const {
    auth::Verifier::SuffixMap suffix_map;

    HashType hash_algo = Decoder::getHashAlgorithm();
    SuffixList suffix_list = Decoder::getEntries();

    for (auto it = suffix_list.begin(); it != suffix_list.end(); ++it) {
      Hash hash(it->second, Hash::getSize(hash_algo), hash_algo);
      suffix_map[it->first] = hash;
    }

    return suffix_map;
  }

  static Manifest::Ptr createContentManifest(Packet::Format format,
                                             const core::Name &manifest_name,
                                             std::size_t signature_size) {
    ContentObject::Ptr content_object =
        core::PacketManager<>::getInstance().getPacket<ContentObject>(
            format, signature_size);
    content_object->setName(manifest_name);
    return std::make_shared<Manifest>(content_object, true);
  };

 protected:
  Packet::Ptr packet_;
};

}  // end namespace core
}  // end namespace transport
