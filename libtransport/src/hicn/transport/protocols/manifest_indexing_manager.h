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

#include <hicn/transport/interfaces/socket.h>
#include <hicn/transport/protocols/indexing_manager.h>

#include <deque>

namespace transport {

namespace protocol {

class ManifestIndexManager : public TrivialIndexManager {
 public:

  using SuffixQueue = std::deque<uint32_t>;
  using HashEntry = std::pair<std::vector<uint8_t>, core::HashAlgorithm>;

  ManifestIndexManager(interface::ConsumerSocket *icn_socket);

  virtual ~ManifestIndexManager() = default;

  void reset() override;

  bool onManifest(std::unique_ptr<core::ContentObjectManifest> &&manifest) override;

  bool onContentObject(const core::ContentObject &content_object) override;

  uint32_t getNextSuffix() override;

  uint32_t getNextReassemblySegment() override;

  bool isFinalSuffixDiscovered() override;

  uint32_t getFinalSuffix() override;

 protected: 
  SuffixQueue suffix_queue_;
  SuffixQueue::iterator next_reassembly_segment_;
  SuffixQueue::iterator next_to_retrieve_segment_;

  // Manifest indexes
  uint32_t next_manifest_interval_;

  // Hash verification
  std::unordered_map<uint32_t, std::pair<std::vector<uint8_t>, core::HashAlgorithm>> suffix_hash_map_;
};

}  // end namespace protocol

}  // end namespace transport
