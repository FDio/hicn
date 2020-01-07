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
#include <hicn/transport/utils/suffix_strategy.h>

#include <list>

namespace transport {

namespace protocol {

class ManifestIndexManager : public IncrementalIndexManager,
                             public PacketManager<Interest> {
  static constexpr double alpha = 0.3;

 public:
  using SuffixQueue = std::list<uint32_t>;
  using HashEntry = std::pair<std::vector<uint8_t>, core::HashAlgorithm>;

  ManifestIndexManager(interface::ConsumerSocket *icn_socket,
                       TransportProtocol *next_interest);

  virtual ~ManifestIndexManager() = default;

  void reset() override;

  bool onManifest(core::ContentObject::Ptr &&content_object) override;

  bool onContentObject(const core::ContentObject &content_object) override;

  uint32_t getNextSuffix() override;

  uint32_t getNextReassemblySegment() override;

  bool isFinalSuffixDiscovered() override;

  uint32_t getFinalSuffix() override;

 private:
  void onManifestReceived(Interest::Ptr &&i, ContentObject::Ptr &&c);
  void onManifestTimeout(Interest::Ptr &&i);
  void fillWindow(Name &name, uint32_t current_manifest);

 protected:
  SuffixQueue suffix_queue_;
  SuffixQueue::iterator next_to_retrieve_segment_;
  utils::SuffixManifest suffix_manifest_;
  utils::SuffixContent next_reassembly_segment_;

  // Holds segments that should not be requested. Useful when
  // computing the next reassembly segment because some manifests
  // may be incomplete.
  std::vector<uint32_t> ignored_segments_;

  // Hash verification
  std::unordered_map<uint32_t,
                     std::pair<std::vector<uint8_t>, core::HashAlgorithm>>
      suffix_hash_map_;

  // (temporary) To call scheduleNextInterests() after receiving a manifest
  TransportProtocol *next_interest_;
};

}  // end namespace protocol

}  // end namespace transport
