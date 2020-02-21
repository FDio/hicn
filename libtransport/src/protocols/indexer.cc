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

#include <hicn/transport/utils/branch_prediction.h>

#include <protocols/incremental_indexer.h>
#include <protocols/indexer.h>
#include <protocols/manifest_incremental_indexer.h>
#include <protocols/protocol.h>

namespace transport {
namespace protocol {

IndexManager::IndexManager(implementation::ConsumerSocket *icn_socket,
                           TransportProtocol *transport, Reassembly *reassembly)
    : indexer_(std::make_unique<IncrementalIndexer>(icn_socket, transport,
                                                    reassembly)),
      first_segment_received_(false),
      icn_socket_(icn_socket),
      transport_(transport),
      reassembly_(reassembly) {}

void IndexManager::onContentObject(core::Interest::Ptr &&interest,
                                   core::ContentObject::Ptr &&content_object) {
  if (first_segment_received_) {
    indexer_->onContentObject(std::move(interest), std::move(content_object));
  } else {
    std::uint32_t segment_number = interest->getName().getSuffix();

    if (segment_number == 0) {
      // Check if manifest
      if (content_object->getPayloadType() == PayloadType::MANIFEST) {
        IncrementalIndexer *indexer =
            static_cast<IncrementalIndexer *>(indexer_.release());
        indexer_ =
            std::make_unique<ManifestIncrementalIndexer>(std::move(*indexer));
        delete indexer;
      }

      indexer_->onContentObject(std::move(interest), std::move(content_object));
      auto it = interest_data_set_.begin();
      while (it != interest_data_set_.end()) {
        indexer_->onContentObject(
            std::move(const_cast<core::Interest::Ptr &&>(it->first)),
            std::move(const_cast<core::ContentObject::Ptr &&>(it->second)));
        it = interest_data_set_.erase(it);
      }

      first_segment_received_ = true;
    } else {
      interest_data_set_.emplace(std::move(interest),
                                 std::move(content_object));
    }
  }
}

bool IndexManager::onKeyToVerify() { return indexer_->onKeyToVerify(); }

void IndexManager::reset(std::uint32_t offset) {
  indexer_ = std::make_unique<IncrementalIndexer>(icn_socket_, transport_,
                                                  reassembly_);
  first_segment_received_ = false;
  interest_data_set_.clear();
}

}  // namespace protocol
}  // namespace transport
