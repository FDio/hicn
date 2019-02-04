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

#include <hicn/transport/protocols/reassembly.h>
#include <hicn/transport/protocols/indexing_manager.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/utils/array.h>

namespace transport {

namespace protocol {

BaseReassembly::BaseReassembly(interface::ConsumerSocket *icn_socket, ContentReassembledCallback *content_callback) 
  : reassembly_consumer_socket_(icn_socket),
    zero_index_manager_(std::make_unique<ZeroIndexManager>()),
    incremental_index_manager_(std::make_unique<IncrementalIndexManager>(icn_socket)),
    manifest_index_manager_(std::make_unique<ManifestIndexManager>(icn_socket)),
    index_manager_(zero_index_manager_.get()),
    index_(0) {
  setContentCallback(content_callback);
}

void BaseReassembly::reassemble(ContentObject::Ptr &&content_object) {

  TRANSPORT_LOGI("Packet: %u", content_object->getName().getSuffix());
  if (TRANSPORT_EXPECT_TRUE(content_object != nullptr)) {
    received_packets_.emplace(
          std::make_pair(content_object->getName().getSuffix(), std::move(content_object)));
  }

  TRANSPORT_LOGI("Index: %llu", index_);
  auto it = received_packets_.find(index_);
  while (it != received_packets_.end()) {
    if (it->second->getPayloadType() == PayloadType::CONTENT_OBJECT) {
      copyContent(*it->second);
      received_packets_.erase(it);
    }

    index_ = index_manager_->getNextReassemblySegment();
    TRANSPORT_LOGI("Next index: %llu", index_);
    it = received_packets_.find(index_);
  }
}

void BaseReassembly::copyContent(const ContentObject &content_object) {
  utils::Array<> a = content_object.getPayload();

  std::shared_ptr<std::vector<uint8_t>> content_buffer;
  reassembly_consumer_socket_->getSocketOption(interface::GeneralTransportOptions::APPLICATION_BUFFER, content_buffer);

  content_buffer->insert(content_buffer->end(), (uint8_t *)a.data(),
                          (uint8_t *)a.data() + a.length());

  bool download_completed = 
    index_manager_->getFinalSuffix() == content_object.getName().getSuffix();
  
  TRANSPORT_LOGI("Final suffix: %u, Suffix: %u", index_manager_->getFinalSuffix(), content_object.getName().getSuffix());

  if (TRANSPORT_EXPECT_FALSE(download_completed)) {
    content_callback_->onContentReassembled(std::make_error_code(std::errc(0)));
  }
}

void BaseReassembly::reset() {
  manifest_index_manager_->reset();
  incremental_index_manager_->reset();

  received_packets_.clear();
}

}  // namespace protocol

}  // end namespace transport
