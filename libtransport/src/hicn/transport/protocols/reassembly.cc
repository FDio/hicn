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

BaseReassembly::BaseReassembly(interface::ConsumerSocket *icn_socket) 
  : reassembly_consumer_socket_(icn_socket),
    index_manager_(std::make_unique<TrivialIndexManager>()),
    last_reassembled_segment_(0) {}

void BaseReassembly::reassemble(ContentObject::Ptr &&content_object) {

  if (TRANSPORT_EXPECT_TRUE(content_object != nullptr)) {
    received_packets_.emplace(
          std::make_pair(content_object->getName().getSuffix(), std::move(content_object)));
  }

  uint64_t index = last_reassembled_segment_;
  auto it = received_packets_.find(index);

  while (it != received_packets_.end()) {
    if (it->second->getPayloadType() == PayloadType::CONTENT_OBJECT) {
      copyContent(*it->second);
      received_packets_.erase(it);
    }

    index = index_manager_->getNextReassemblySegment();
    it = received_packets_.find(index);
  }
}

void BaseReassembly::callApplicationCallback(std::error_code&& ec) {
  interface::ConsumerContentCallback *on_payload = nullptr;
  reassembly_consumer_socket_->getSocketOption(interface::CONTENT_RETRIEVED, &on_payload);
  if (*on_payload != VOID_HANDLER) {
    std::shared_ptr<std::vector<uint8_t>> content_buffer;
    reassembly_consumer_socket_->getSocketOption(interface::GeneralTransportOptions::APPLICATION_BUFFER, content_buffer);
    (*on_payload)(*reassembly_consumer_socket_, content_buffer->size(), ec);
  }
}

void BaseReassembly::returnContentToApplication() {
  BaseReassembly::callApplicationCallback(std::make_error_code(std::errc(0)));
}

void BaseReassembly::partialDownload() {
  bool virtual_download;
  reassembly_consumer_socket_->getSocketOption(interface::VIRTUAL_DOWNLOAD, virtual_download);
  if (!virtual_download) {
    reassemble(nullptr);
  }

  BaseReassembly::callApplicationCallback(std::make_error_code(std::errc(std::errc::io_error)));
}

void BaseReassembly::copyContent(const ContentObject &content_object) {
  utils::Array<> a = content_object.getPayload();

  std::shared_ptr<std::vector<uint8_t>> content_buffer;
  reassembly_consumer_socket_->getSocketOption(interface::GeneralTransportOptions::APPLICATION_BUFFER, content_buffer);

  content_buffer->insert(content_buffer->end(), (uint8_t *)a.data(),
                          (uint8_t *)a.data() + a.length());

  bool download_completed = 
    index_manager_->getFinalSuffix() == content_object.getName().getSuffix();

  if (TRANSPORT_EXPECT_FALSE(download_completed)) {
    returnContentToApplication();
  }
}

void BaseReassembly::reset() {
  if (index_manager_) {
    index_manager_->reset();
  }

  last_reassembled_segment_ = 0;
  received_packets_.clear();
}

}  // namespace protocol

}  // end namespace transport
