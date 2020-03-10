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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/utils/array.h>
#include <hicn/transport/utils/membuf.h>

#include <implementation/socket_consumer.h>
#include <protocols/byte_stream_reassembly.h>
#include <protocols/errors.h>
#include <protocols/indexer.h>
#include <protocols/protocol.h>

namespace transport {

namespace protocol {

using namespace core;
using ReadCallback = interface::ConsumerSocket::ReadCallback;

ByteStreamReassembly::ByteStreamReassembly(
    implementation::ConsumerSocket *icn_socket,
    TransportProtocol *transport_protocol)
    : Reassembly(icn_socket, transport_protocol),
      index_(IndexManager::invalid_index),
      download_complete_(false) {}

void ByteStreamReassembly::reassemble(
    std::unique_ptr<ContentObjectManifest> &&manifest) {
  if (TRANSPORT_EXPECT_TRUE(manifest != nullptr) && read_buffer_->capacity()) {
    received_packets_.emplace(
        std::make_pair(manifest->getName().getSuffix(), nullptr));
    assembleContent();
  }
}

void ByteStreamReassembly::reassemble(ContentObject::Ptr &&content_object) {
  if (TRANSPORT_EXPECT_TRUE(content_object != nullptr) &&
      read_buffer_->capacity()) {
    received_packets_.emplace(std::make_pair(
        content_object->getName().getSuffix(), std::move(content_object)));
    assembleContent();
  }
}

void ByteStreamReassembly::assembleContent() {
  if (TRANSPORT_EXPECT_FALSE(index_ == IndexManager::invalid_index)) {
    index_ = index_manager_->getNextReassemblySegment();
    if (index_ == IndexManager::invalid_index) {
      return;
    }
  }

  auto it = received_packets_.find((const unsigned int)index_);
  while (it != received_packets_.end()) {
    // Check if valid packet
    if (it->second) {
      copyContent(*it->second);
    }

    received_packets_.erase(it);
    index_ = index_manager_->getNextReassemblySegment();
    it = received_packets_.find((const unsigned int)index_);
  }

  if (!download_complete_ && index_ != IndexManager::invalid_index) {
    transport_protocol_->onReassemblyFailed(index_);
  }
}

void ByteStreamReassembly::copyContent(const ContentObject &content_object) {
  auto payload = content_object.getPayloadReference();
  auto payload_length = payload.second;
  auto write_size = std::min(payload_length, read_buffer_->tailroom());
  auto additional_bytes = payload_length > read_buffer_->tailroom()
                              ? payload_length - read_buffer_->tailroom()
                              : 0;

  std::memcpy(read_buffer_->writableTail(), payload.first, write_size);
  read_buffer_->append(write_size);

  if (!read_buffer_->tailroom()) {
    notifyApplication();
    std::memcpy(read_buffer_->writableTail(), payload.first + write_size,
                additional_bytes);
    read_buffer_->append(additional_bytes);
  }

  download_complete_ =
      index_manager_->getFinalSuffix() == content_object.getName().getSuffix();

  if (TRANSPORT_EXPECT_FALSE(download_complete_)) {
    notifyApplication();
    transport_protocol_->onContentReassembled(
        make_error_code(protocol_error::success));
  }
}

void ByteStreamReassembly::reInitialize() {
  index_ = IndexManager::invalid_index;
  download_complete_ = false;

  received_packets_.clear();

  // reset read buffer
  ReadCallback *read_callback;
  reassembly_consumer_socket_->getSocketOption(
      interface::ConsumerCallbacksOptions::READ_CALLBACK, &read_callback);

  read_buffer_ = utils::MemBuf::create(read_callback->maxBufferSize());
}

}  // namespace protocol

}  // namespace transport
