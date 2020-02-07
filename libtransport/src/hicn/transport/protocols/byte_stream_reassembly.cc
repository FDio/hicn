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

#include <hicn/transport/protocols/byte_stream_reassembly.h>

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/errors.h>
#include <hicn/transport/protocols/indexing_manager.h>
#include <hicn/transport/utils/array.h>
#include <hicn/transport/utils/membuf.h>

namespace transport {

namespace protocol {

ByteStreamReassembly::ByteStreamReassembly(
    interface::ConsumerSocket *icn_socket,
    TransportProtocol *transport_protocol)
    : Reassembly(icn_socket, transport_protocol), index_(0) {}

void ByteStreamReassembly::reassemble(
    std::unique_ptr<ContentObjectManifest> &&manifest) {
  if (TRANSPORT_EXPECT_TRUE(manifest != nullptr)) {
    received_packets_.emplace(
        std::make_pair(manifest->getName().getSuffix(), nullptr));
  }
}

void ByteStreamReassembly::reassemble(ContentObject::Ptr &&content_object) {
  if (TRANSPORT_EXPECT_TRUE(content_object != nullptr)) {
    received_packets_.emplace(std::make_pair(
        content_object->getName().getSuffix(), std::move(content_object)));
  }

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
      received_packets_.erase(it);
    }

    index_ = index_manager_->getNextReassemblySegment();
    it = received_packets_.find((const unsigned int)index_);
  }
}

void ByteStreamReassembly::copyContent(const ContentObject &content_object) {
  auto a = content_object.getPayload();
  auto payload_length = a->length();
  auto write_size = std::min(payload_length, read_buffer_->tailroom());
  auto additional_bytes = payload_length > read_buffer_->tailroom()
                              ? payload_length - read_buffer_->tailroom()
                              : 0;

  std::memcpy(read_buffer_->writableTail(), a->data(), write_size);
  read_buffer_->append(write_size);

  if (!read_buffer_->tailroom()) {
    notifyApplication();
    std::memcpy(read_buffer_->writableTail(), a->data() + write_size,
                additional_bytes);
    read_buffer_->append(additional_bytes);
  }

  bool download_completed =
      index_manager_->getFinalSuffix() == content_object.getName().getSuffix();

  if (TRANSPORT_EXPECT_FALSE(download_completed)) {
    notifyApplication();
    transport_protocol_->onContentReassembled(
        make_error_code(protocol_error::success));
  }
}

void ByteStreamReassembly::reInitialize() {
  index_ = 0;

  received_packets_.clear();

  // reset read buffer
  interface::ConsumerSocket::ReadCallback *read_callback;
  reassembly_consumer_socket_->getSocketOption(
      interface::ConsumerCallbacksOptions::READ_CALLBACK, &read_callback);

  read_buffer_ = utils::MemBuf::create(read_callback->maxBufferSize());
}

}  // namespace protocol

}  // namespace transport
