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
#include <hicn/transport/protocols/indexing_manager.h>
#include <hicn/transport/protocols/reassembly.h>
#include <hicn/transport/utils/array.h>
#include <hicn/transport/utils/membuf.h>

namespace transport {

namespace protocol {

BaseReassembly::BaseReassembly(interface::ConsumerSocket *icn_socket,
                               ContentReassembledCallback *content_callback,
                               TransportProtocol *next_interest)
    : reassembly_consumer_socket_(icn_socket),
      incremental_index_manager_(
          std::make_unique<IncrementalIndexManager>(icn_socket)),
      manifest_index_manager_(
          std::make_unique<ManifestIndexManager>(icn_socket, next_interest)),
      index_manager_(incremental_index_manager_.get()),
      index_(0),
      read_buffer_(nullptr) {
  setContentCallback(content_callback);
}

void BaseReassembly::reassemble(ContentObject::Ptr &&content_object) {

  if (TRANSPORT_EXPECT_TRUE(content_object != nullptr)) {
    received_packets_.emplace(std::make_pair(
        content_object->getName().getSuffix(), std::move(content_object)));
  }
  auto it = received_packets_.find((const unsigned int)index_);
  while (it != received_packets_.end()) {
    if (it->second->getPayloadType() == PayloadType::CONTENT_OBJECT) {
      copyContent(*it->second);
      received_packets_.erase(it);
    }

    index_ = index_manager_->getNextReassemblySegment();
    it = received_packets_.find((const unsigned int)index_);
  }
}

void BaseReassembly::copyContent(const ContentObject &content_object) {
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
    content_callback_->onContentReassembled(std::make_error_code(std::errc(0)));
  }
}

void BaseReassembly::notifyApplication() {
  interface::ConsumerSocket::ReadCallback *read_callback = nullptr;
  reassembly_consumer_socket_->getSocketOption(
      interface::ConsumerCallbacksOptions::READ_CALLBACK, &read_callback);

  if (TRANSPORT_EXPECT_FALSE(!read_callback)) {
    TRANSPORT_LOGE("Read callback not installed!");
    return;
  }

  if (read_callback->isBufferMovable()) {
    // No need to perform an additional copy. The whole buffer will be
    // tranferred to the application.

    read_callback->readBufferAvailable(std::move(read_buffer_));
    read_buffer_ = utils::MemBuf::create(read_callback->maxBufferSize());
  } else {
    // The buffer will be copied into the application-provided buffer
    uint8_t *buffer;
    std::size_t length;
    std::size_t total_length = read_buffer_->length();

    while (read_buffer_->length()) {
      buffer = nullptr;
      length = 0;
      read_callback->getReadBuffer(&buffer, &length);

      if (!buffer || !length) {
        throw errors::RuntimeException(
            "Invalid buffer provided by the application.");
      }

      auto to_copy = std::min(read_buffer_->length(), length);
      std::memcpy(buffer, read_buffer_->data(), to_copy);
      read_buffer_->trimStart(to_copy);
    }

    read_callback->readDataAvailable(total_length);
    read_buffer_->clear();
  }
}

void BaseReassembly::reset() {
  manifest_index_manager_->reset();
  incremental_index_manager_->reset();
  index_ = index_manager_->getNextReassemblySegment();

  received_packets_.clear();

  // reset read buffer
  interface::ConsumerSocket::ReadCallback *read_callback;
  reassembly_consumer_socket_->getSocketOption(
      interface::ConsumerCallbacksOptions::READ_CALLBACK, &read_callback);

  read_buffer_ = utils::MemBuf::create(read_callback->maxBufferSize());
}

}  // namespace protocol

}  // namespace transport
