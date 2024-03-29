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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/utils/array.h>
#include <hicn/transport/utils/membuf.h>
#include <implementation/socket_consumer.h>
#include <protocols/byte_stream_reassembly.h>
#include <protocols/errors.h>
#include <protocols/indexer.h>
#include <protocols/transport_protocol.h>

namespace transport {

namespace protocol {

using namespace core;
using ReadCallback = interface::ConsumerSocket::ReadCallback;

ByteStreamReassembly::ByteStreamReassembly(
    implementation::ConsumerSocket *icn_socket,
    TransportProtocol *transport_protocol)
    : Reassembly(icn_socket, transport_protocol),
      index_(Indexer::invalid_index),
      download_complete_(false) {}

void ByteStreamReassembly::reassemble(ContentObject &content_object) {
  if (TRANSPORT_EXPECT_TRUE(read_buffer_->capacity())) {
    received_packets_.emplace(
        std::make_pair(content_object.getName().getSuffix(),
                       content_object.shared_from_this()));
    assembleContent();
  }
}

void ByteStreamReassembly::reassemble(utils::MemBuf &buffer, uint32_t suffix) {
  throw errors::NotImplementedException();
}

void ByteStreamReassembly::assembleContent() {
  if (TRANSPORT_EXPECT_FALSE(index_ == Indexer::invalid_index)) {
    index_ = indexer_verifier_->getNextReassemblySegment();
    if (index_ == Indexer::invalid_index) {
      return;
    }
  }

  auto it = received_packets_.find((const unsigned int)index_);
  while (it != received_packets_.end()) {
    // Check if valid packet
    if (it->second) {
      if (TRANSPORT_EXPECT_FALSE(copyContent(*it->second))) {
        return;
      }
    }

    received_packets_.erase(it);
    index_ = indexer_verifier_->getNextReassemblySegment();
    it = received_packets_.find((const unsigned int)index_);
  }

  if (!download_complete_ && index_ != Indexer::invalid_index) {
    transport_protocol_->onReassemblyFailed(index_);
  }
}

bool ByteStreamReassembly::copyContent(ContentObject &content_object) {
  bool ret = false;

  content_object.trimStart(content_object.headerSize());

  utils::MemBuf *current = &content_object;

  do {
    auto payload_length = current->length();
    auto write_size = std::min(payload_length, read_buffer_->tailroom());
    auto additional_bytes = payload_length > read_buffer_->tailroom()
                                ? payload_length - read_buffer_->tailroom()
                                : 0;

    std::memcpy(read_buffer_->writableTail(), current->data(), write_size);
    read_buffer_->append(write_size);

    if (!read_buffer_->tailroom()) {
      notifyApplication();
      std::memcpy(read_buffer_->writableTail(), current->data() + write_size,
                  additional_bytes);
      read_buffer_->append(additional_bytes);
    }

    current = current->next();
  } while (current != &content_object);

  download_complete_ = indexer_verifier_->getFinalSuffix() ==
                       content_object.getName().getSuffix();

  if (TRANSPORT_EXPECT_FALSE(download_complete_)) {
    ret = download_complete_;
    notifyApplication();
    transport_protocol_->onContentReassembled(
        make_error_code(protocol_error::success));
  }

  return ret;
}

void ByteStreamReassembly::reInitialize() {
  index_ = Indexer::invalid_index;
  download_complete_ = false;

  received_packets_.clear();

  // reset read buffer
  ReadCallback *read_callback;

  if (reassembly_consumer_socket_) {
    reassembly_consumer_socket_->getSocketOption(
        interface::ConsumerCallbacksOptions::READ_CALLBACK, &read_callback);
    read_buffer_ = utils::MemBuf::create(read_callback->maxBufferSize());
  }
}

}  // namespace protocol

}  // namespace transport
