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
#include <hicn/transport/protocols/errors.h>
#include <hicn/transport/protocols/indexer.h>
#include <hicn/transport/protocols/reassembly.h>
#include <hicn/transport/utils/array.h>
#include <hicn/transport/utils/membuf.h>

namespace transport {

namespace protocol {

void Reassembly::notifyApplication() {
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

}  // namespace protocol
}  // namespace transport
