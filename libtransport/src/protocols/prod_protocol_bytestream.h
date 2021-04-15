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

#include <hicn/transport/utils/ring_buffer.h>
#include <protocols/production_protocol.h>

#include <atomic>
#include <queue>

namespace transport {

namespace protocol {

using namespace core;

class ByteStreamProductionProtocol : public ProductionProtocol {
  static constexpr uint32_t burst_size = 256;

 public:
  ByteStreamProductionProtocol(implementation::ProducerSocket *icn_socket);

  ~ByteStreamProductionProtocol() override;

  using ProductionProtocol::start;
  using ProductionProtocol::stop;

  uint32_t produceStream(const Name &content_name,
                         std::unique_ptr<utils::MemBuf> &&buffer,
                         bool is_last = true,
                         uint32_t start_offset = 0) override;
  uint32_t produceStream(const Name &content_name, const uint8_t *buffer,
                         size_t buffer_size, bool is_last = true,
                         uint32_t start_offset = 0) override;
  uint32_t produceDatagram(const Name &content_name,
                           std::unique_ptr<utils::MemBuf> &&buffer) override;
  uint32_t produceDatagram(const Name &content_name, const uint8_t *buffer,
                           size_t buffer_size) override;

 protected:
  // Consumer Callback
  //   void reset() override;
  void onInterest(core::Interest &i) override;
  void onError(std::error_code ec) override;

 private:
  void passContentObjectToCallbacks(
      const std::shared_ptr<ContentObject> &content_object);
  void scheduleSendBurst();

 private:
  // While manifests are being built, contents are stored in a queue
  std::queue<std::shared_ptr<ContentObject>> content_queue_;
  utils::CircularFifo<std::shared_ptr<ContentObject>, 2048>
      object_queue_for_callbacks_;
};

}  // end namespace protocol
}  // end namespace transport
