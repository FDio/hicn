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

#pragma once

#include <core/facade.h>

namespace transport {

namespace implementation {
class ConsumerReadCallback;
class ConsumerSocket;
}  // namespace implementation

namespace protocol {

class TransportProtocol;
class Indexer;

// Forward Declaration
class ManifestManager;

class Reassembly {
 public:
  class ContentReassembledCallback {
   public:
    virtual void onContentReassembled(const std::error_code &ec) = 0;
  };

  Reassembly(implementation::ConsumerSocket *icn_socket,
             TransportProtocol *transport_protocol)
      : reassembly_consumer_socket_(icn_socket),
        transport_protocol_(transport_protocol) {}

  virtual ~Reassembly() = default;

  /**
   * Handle reassembly of content object.
   */
  virtual void reassemble(core::ContentObject &content_object) = 0;

  /**
   * Handle reassembly of content object.
   */
  virtual void reassemble(utils::MemBuf &buffer, uint32_t suffix) = 0;

  /**
   * Handle reassembly of manifest
   */
  virtual void reassemble(
      std::unique_ptr<core::ContentObjectManifest> &&manifest) = 0;

  /**
   * Reset reassembler for new round
   */
  virtual void reInitialize() = 0;

  /**
   * Use indexer to get next segments to reassembly
   */
  virtual void setIndexer(Indexer *indexer) { indexer_verifier_ = indexer; }

  /**
   * Decide if it is required to pass to application buffers whose verification
   * has been delayed (e.g. because the manifest is missing). False by default.
   */
  virtual bool reassembleUnverified() { return false; }

 protected:
  /**
   * Notify application there is data to read.
   */
  virtual void notifyApplication();

 protected:
  implementation::ConsumerSocket *reassembly_consumer_socket_;
  TransportProtocol *transport_protocol_;
  Indexer *indexer_verifier_;
  std::unique_ptr<utils::MemBuf> read_buffer_;
};

}  // namespace protocol

}  // end namespace transport
