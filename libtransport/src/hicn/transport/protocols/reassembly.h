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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/protocols/manifest_indexing_manager.h>

namespace transport {

namespace interface {
class ConsumerReadCallback;
}

namespace protocol {

// Forward Declaration
class ManifestManager;

class Reassembly {
 public:
  class ContentReassembledCallback {
   public:
    virtual void onContentReassembled(std::error_code ec) = 0;
  };

  virtual void reassemble(ContentObject::Ptr &&content_object) = 0;
  virtual void reset() = 0;
  virtual void setContentCallback(ContentReassembledCallback *callback) {
    content_callback_ = callback;
  }

 protected:
  ContentReassembledCallback *content_callback_;
};

class BaseReassembly : public Reassembly {
 public:
  BaseReassembly(interface::ConsumerSocket *icn_socket,
                 ContentReassembledCallback *content_callback,
                 TransportProtocol *next_interest);

 protected:
  virtual void reassemble(ContentObject::Ptr &&content_object) override;

  virtual void copyContent(const ContentObject &content_object);

  virtual void reset() override;

 private:
  void notifyApplication();

 protected:
  // The consumer socket
  interface::ConsumerSocket *reassembly_consumer_socket_;
  std::unique_ptr<IncrementalIndexManager> incremental_index_manager_;
  std::unique_ptr<ManifestIndexManager> manifest_index_manager_;
  IndexVerificationManager *index_manager_;
  std::unordered_map<std::uint32_t, ContentObject::Ptr> received_packets_;

  uint32_t index_;
  std::unique_ptr<utils::MemBuf> read_buffer_;
};

}  // namespace protocol

}  // end namespace transport
