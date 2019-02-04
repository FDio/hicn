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

#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/protocols/indexing_manager.h>

namespace transport {

namespace protocol {

// Forward Declaration
class ManifestManager;

class Reassembly {
 protected:
  virtual void reassemble(ContentObject::Ptr &&content_object) = 0;
  virtual void reset() = 0;
};

class BaseReassembly : public Reassembly {
 public:
  BaseReassembly(interface::ConsumerSocket *icn_socket);
 protected:
  virtual void reassemble(ContentObject::Ptr &&content_object) override;

  virtual void returnContentToApplication();

  virtual void partialDownload();

  virtual void copyContent(const ContentObject &content_object);

  virtual void reset() override;

 private:
  void callApplicationCallback(std::error_code&& ec);
 
 protected:
  // The consumer socket
  interface::ConsumerSocket *reassembly_consumer_socket_;
  std::unique_ptr<IndexVerificationManager> index_manager_;
  uint64_t last_reassembled_segment_;
  std::unordered_map<std::uint32_t, ContentObject::Ptr> received_packets_;
};

}  // namespace protocol

}  // end namespace transport
