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

#include <hicn/transport/protocols/reassembly.h>

namespace transport {

namespace protocol {

class ByteStreamReassembly : public Reassembly {
 public:
  ByteStreamReassembly(interface::ConsumerSocket *icn_socket,
                       TransportProtocol *transport_protocol);

 protected:
  virtual void reassemble(core::ContentObject::Ptr &&content_object) override;

  virtual void reassemble(
      std::unique_ptr<core::ContentObjectManifest> &&manifest) override;

  virtual void copyContent(const core::ContentObject &content_object);

  virtual void reInitialize() override;

 private:
  void assembleContent();

 protected:
  // The consumer socket
  // std::unique_ptr<IncrementalIndexManager> incremental_index_manager_;
  // std::unique_ptr<ManifestIndexManager> manifest_index_manager_;
  // IndexVerificationManager *index_manager_;
  std::unordered_map<std::uint32_t, core::ContentObject::Ptr> received_packets_;
  uint32_t index_;
  bool download_complete_;
};

}  // namespace protocol

}  // end namespace transport
