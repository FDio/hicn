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
#include <hicn/transport/core/interest.h>

#include <set>

namespace transport {

namespace interface {
class ConsumerSocket;
}

namespace protocol {

class Reassembly;
class TransportProtocol;

class Indexer {
 public:
  /**
   *
   */
  virtual ~Indexer() = default;
  /**
   * Retrieve from the manifest the next suffix to retrieve.
   */
  virtual uint32_t getNextSuffix() = 0;

  virtual void setFirstSuffix(uint32_t suffix) = 0;

  /**
   * Retrive the next segment to be reassembled.
   */
  virtual uint32_t getNextReassemblySegment() = 0;

  virtual bool isFinalSuffixDiscovered() = 0;

  virtual uint32_t getFinalSuffix() = 0;

  virtual void reset(std::uint32_t offset = 0) = 0;

  virtual void onContentObject(core::Interest::Ptr &&interest,
                               core::ContentObject::Ptr &&content_object) = 0;
};

class IndexManager : Indexer {
 public:
  static constexpr uint32_t invalid_index = ~0;

  IndexManager(interface::ConsumerSocket *icn_socket,
               TransportProtocol *transport, Reassembly *reassembly);

  uint32_t getNextSuffix() override { return indexer_->getNextSuffix(); }

  void setFirstSuffix(uint32_t suffix) override {
    indexer_->setFirstSuffix(suffix);
  }

  uint32_t getNextReassemblySegment() override {
    return indexer_->getNextReassemblySegment();
  }

  bool isFinalSuffixDiscovered() override {
    return indexer_->isFinalSuffixDiscovered();
  }

  uint32_t getFinalSuffix() override { return indexer_->getFinalSuffix(); }

  void reset(std::uint32_t offset = 0) override;

  void onContentObject(core::Interest::Ptr &&interest,
                       core::ContentObject::Ptr &&content_object) override;

 private:
  std::unique_ptr<Indexer> indexer_;
  bool first_segment_received_;
  std::set<std::pair<core::Interest::Ptr, core::ContentObject::Ptr>>
      interest_data_set_;
  interface::ConsumerSocket *icn_socket_;
  TransportProtocol *transport_;
  Reassembly *reassembly_;
};

}  // end namespace protocol

}  // end namespace transport
