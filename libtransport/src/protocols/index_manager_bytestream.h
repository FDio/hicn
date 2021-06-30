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

#include <protocols/incremental_indexer_bytestream.h>

#include <list>

namespace transport {

namespace implementation {
class ConsumerSocket;
}

namespace protocol {

class TransportProtocol;

class IndexManager : public IncrementalIndexer {
 public:
  IndexManager(implementation::ConsumerSocket *icn_socket,
               TransportProtocol *transport);

  uint32_t getNextSuffix() override { return indexer_->getNextSuffix(); }

  void setFirstSuffix(uint32_t suffix) override {
    indexer_->setFirstSuffix(suffix);
  }

  uint32_t getFirstSuffix() override {
    return indexer_->getFirstSuffix();
  }

  uint32_t getNextReassemblySegment() override {
    return indexer_->getNextReassemblySegment();
  }

  bool isFinalSuffixDiscovered() override {
    return indexer_->isFinalSuffixDiscovered();
  }

  uint32_t getFinalSuffix() override { return indexer_->getFinalSuffix(); }

  uint32_t jumpToIndex(uint32_t index) override {
    return indexer_->jumpToIndex(index);
  }

  void setNFec(uint32_t n_fec) override { return indexer_->setNFec(n_fec); }
  uint32_t getNFec() override { return indexer_->getNFec(); }

  void enableFec(fec::FECType fec_type) override {
    return indexer_->enableFec(fec_type);
  }

  double getFecOverhead() override {
    return indexer_->getFecOverhead();
  }

  double getMaxFecOverhead() override {
    return indexer_->getMaxFecOverhead();
  }

  void disableFec() override { return indexer_->disableFec(); }

  void reset() override;

  void setReassembly(Reassembly *reassembly) override {
      Indexer::setReassembly(reassembly);
      indexer_->setReassembly(reassembly);
  }

  void onContentObject(core::Interest &interest,
                       core::ContentObject &content_object,
                       bool reassembly) override;

 private:
  std::unique_ptr<Indexer> indexer_;
  bool first_segment_received_;
  std::set<std::pair<core::Interest::Ptr, core::ContentObject::Ptr>>
      interest_data_set_;
};

}  // namespace protocol
}  // namespace transport
