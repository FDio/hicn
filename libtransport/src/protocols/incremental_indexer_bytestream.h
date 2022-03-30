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

#include <hicn/transport/errors/errors.h>
#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/utils/literals.h>
#include <implementation/socket_consumer.h>
#include <protocols/indexer.h>
#include <protocols/reassembly.h>

#include <deque>

namespace transport {

namespace interface {
class ConsumerSocket;
}

namespace protocol {

class Reassembly;
class TransportProtocol;

class IncrementalIndexer : public Indexer {
 public:
  IncrementalIndexer(implementation::ConsumerSocket *icn_socket,
                     TransportProtocol *transport)
      : Indexer(icn_socket, transport),
        final_suffix_(Indexer::invalid_index),
        first_suffix_(0),
        next_download_suffix_(0),
        next_reassembly_suffix_(0) {}

  IncrementalIndexer(const IncrementalIndexer &other) = delete;

  IncrementalIndexer(IncrementalIndexer &&other)
      : Indexer(std::forward<Indexer>(other)),
        final_suffix_(other.final_suffix_),
        first_suffix_(other.first_suffix_),
        next_download_suffix_(other.next_download_suffix_),
        next_reassembly_suffix_(other.next_reassembly_suffix_) {}

  virtual ~IncrementalIndexer() {}

  virtual void reset() override {
    final_suffix_ = Indexer::invalid_index;
    next_download_suffix_ = first_suffix_;
    next_reassembly_suffix_ = first_suffix_;
  }

  virtual uint32_t checkNextSuffix() const override {
    return next_download_suffix_ <= final_suffix_ ? next_download_suffix_
                                                  : Indexer::invalid_index;
  }

  virtual uint32_t getNextSuffix() override {
    return next_download_suffix_ <= final_suffix_ ? next_download_suffix_++
                                                  : Indexer::invalid_index;
  }

  virtual void setFirstSuffix(uint32_t suffix) override {
    first_suffix_ = suffix;
  }

  uint32_t getFirstSuffix() const override { return first_suffix_; }

  virtual uint32_t jumpToIndex(uint32_t index) override {
    next_download_suffix_ = index;
    return next_download_suffix_;
  }

  /**
   * Retrive the next segment to be reassembled.
   */
  virtual uint32_t getNextReassemblySegment() override {
    return next_reassembly_suffix_ <= final_suffix_ ? next_reassembly_suffix_++
                                                    : Indexer::invalid_index;
  }

  virtual bool isFinalSuffixDiscovered() override {
    return final_suffix_ != Indexer::invalid_index;
  }

  virtual uint32_t getFinalSuffix() const override { return final_suffix_; }

  void enableFec(fec::FECType fec_type) override {}

  void disableFec() override {}

  void setNFec(uint32_t n_fec) override {}
  virtual uint32_t getNFec() const override { return 0; }

  virtual void onContentObject(core::Interest &interest,
                               core::ContentObject &content_object,
                               bool reassembly) override;

 protected:
  uint32_t final_suffix_;
  uint32_t first_suffix_;
  uint32_t next_download_suffix_;
  uint32_t next_reassembly_suffix_;
};

}  // namespace protocol
}  // namespace transport
