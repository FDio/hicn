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

#include <hicn/transport/protocols/indexer.h>

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/errors/unexpected_manifest_exception.h>
#include <hicn/transport/protocols/reassembly.h>
#include <hicn/transport/protocols/verification_manager.h>
#include <hicn/transport/utils/literals.h>

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
  IncrementalIndexer(interface::ConsumerSocket *icn_socket,
                     TransportProtocol *transport, Reassembly *reassembly)
      : socket_(icn_socket),
        reassembly_(reassembly),
        transport_protocol_(transport),
        final_suffix_(std::numeric_limits<uint32_t>::max()),
        first_suffix_(0),
        next_download_suffix_(0),
        next_reassembly_suffix_(0),
        verification_manager_(
            std::make_unique<SignatureVerificationManager>(icn_socket)) {
    if (reassembly_) {
      reassembly_->setIndexer(this);
    }
  }

  IncrementalIndexer(const IncrementalIndexer &) = delete;

  IncrementalIndexer(IncrementalIndexer &&other)
      : socket_(other.socket_),
        reassembly_(other.reassembly_),
        transport_protocol_(other.transport_protocol_),
        final_suffix_(other.final_suffix_),
        first_suffix_(other.first_suffix_),
        next_download_suffix_(other.next_download_suffix_),
        next_reassembly_suffix_(other.next_reassembly_suffix_),
        verification_manager_(std::move(other.verification_manager_)) {
    if (reassembly_) {
      reassembly_->setIndexer(this);
    }
  }

  /**
   *
   */
  virtual ~IncrementalIndexer() {}

  TRANSPORT_ALWAYS_INLINE virtual void reset(
      std::uint32_t offset = 0) override {
    final_suffix_ = std::numeric_limits<uint32_t>::max();
    next_download_suffix_ = offset;
    next_reassembly_suffix_ = offset;
  }

  /**
   * Retrieve from the manifest the next suffix to retrieve.
   */
  TRANSPORT_ALWAYS_INLINE virtual uint32_t getNextSuffix() override {
    return next_download_suffix_ <= final_suffix_ ? next_download_suffix_++
                                                  : IndexManager::invalid_index;
  }

  TRANSPORT_ALWAYS_INLINE virtual void setFirstSuffix(
      uint32_t suffix) override {
    first_suffix_ = suffix;
  }

  /**
   * Retrive the next segment to be reassembled.
   */
  TRANSPORT_ALWAYS_INLINE virtual uint32_t getNextReassemblySegment() override {
    return next_reassembly_suffix_ <= final_suffix_
               ? next_reassembly_suffix_++
               : IndexManager::invalid_index;
  }

  TRANSPORT_ALWAYS_INLINE virtual bool isFinalSuffixDiscovered() override {
    return final_suffix_ != std::numeric_limits<uint32_t>::max();
  }

  TRANSPORT_ALWAYS_INLINE virtual uint32_t getFinalSuffix() override {
    return final_suffix_;
  }

  void onContentObject(core::Interest::Ptr &&interest,
                       core::ContentObject::Ptr &&content_object) override;

  TRANSPORT_ALWAYS_INLINE void setReassembly(Reassembly *reassembly) {
    reassembly_ = reassembly;

    if (reassembly_) {
      reassembly_->setIndexer(this);
    }
  }

 protected:
  interface::ConsumerSocket *socket_;
  Reassembly *reassembly_;
  TransportProtocol *transport_protocol_;
  uint32_t final_suffix_;
  uint32_t first_suffix_;
  uint32_t next_download_suffix_;
  uint32_t next_reassembly_suffix_;
  std::unique_ptr<VerificationManager> verification_manager_;
};

}  // end namespace protocol

}  // end namespace transport
