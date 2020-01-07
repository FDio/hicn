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

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/errors/unexpected_manifest_exception.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/verification_manager.h>
#include <hicn/transport/utils/literals.h>

#include <deque>

namespace transport {

namespace protocol {

class IndexManager {
 public:
  static constexpr uint32_t invalid_index = ~0;

  /**
   *
   */
  virtual ~IndexManager() = default;
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

  virtual void reset() = 0;
};

class IndexVerificationManager : public IndexManager {
 public:
  /**
   *
   */
  virtual ~IndexVerificationManager() = default;

  /**
   * The ownership of the ContentObjectManifest is moved
   * from the caller to the VerificationManager
   */
  virtual bool onManifest(core::ContentObject::Ptr &&content_object) = 0;

  /**
   * The content object must just be verified; the ownership is still of the
   * caller.
   */
  virtual bool onContentObject(const core::ContentObject &content_object) = 0;

  /**
   * The signatures of the packets containing the key must be verified;
   * verifying the authenticity of the key is still on the caller.
   */
  virtual bool onKeyToVerify() = 0;
};

class IncrementalIndexManager : public IndexVerificationManager {
 public:
  IncrementalIndexManager(interface::ConsumerSocket *icn_socket)
      : socket_(icn_socket),
        final_suffix_(std::numeric_limits<uint32_t>::max()),
        next_download_suffix_(0),
        next_reassembly_suffix_(0),
        verification_manager_(
            std::make_unique<SignatureVerificationManager>(icn_socket)) {}

  /**
   *
   */
  virtual ~IncrementalIndexManager() {}

  TRANSPORT_ALWAYS_INLINE virtual void reset() override {
    final_suffix_ = std::numeric_limits<uint32_t>::max();
    next_download_suffix_ = first_suffix_;
    next_reassembly_suffix_ = 0;
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

  TRANSPORT_ALWAYS_INLINE bool onManifest(
      core::ContentObject::Ptr &&content_object) override {
    throw errors::UnexpectedManifestException();
  }

  TRANSPORT_ALWAYS_INLINE bool onContentObject(
      const core::ContentObject &content_object) override {
    auto ret = verification_manager_->onPacketToVerify(content_object);

    if (TRANSPORT_EXPECT_FALSE(content_object.testRst())) {
      final_suffix_ = content_object.getName().getSuffix();
    }

    return ret;
  }

  TRANSPORT_ALWAYS_INLINE bool onKeyToVerify() override {
    return verification_manager_->onKeyToVerify();
  }

 protected:
  interface::ConsumerSocket *socket_;
  uint32_t final_suffix_;
  uint32_t first_suffix_;
  uint32_t next_download_suffix_;
  uint32_t next_reassembly_suffix_;
  std::unique_ptr<VerificationManager> verification_manager_;
};

}  // end namespace protocol

}  // end namespace transport
