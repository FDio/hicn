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

#include <hicn/transport/interfaces/socket.h>

#include <deque>

namespace transport {

namespace protocol {

class IndexManager {

 public:
  /**
   * 
   */
  virtual ~IndexManager() = default;
  /**
   * Retrieve from the manifest the next suffix to retrieve.
   */
  virtual uint32_t getNextSuffix() = 0;

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
  virtual bool onManifest(std::unique_ptr<core::ContentObjectManifest> &&manifest) = 0;

  /**
   * The content object must just be verified; the ownership is still of the
   * caller.
   */ 
  virtual bool onContentObject(const core::ContentObject &content_object) = 0;
};

class TrivialIndexManager : public IndexVerificationManager {
 public:
  TrivialIndexManager() 
    : /*socket_(icn_socket),*/
      final_suffix_(std::numeric_limits<uint64_t>::max()),
      next_download_suffix_(0),
      next_reassembly_suffix_(0) {}
  
  /**
   * 
   */
  virtual ~TrivialIndexManager() {}

  TRANSPORT_ALWAYS_INLINE virtual void reset() override {
    final_suffix_ = std::numeric_limits<uint64_t>::max();
    next_download_suffix_ = 0;
    next_reassembly_suffix_ = 0;
  }

  /**
   * Retrieve from the manifest the next suffix to retrieve.
   */
  TRANSPORT_ALWAYS_INLINE virtual uint32_t getNextSuffix() override {
    return next_download_suffix_++;
  }

  /**
   * Retrive the next segment to be reassembled.
   */
  TRANSPORT_ALWAYS_INLINE virtual uint32_t getNextReassemblySegment() override {
    return next_reassembly_suffix_++;
  }

  TRANSPORT_ALWAYS_INLINE virtual bool isFinalSuffixDiscovered() override {
    return final_suffix_ != std::numeric_limits<uint64_t>::max();
  }

  TRANSPORT_ALWAYS_INLINE virtual uint32_t getFinalSuffix() override {
    return final_suffix_;
  }

  TRANSPORT_ALWAYS_INLINE bool onManifest(std::unique_ptr<core::ContentObjectManifest> &&manifest) override {
    return true;
  }

  TRANSPORT_ALWAYS_INLINE bool onContentObject(const core::ContentObject &content_object) override {
    if (TRANSPORT_EXPECT_FALSE(content_object.testRst())) {
      final_suffix_ = content_object.getName().getSuffix();
    }

    return true;
  }

 protected:
  uint64_t final_suffix_;
  uint64_t next_download_suffix_;
  uint64_t next_reassembly_suffix_;
};

class ManifestIndexVerificationManager : public TrivialIndexManager {
 public:

  using SuffixQueue = std::deque<uint32_t>;
  using HashEntry = std::pair<std::vector<uint8_t>, core::HashAlgorithm>;

  ManifestIndexVerificationManager(interface::ConsumerSocket *icn_socket);

  virtual ~ManifestIndexVerificationManager() = default;

  void reset() override;

  bool onManifest(std::unique_ptr<core::ContentObjectManifest> &&manifest) override;

  bool onContentObject(const core::ContentObject &content_object) override;

  uint32_t getNextSuffix() override;

  uint32_t getNextReassemblySegment() override;

  bool isFinalSuffixDiscovered() override;

  uint32_t getFinalSuffix() override;

 private:
  bool verifyManifest(core::ContentObjectManifest &manifest);

 protected:
  interface::ConsumerSocket *socket_;
  bool download_started_;
  bool manifest_;
  
  SuffixQueue suffix_queue_;
  SuffixQueue::iterator next_reassembly_segment_;
  SuffixQueue::iterator next_to_retrieve_segment_;

  // Manifest indexes
  uint32_t next_manifest_interval_;

  // verification
  std::unordered_map<uint32_t, std::pair<std::vector<uint8_t>, core::HashAlgorithm>> suffix_hash_map_;
};

}  // end namespace protocol

}  // end namespace transport
