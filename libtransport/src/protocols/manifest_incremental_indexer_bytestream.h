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

#include <hicn/transport/auth/common.h>
#include <implementation/socket.h>
#include <protocols/incremental_indexer_bytestream.h>
#include <utils/suffix_strategy.h>

#include <list>

namespace transport {
namespace protocol {

class ManifestIncrementalIndexer : public IncrementalIndexer {
  static constexpr double alpha = 0.3;

 public:
  using SuffixQueue = std::queue<uint32_t>;
  using InterestContentPair =
      std::tuple<core::Interest::Ptr, core::ContentObject::Ptr, bool>;

  ManifestIncrementalIndexer(implementation::ConsumerSocket *icn_socket,
                             TransportProtocol *transport);

  ManifestIncrementalIndexer(IncrementalIndexer &&indexer)
      : IncrementalIndexer(std::move(indexer)),
        suffix_strategy_(utils::SuffixStrategyFactory::getSuffixStrategy(
            utils::NextSuffixStrategy::INCREMENTAL, next_download_suffix_)) {
    for (uint32_t i = first_suffix_; i < next_download_suffix_; i++) {
      suffix_queue_.push(i);
    }
  }

  virtual ~ManifestIncrementalIndexer() = default;

  void reset() override;

  void onContentObject(core::Interest &interest,
                       core::ContentObject &content_object,
                       bool reassembly) override;

  uint32_t checkNextSuffix() const override;

  uint32_t getNextSuffix() override;

  uint32_t getNextReassemblySegment() override;

  bool isFinalSuffixDiscovered() override;

  uint32_t getFinalSuffix() const override;

 protected:
  std::unique_ptr<utils::SuffixStrategy> suffix_strategy_;
  SuffixQueue suffix_queue_;

  // Hash verification
  auth::Verifier::SuffixMap suffix_map_;
  std::unordered_map<auth::Suffix, InterestContentPair> unverified_segments_;

 private:
  void onUntrustedManifest(core::Interest &interest,
                           core::ContentObject &content_object,
                           bool reassembly);
  void processTrustedManifest(core::Interest &interest,
                              core::ContentObjectManifest &manifest,
                              bool reassembly);
  void onUntrustedContentObject(core::Interest &interest,
                                core::ContentObject &content_object,
                                bool reassembly);
};

}  // end namespace protocol

}  // end namespace transport
