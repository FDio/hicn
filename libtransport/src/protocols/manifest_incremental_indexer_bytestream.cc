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

#include <implementation/socket_consumer.h>
#include <protocols/errors.h>
#include <protocols/manifest_incremental_indexer_bytestream.h>
#include <protocols/transport_protocol.h>

#include <cmath>
#include <deque>

namespace transport {

namespace protocol {

using namespace interface;

ManifestIncrementalIndexer::ManifestIncrementalIndexer(
    implementation::ConsumerSocket *icn_socket, TransportProtocol *transport)
    : IncrementalIndexer(icn_socket, transport),
      suffix_strategy_(utils::SuffixStrategyFactory::getSuffixStrategy(
          utils::NextSuffixStrategy::INCREMENTAL, next_download_suffix_)) {}

void ManifestIncrementalIndexer::onContentObject(
    core::Interest &interest, core::ContentObject &content_object,
    bool reassembly) {
  switch (content_object.getPayloadType()) {
    case PayloadType::DATA: {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Received content " << content_object.getName();
      onUntrustedContentObject(interest, content_object, reassembly);
      break;
    }
    case PayloadType::MANIFEST: {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Received manifest " << content_object.getName();
      onUntrustedManifest(interest, content_object, reassembly);
      break;
    }
    default: {
      return;
    }
  }
}

void ManifestIncrementalIndexer::onUntrustedManifest(
    core::Interest &interest, core::ContentObject &content_object,
    bool reassembly) {
  auth::VerificationPolicy policy = verifier_->verifyPackets(&content_object);

  if (policy != auth::VerificationPolicy::ACCEPT) {
    transport_->onContentReassembled(
        make_error_code(protocol_error::session_aborted));
    return;
  }

  auto manifest =
      std::make_unique<ContentObjectManifest>(std::move(content_object));
  manifest->decode();

  processTrustedManifest(interest, std::move(manifest), reassembly);
}

void ManifestIncrementalIndexer::processTrustedManifest(
    core::Interest &interest, std::unique_ptr<ContentObjectManifest> manifest,
    bool reassembly) {
  if (TRANSPORT_EXPECT_FALSE(manifest->getVersion() !=
                             core::ManifestVersion::VERSION_1)) {
    throw errors::RuntimeException("Received manifest with unknown version.");
  }

  switch (manifest->getType()) {
    case core::ManifestType::INLINE_MANIFEST: {
      suffix_strategy_->setFinalSuffix(
          manifest->getParamsBytestream().final_segment);

      // The packets to verify with the received manifest
      std::vector<auth::PacketPtr> packets;

      // Convert the received manifest to a map of packet suffixes to hashes
      auth::Verifier::SuffixMap current_manifest =
          core::ContentObjectManifest::getSuffixMap(manifest.get());

      // Update 'suffix_map_' with new hashes from the received manifest and
      // build 'packets'
      for (auto it = current_manifest.begin(); it != current_manifest.end();) {
        if (unverified_segments_.find(it->first) ==
            unverified_segments_.end()) {
          suffix_map_[it->first] = std::move(it->second);
          current_manifest.erase(it++);
          continue;
        }

        packets.push_back(std::get<1>(unverified_segments_[it->first]).get());
        it++;
      }

      // Verify unverified segments using the received manifest
      auth::Verifier::PolicyMap policies =
          verifier_->verifyPackets(packets, current_manifest);

      for (unsigned int i = 0; i < packets.size(); ++i) {
        auth::Suffix suffix = packets[i]->getName().getSuffix();

        auto it = unverified_segments_.find(suffix);

        if (policies[suffix] != auth::VerificationPolicy::UNKNOWN) {
          unverified_segments_.erase(it);
          continue;
        }

        applyPolicy(*std::get<0>(it->second), *std::get<1>(it->second),
                    std::get<2>(it->second), policies[suffix]);
      }

      if (reassembly) {
        reassembly_->reassemble(std::move(manifest));
      }
      break;
    }
    case core::ManifestType::FLIC_MANIFEST: {
      throw errors::NotImplementedException();
    }
    case core::ManifestType::FINAL_CHUNK_NUMBER: {
      throw errors::NotImplementedException();
    }
  }
}

void ManifestIncrementalIndexer::onUntrustedContentObject(
    Interest &interest, ContentObject &content_object, bool reassembly) {
  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy policy =
      verifier_->verifyPackets(&content_object, suffix_map_);

  switch (policy) {
    case auth::VerificationPolicy::UNKNOWN: {
      unverified_segments_[suffix] =
          std::make_tuple(interest.shared_from_this(),
                          content_object.shared_from_this(), reassembly);
      break;
    }
    default: {
      suffix_map_.erase(suffix);
      break;
    }
  }

  applyPolicy(interest, content_object, reassembly, policy);
}

uint32_t ManifestIncrementalIndexer::checkNextSuffix() const {
  return suffix_strategy_->checkNextSuffix();
}

uint32_t ManifestIncrementalIndexer::getNextSuffix() {
  auto ret = suffix_strategy_->getNextSuffix();

  if (ret <= suffix_strategy_->getFinalSuffix() &&
      ret != utils::SuffixStrategy::MAX_SUFFIX) {
    suffix_queue_.push(ret);
    return ret;
  }

  return Indexer::invalid_index;
}

uint32_t ManifestIncrementalIndexer::getFinalSuffix() const {
  return suffix_strategy_->getFinalSuffix();
}

bool ManifestIncrementalIndexer::isFinalSuffixDiscovered() {
  return IncrementalIndexer::isFinalSuffixDiscovered();
}

uint32_t ManifestIncrementalIndexer::getNextReassemblySegment() {
  if (suffix_queue_.empty()) {
    return Indexer::invalid_index;
  }

  auto ret = suffix_queue_.front();
  suffix_queue_.pop();
  return ret;
}

void ManifestIncrementalIndexer::reset() {
  IncrementalIndexer::reset();
  suffix_map_.clear();
  unverified_segments_.clear();
  SuffixQueue empty;
  std::swap(suffix_queue_, empty);
  suffix_strategy_->reset(first_suffix_);
}

}  // namespace protocol

}  // namespace transport
