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

#include <implementation/socket_consumer.h>
#include <protocols/errors.h>
#include <protocols/manifest_incremental_indexer.h>
#include <protocols/transport_protocol.h>

#include <cmath>
#include <deque>

namespace transport {

namespace protocol {

using namespace interface;

ManifestIncrementalIndexer::ManifestIncrementalIndexer(
    implementation::ConsumerSocket *icn_socket, TransportProtocol *transport,
    Reassembly *reassembly)
    : IncrementalIndexer(icn_socket, transport, reassembly),
      suffix_strategy_(utils::SuffixStrategyFactory::getSuffixStrategy(
          NextSegmentCalculationStrategy::INCREMENTAL, next_download_suffix_,
          0)) {}

void ManifestIncrementalIndexer::onContentObject(
    core::Interest &interest, core::ContentObject &content_object) {
  switch (content_object.getPayloadType()) {
    case PayloadType::DATA: {
      TRANSPORT_LOGD("Received content %s",
                     content_object.getName().toString().c_str());
      onUntrustedContentObject(interest, content_object);
      break;
    }
    case PayloadType::MANIFEST: {
      TRANSPORT_LOGD("Received manifest %s",
                     content_object.getName().toString().c_str());
      onUntrustedManifest(interest, content_object);
      break;
    }
    default: {
      return;
    }
  }
}

void ManifestIncrementalIndexer::onUntrustedManifest(
    core::Interest &interest, core::ContentObject &content_object) {
  auto manifest =
      std::make_unique<ContentObjectManifest>(std::move(content_object));

  auth::VerificationPolicy policy = verifier_->verifyPackets(manifest.get());

  manifest->decode();

  if (policy != auth::VerificationPolicy::ACCEPT) {
    transport_protocol_->onContentReassembled(
        make_error_code(protocol_error::session_aborted));
    return;
  }

  processTrustedManifest(interest, std::move(manifest));
}

void ManifestIncrementalIndexer::processTrustedManifest(
    core::Interest &interest, std::unique_ptr<ContentObjectManifest> manifest) {
  if (TRANSPORT_EXPECT_FALSE(manifest->getVersion() !=
                             core::ManifestVersion::VERSION_1)) {
    throw errors::RuntimeException("Received manifest with unknown version.");
  }

  switch (manifest->getManifestType()) {
    case core::ManifestType::INLINE_MANIFEST: {
      suffix_strategy_->setFinalSuffix(manifest->getFinalBlockNumber());

      // The packets to verify with the received manifest
      std::vector<auth::PacketPtr> packets;

      // Convert the received manifest to a map of packet suffixes to hashes
      std::unordered_map<auth::Suffix, auth::HashEntry> current_manifest =
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

        packets.push_back(unverified_segments_[it->first].second.get());
        it++;
      }

      // Verify unverified segments using the received manifest
      std::vector<auth::VerificationPolicy> policies =
          verifier_->verifyPackets(packets, current_manifest);

      for (unsigned int i = 0; i < packets.size(); ++i) {
        auth::Suffix suffix = packets[i]->getName().getSuffix();

        if (policies[i] != auth::VerificationPolicy::UNKNOWN) {
          unverified_segments_.erase(suffix);
        }

        applyPolicy(*unverified_segments_[suffix].first,
                    *unverified_segments_[suffix].second, policies[i]);
      }

      reassembly_->reassemble(std::move(manifest));
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
    Interest &interest, ContentObject &content_object) {
  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy policy =
      verifier_->verifyPackets(&content_object, suffix_map_);

  switch (policy) {
    case auth::VerificationPolicy::UNKNOWN: {
      unverified_segments_[suffix] = std::make_pair(
          interest.shared_from_this(), content_object.shared_from_this());
      break;
    }
    default: {
      suffix_map_.erase(suffix);
      break;
    }
  }

  applyPolicy(interest, content_object, policy);
}

void ManifestIncrementalIndexer::applyPolicy(
    core::Interest &interest, core::ContentObject &content_object,
    auth::VerificationPolicy policy) {
  switch (policy) {
    case auth::VerificationPolicy::ACCEPT: {
      reassembly_->reassemble(content_object);
      break;
    }
    case auth::VerificationPolicy::DROP: {
      transport_protocol_->onPacketDropped(interest, content_object);
      break;
    }
    case auth::VerificationPolicy::ABORT: {
      transport_protocol_->onContentReassembled(
          make_error_code(protocol_error::session_aborted));
      break;
    }
    default: {
      break;
    }
  }
}

uint32_t ManifestIncrementalIndexer::getNextSuffix() {
  auto ret = suffix_strategy_->getNextSuffix();

  if (ret <= suffix_strategy_->getFinalSuffix() &&
      ret != utils::SuffixStrategy::INVALID_SUFFIX) {
    suffix_queue_.push(ret);
    return ret;
  }

  return IndexManager::invalid_index;
}

uint32_t ManifestIncrementalIndexer::getFinalSuffix() {
  return suffix_strategy_->getFinalSuffix();
}

bool ManifestIncrementalIndexer::isFinalSuffixDiscovered() {
  return IncrementalIndexer::isFinalSuffixDiscovered();
}

uint32_t ManifestIncrementalIndexer::getNextReassemblySegment() {
  if (suffix_queue_.empty()) {
    return IndexManager::invalid_index;
  }

  auto ret = suffix_queue_.front();
  suffix_queue_.pop();
  return ret;
}

void ManifestIncrementalIndexer::reset(std::uint32_t offset) {
  IncrementalIndexer::reset(offset);
  suffix_map_.clear();
  unverified_segments_.clear();
  SuffixQueue empty;
  std::swap(suffix_queue_, empty);
  suffix_strategy_->reset(offset);
}

}  // namespace protocol

}  // namespace transport
