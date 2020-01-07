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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/manifest_indexing_manager.h>

#include <cmath>
#include <deque>

namespace transport {

namespace protocol {

using namespace interface;

ManifestIndexManager::ManifestIndexManager(
    interface::ConsumerSocket *icn_socket, TransportProtocol *next_interest)
    : IncrementalIndexManager(icn_socket),
      PacketManager<Interest>(1024),
      next_to_retrieve_segment_(suffix_queue_.end()),
      suffix_manifest_(core::NextSegmentCalculationStrategy::INCREMENTAL, 0),
      next_reassembly_segment_(
          core::NextSegmentCalculationStrategy::INCREMENTAL, 1, true),
      ignored_segments_(),
      next_interest_(next_interest) {}

bool ManifestIndexManager::onManifest(
    core::ContentObject::Ptr &&content_object) {
  auto manifest =
      std::make_unique<ContentObjectManifest>(std::move(*content_object));
  bool manifest_verified = verification_manager_->onPacketToVerify(*manifest);

  if (manifest_verified) {
    manifest->decode();

    if (TRANSPORT_EXPECT_FALSE(manifest->getVersion() !=
                               core::ManifestVersion::VERSION_1)) {
      throw errors::RuntimeException("Received manifest with unknown version.");
    }

    switch (manifest->getManifestType()) {
      case core::ManifestType::INLINE_MANIFEST: {
        auto _it = manifest->getSuffixList().begin();
        auto _end = manifest->getSuffixList().end();
        size_t nb_segments = std::distance(_it, _end);
        final_suffix_ = manifest->getFinalBlockNumber();  // final block number

        TRANSPORT_LOGD("Received manifest %u",
                       manifest->getWritableName().getSuffix());
        suffix_hash_map_[_it->first] =
            std::make_pair(std::vector<uint8_t>(_it->second, _it->second + 32),
                           manifest->getHashAlgorithm());
        suffix_queue_.push_back(_it->first);

        // If the transport protocol finished the list of segments to retrieve,
        // reset the next_to_retrieve_segment_ iterator to the next segment
        // provided by this manifest.
        if (TRANSPORT_EXPECT_FALSE(next_to_retrieve_segment_ ==
                                   suffix_queue_.end())) {
          next_to_retrieve_segment_ = --suffix_queue_.end();
        }

        std::advance(_it, 1);
        for (; _it != _end; _it++) {
          suffix_hash_map_[_it->first] = std::make_pair(
              std::vector<uint8_t>(_it->second, _it->second + 32),
              manifest->getHashAlgorithm());
          suffix_queue_.push_back(_it->first);
        }

        if (TRANSPORT_EXPECT_FALSE(manifest->getName().getSuffix()) == 0) {
          core::NextSegmentCalculationStrategy strategy =
              manifest->getNextSegmentCalculationStrategy();

          suffix_manifest_.reset(0);
          suffix_manifest_.setNbSegments(nb_segments);
          suffix_manifest_.setSuffixStrategy(strategy);
          TRANSPORT_LOGD("Capacity of 1st manifest %zu",
                         suffix_manifest_.getNbSegments());

          next_reassembly_segment_.reset(*suffix_queue_.begin());
          next_reassembly_segment_.setNbSegments(nb_segments);
          suffix_manifest_.setSuffixStrategy(strategy);
        }

        // If the manifest is not full, we add the suffixes of missing segments
        // to the list of segments to ignore when computing the next reassembly
        // index.
        if (TRANSPORT_EXPECT_FALSE(
                suffix_manifest_.getNbSegments() - nb_segments > 0)) {
          auto start = manifest->getSuffixList().begin();
          auto last = --_end;
          for (uint32_t i = last->first + 1;
               i < start->first + suffix_manifest_.getNbSegments(); i++) {
            ignored_segments_.push_back(i);
          }
        }

        if (TRANSPORT_EXPECT_FALSE(manifest->isFinalManifest()) == 0) {
          fillWindow(manifest->getWritableName(),
                     manifest->getName().getSuffix());
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

  return manifest_verified;
}

void ManifestIndexManager::onManifestReceived(Interest::Ptr &&i,
                                              ContentObject::Ptr &&c) {
  onManifest(std::move(c));
  if (next_interest_) {
    next_interest_->scheduleNextInterests();
  }
}

void ManifestIndexManager::onManifestTimeout(Interest::Ptr &&i) {
  const Name &n = i->getName();
  uint32_t segment = n.getSuffix();

  if (segment > final_suffix_) {
    return;
  }

  TRANSPORT_LOGD("Timeout on manifest %u", segment);
  // Get portal
  std::shared_ptr<interface::BasePortal> portal;
  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal);

  // Send requests for manifest out of the congestion window (no
  // in_flight_interests++)
  portal->sendInterest(
      std::move(i),
      std::bind(&ManifestIndexManager::onManifestReceived, this,
                std::placeholders::_1, std::placeholders::_2),
      std::bind(&ManifestIndexManager::onManifestTimeout, this,
                std::placeholders::_1));
}

void ManifestIndexManager::fillWindow(Name &name, uint32_t current_manifest) {
  /* Send as many manifest as required for filling window. */
  uint32_t interest_lifetime;
  double window_size;
  std::shared_ptr<interface::BasePortal> portal;
  Interest::Ptr interest;
  uint32_t current_segment = *next_to_retrieve_segment_;
  // suffix_manifest_ now points to the next manifest to request
  uint32_t last_requested_manifest = (suffix_manifest_++).getSuffix();

  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal);
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           interest_lifetime);
  socket_->getSocketOption(GeneralTransportOptions::CURRENT_WINDOW_SIZE,
                           window_size);

  if (TRANSPORT_EXPECT_FALSE(suffix_manifest_.getSuffix() >= final_suffix_)) {
    suffix_manifest_.updateSuffix(last_requested_manifest);
    return;
  }

  if (current_segment + window_size < suffix_manifest_.getSuffix() &&
      current_manifest != last_requested_manifest) {
    suffix_manifest_.updateSuffix(last_requested_manifest);
    return;
  }

  do {
    interest = getPacket();
    name.setSuffix(suffix_manifest_.getSuffix());
    interest->setName(name);
    interest->setLifetime(interest_lifetime);

    // Send interests for manifest out of the congestion window (no
    // in_flight_interests++)
    portal->sendInterest(
        std::move(interest),
        std::bind(&ManifestIndexManager::onManifestReceived, this,
                  std::placeholders::_1, std::placeholders::_2),
        std::bind(&ManifestIndexManager::onManifestTimeout, this,
                  std::placeholders::_1));
    TRANSPORT_LOGD("Send manifest interest %u", name.getSuffix());

    last_requested_manifest = (suffix_manifest_++).getSuffix();
  } while (current_segment + window_size >= suffix_manifest_.getSuffix() &&
           suffix_manifest_.getSuffix() < final_suffix_);

  // suffix_manifest_ now points to the last requested manifest
  suffix_manifest_.updateSuffix(last_requested_manifest);
}

bool ManifestIndexManager::onContentObject(
    const core::ContentObject &content_object) {
  bool verify_signature;
  socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE,
                           verify_signature);

  if (!verify_signature) {
    return true;
  }

  uint64_t segment = content_object.getName().getSuffix();

  bool ret = false;

  auto it = suffix_hash_map_.find((const unsigned int)segment);
  if (it != suffix_hash_map_.end()) {
    auto hash_type = static_cast<utils::CryptoHashType>(it->second.second);
    auto data_packet_digest = content_object.computeDigest(it->second.second);
    auto data_packet_digest_bytes =
        data_packet_digest.getDigest<uint8_t>().data();
    std::vector<uint8_t> &manifest_digest_bytes = it->second.first;

    if (utils::CryptoHash::compareBinaryDigest(data_packet_digest_bytes,
                                               manifest_digest_bytes.data(),
                                               hash_type)) {
      suffix_hash_map_.erase(it);
      ret = true;
    } else {
      throw errors::RuntimeException(
          "Verification failure policy has to be implemented.");
    }
  }

  return ret;
}

uint32_t ManifestIndexManager::getNextSuffix() {
  if (TRANSPORT_EXPECT_FALSE(next_to_retrieve_segment_ ==
                             suffix_queue_.end())) {
    return invalid_index;
  }

  return *next_to_retrieve_segment_++;
}

uint32_t ManifestIndexManager::getFinalSuffix() { return final_suffix_; }

bool ManifestIndexManager::isFinalSuffixDiscovered() {
  return IncrementalIndexManager::isFinalSuffixDiscovered();
}

uint32_t ManifestIndexManager::getNextReassemblySegment() {
  uint32_t current_reassembly_segment;

  while (true) {
    current_reassembly_segment = next_reassembly_segment_.getSuffix();
    next_reassembly_segment_++;

    if (TRANSPORT_EXPECT_FALSE(current_reassembly_segment > final_suffix_)) {
      return invalid_index;
    }

    if (ignored_segments_.empty()) break;

    auto is_ignored =
        std::find(ignored_segments_.begin(), ignored_segments_.end(),
                  current_reassembly_segment);

    if (is_ignored == ignored_segments_.end()) break;

    ignored_segments_.erase(is_ignored);
  }

  return current_reassembly_segment;
}

void ManifestIndexManager::reset() {
  IncrementalIndexManager::reset();
  suffix_manifest_.reset(0);
  suffix_queue_.clear();
  suffix_hash_map_.clear();
}

}  // end namespace protocol

}  // end namespace transport
