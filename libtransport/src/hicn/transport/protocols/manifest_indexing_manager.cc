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
      manifests_in_flight_(0),
      next_reassembly_segment_(suffix_queue_.end()),
      next_to_retrieve_segment_(suffix_queue_.end()),
      suffix_manifest_(core::NextSegmentCalculationStrategy::INCREMENTAL, 0),
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
        auto _end = --manifest->getSuffixList().end();

        if (TRANSPORT_EXPECT_FALSE(manifest->isFinalManifest())) {
          _end++;
        }

        // Get final block number
        final_suffix_ = manifest->getFinalBlockNumber();

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
          // Set the iterators to the beginning of the suffix queue
          next_reassembly_segment_ = suffix_queue_.begin();
          // Set number of segments in manifests assuming the first one is full
          suffix_manifest_.setNbSegments(
              std::distance(manifest->getSuffixList().begin(),
                            manifest->getSuffixList().end()) -
              1);
          suffix_manifest_.setSuffixStrategy(
              manifest->getNextSegmentCalculationStrategy());
        } else if (manifests_in_flight_) {
          manifests_in_flight_--;
        }

        if (TRANSPORT_EXPECT_FALSE(manifest->isFinalManifest() ||
                                   suffix_manifest_.getSuffix() >
                                       final_suffix_)) {
          break;
        }

        // Get current window size
        double current_window_size = 0.;
        socket_->getSocketOption(GeneralTransportOptions::CURRENT_WINDOW_SIZE,
                                 current_window_size);

        // Get portal
        std::shared_ptr<interface::BasePortal> portal;
        socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal);

        // Number of segments in manifest
        std::size_t segment_count = 0;

        // Manifest namespace
        Name &name = manifest->getWritableName();

        if (manifests_in_flight_ >= MAX_MANIFESTS_IN_FLIGHT) {
          break;
        }

        // Send as many manifest as required for filling window.
        do {
          segment_count += suffix_manifest_.getNbSegments();
          suffix_manifest_++;

          Interest::Ptr interest = getPacket();
          name.setSuffix(suffix_manifest_.getSuffix());
          interest->setName(name);

          uint32_t interest_lifetime;
          socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                                   interest_lifetime);
          interest->setLifetime(interest_lifetime);

          // Send requests for manifest out of the congestion window (no
          // in_flight_interests++)
          portal->sendInterest(
              std::move(interest),
              std::bind(&ManifestIndexManager::onManifestReceived, this,
                        std::placeholders::_1, std::placeholders::_2),
              std::bind(&ManifestIndexManager::onManifestTimeout, this,
                        std::placeholders::_1));
          manifests_in_flight_++;
        } while (segment_count < current_window_size &&
                 suffix_manifest_.getSuffix() < final_suffix_ &&
                 manifests_in_flight_ < MAX_MANIFESTS_IN_FLIGHT);

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
  if (TRANSPORT_EXPECT_FALSE(next_reassembly_segment_ == suffix_queue_.end())) {
    return invalid_index;
  }

  if (TRANSPORT_EXPECT_TRUE(next_reassembly_segment_ !=
                            suffix_queue_.begin())) {
    suffix_queue_.erase(std::prev(next_reassembly_segment_));
  }

  return *next_reassembly_segment_++;
}

void ManifestIndexManager::reset() {
  IncrementalIndexManager::reset();
  suffix_manifest_.reset(0);
  suffix_queue_.clear();
  suffix_hash_map_.clear();
}

}  // end namespace protocol

}  // end namespace transport
