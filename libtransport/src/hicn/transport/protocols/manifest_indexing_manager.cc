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

#include <deque>

namespace transport {

namespace protocol {

using namespace interface;

ManifestIndexManager::ManifestIndexManager(interface::ConsumerSocket *icn_socket)
  : IncrementalIndexManager(icn_socket),
    next_reassembly_segment_(suffix_queue_.begin()),
    next_to_retrieve_segment_(suffix_queue_.begin()) {}

bool ManifestIndexManager::onManifest(core::ContentObject::Ptr &&content_object) {
  auto manifest =
        std::make_unique<ContentObjectManifest>(std::move(*content_object));

  bool manifest_verified = verification_manager_->onPacketToVerify(*manifest);
  
  if (manifest_verified) {
    manifest->decode();

    if (TRANSPORT_EXPECT_FALSE(manifest->getVersion() != core::ManifestVersion::VERSION_1)) {
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

        for (; _it != _end; _it++) {
          suffix_hash_map_[_it->first] = std::make_pair(
              std::vector<uint8_t>(_it->second, _it->second + 32),
              manifest->getHashAlgorithm());
          suffix_queue_.push_back(_it->first);
        }

        if (TRANSPORT_EXPECT_TRUE(!manifest->isFinalManifest())) {
          suffix_queue_.push_front(suffix_queue_.back() + 1);
          next_to_retrieve_segment_ = suffix_queue_.begin();
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

bool ManifestIndexManager::onContentObject(const core::ContentObject &content_object) {
  bool verify_signature;
  socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE, verify_signature);

  if (!verify_signature) {
    return true;
  }

  uint64_t segment = content_object.getName().getSuffix();

  bool ret = false;

  auto it = suffix_hash_map_.find(segment);
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
  if (TRANSPORT_EXPECT_FALSE(next_to_retrieve_segment_ == suffix_queue_.end())) {
    return invalid_index;
  }

  return *next_to_retrieve_segment_++;
}

uint32_t ManifestIndexManager::getFinalSuffix() {
  return final_suffix_;
}

bool ManifestIndexManager::isFinalSuffixDiscovered() {
  return IncrementalIndexManager::isFinalSuffixDiscovered();
}

uint32_t ManifestIndexManager::getNextReassemblySegment() {
  if (TRANSPORT_EXPECT_FALSE(next_reassembly_segment_ == suffix_queue_.end())) {
    return invalid_index;
  }

  auto ret = *next_reassembly_segment_;
  next_reassembly_segment_ = suffix_queue_.erase(next_reassembly_segment_);
  return ret;
}

void ManifestIndexManager::reset() {
  IncrementalIndexManager::reset();
  suffix_queue_.clear();
  suffix_hash_map_.clear();
}

}  // end namespace protocol

}  // end namespace transport
