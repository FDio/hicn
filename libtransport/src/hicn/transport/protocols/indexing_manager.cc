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
#include <hicn/transport/protocols/indexing_manager.h>

#include <deque>

namespace transport {

namespace protocol {

using namespace interface;

ManifestIndexVerificationManager::ManifestIndexVerificationManager(interface::ConsumerSocket *icn_socket)
  : TrivialIndexManager(),
    socket_(icn_socket),
    download_started_(false),
    manifest_(false) {}

bool ManifestIndexVerificationManager::onManifest(std::unique_ptr<core::ContentObjectManifest> &&manifest) {
  download_started_ = true;
  manifest_ = true;

  bool manifest_verified = verifyManifest(*manifest);

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

        next_manifest_interval_ += manifest->getSuffixList().size();

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

bool ManifestIndexVerificationManager::onContentObject(const core::ContentObject &content_object) {
  bool verify_signature;
  socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE, verify_signature);

  if (!verify_signature) {
    return true;
  }

  uint64_t segment = content_object.getName().getSuffix();

  bool ret = false;

  if (manifest_) {
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
  } else {
    std::shared_ptr<utils::Verifier> verifier;
    socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);
    ret = verifier->verify(content_object);

    if (!ret) {
      throw errors::RuntimeException(
          "Verification failure policy has to be implemented.");
    }
  }

  return ret;
}

uint32_t ManifestIndexVerificationManager::getNextSuffix() {
  auto ret = *next_to_retrieve_segment_;
  next_to_retrieve_segment_++;
  return ret;
}

uint32_t ManifestIndexVerificationManager::getFinalSuffix() {
  return final_suffix_;
}

bool ManifestIndexVerificationManager::isFinalSuffixDiscovered() {
  return TrivialIndexManager::isFinalSuffixDiscovered();
}

uint32_t ManifestIndexVerificationManager::getNextReassemblySegment() {
  auto ret = *next_reassembly_segment_;
  next_reassembly_segment_++;
  return ret;
}

bool ManifestIndexVerificationManager::verifyManifest(
    core::ContentObjectManifest &manifest) {
  bool verify_signature;
  socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE, verify_signature);

  if (!verify_signature) {
    return true;
  }

  bool is_data_secure = false;

  ConsumerContentObjectVerificationCallback *callback;
  socket_->getSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY, &callback);
  if (*callback == VOID_HANDLER) {
    std::shared_ptr<utils::Verifier> verifier;
    socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);
    is_data_secure = static_cast<bool>(verifier->verify(manifest));
  } else if ((*callback)(*socket_, manifest)) {
    is_data_secure = true;
  }

  if (TRANSPORT_EXPECT_FALSE(!is_data_secure)) {
    TRANSPORT_LOGE("Verification failed for %s\n", manifest.getName().toString().c_str());
  }

  return is_data_secure;
}

void ManifestIndexVerificationManager::reset() {
  TrivialIndexManager::reset();
  download_started_ = false;
  manifest_ = false;
  suffix_queue_.clear();
  suffix_hash_map_.clear();
}

}  // end namespace protocol

}  // end namespace transport
