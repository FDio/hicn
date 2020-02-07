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
    interface::ConsumerSocket *icn_socket, TransportProtocol *transport,
    Reassembly *reassembly)
    : IncrementalIndexManager(icn_socket, transport, reassembly),
      suffix_strategy_(nullptr) {}

void ManifestIndexManager::onContentObject(
    core::Interest::Ptr &&interest, core::ContentObject::Ptr &&content_object) {
  // Check if mainfiest or not
  if (content_object->getPayloadType() == PayloadType::MANIFEST) {
    onUntrustedManifest(std::move(interest), std::move(content_object));
  } else if (content_object->getPayloadType() == PayloadType::CONTENT_OBJECT) {
    onUntrustedContentObject(std::move(interest), std::move(content_object));
  }
}

void ManifestIndexManager::onUntrustedManifest(
    core::Interest::Ptr &&interest, core::ContentObject::Ptr &&content_object) {
  auto ret = verification_manager_->onPacketToVerify(*content_object);

  switch (ret) {
    case VerificationPolicy::ACCEPT_PACKET: {
      processTrustedManifest(std::move(content_object));
      break;
    }
    case VerificationPolicy::DROP_PACKET:
    case VerificationPolicy::ABORT_SESSION: {
      transport_protocol_->onContentReassembled(
          make_error_code(protocol_error::session_aborted));
      break;
    }
  }
}

void ManifestIndexManager::processTrustedManifest(
    ContentObject::Ptr &&content_object) {
  auto manifest =
      std::make_unique<ContentObjectManifest>(std::move(*content_object));
  manifest->decode();

  if (TRANSPORT_EXPECT_FALSE(manifest->getVersion() !=
                             core::ManifestVersion::VERSION_1)) {
    throw errors::RuntimeException("Received manifest with unknown version.");
  }

  switch (manifest->getManifestType()) {
    case core::ManifestType::INLINE_MANIFEST: {
      auto _it = manifest->getSuffixList().begin();
      auto _end = manifest->getSuffixList().end();

      if (TRANSPORT_EXPECT_FALSE(manifest->getName().getSuffix() == 0)) {
        suffix_strategy_ = utils::SuffixStrategyFactory::getSuffixStrategy(
            manifest->getNextSegmentCalculationStrategy(),
            next_download_suffix_, std::distance(_it, _end));
      }

      suffix_strategy_->setFinalSuffix(manifest->getFinalBlockNumber());

      for (; _it != _end; _it++) {
        auto hash =
            std::make_pair(std::vector<uint8_t>(_it->second, _it->second + 32),
                           manifest->getHashAlgorithm());

        if (!checkUnverifiedSegments(_it->first, hash)) {
          suffix_hash_map_[_it->first] = std::move(hash);
        }
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

bool ManifestIndexManager::checkUnverifiedSegments(std::uint32_t suffix,
                                                   const HashEntry &hash) {
  auto it = unverified_segments_.find(suffix);

  if (it != unverified_segments_.end()) {
    auto ret = verifyContentObject(hash, *it->second.second);

    switch (ret) {
      case VerificationPolicy::ACCEPT_PACKET: {
        reassembly_->reassemble(std::move(it->second.second));
        break;
      }
      case VerificationPolicy::DROP_PACKET: {
        transport_protocol_->onPacketDropped(std::move(it->second.first),
                                             std::move(it->second.second));
        break;
      }
      case VerificationPolicy::ABORT_SESSION: {
        transport_protocol_->onContentReassembled(
            make_error_code(protocol_error::session_aborted));
        break;
      }
    }

    unverified_segments_.erase(it);
    return true;
  }

  return false;
}

VerificationPolicy ManifestIndexManager::verifyContentObject(
    const HashEntry &manifest_hash, const ContentObject &content_object) {
  VerificationPolicy ret;

  auto hash_type = static_cast<utils::CryptoHashType>(manifest_hash.second);
  auto data_packet_digest = content_object.computeDigest(manifest_hash.second);
  auto data_packet_digest_bytes =
      data_packet_digest.getDigest<uint8_t>().data();
  const std::vector<uint8_t> &manifest_digest_bytes = manifest_hash.first;

  if (utils::CryptoHash::compareBinaryDigest(
          data_packet_digest_bytes, manifest_digest_bytes.data(), hash_type)) {
    ret = VerificationPolicy::ACCEPT_PACKET;
  } else {
    ConsumerContentObjectVerificationFailedCallback
        *verification_failed_callback = VOID_HANDLER;
    socket_->getSocketOption(ConsumerCallbacksOptions::VERIFICATION_FAILED,
                             &verification_failed_callback);
    ret = (*verification_failed_callback)(
        *socket_, content_object,
        make_error_code(protocol_error::integrity_verification_failed));
  }

  return ret;
}

void ManifestIndexManager::onUntrustedContentObject(Interest::Ptr &&i,
                                                    ContentObject::Ptr &&c) {
  auto suffix = c->getName().getSuffix();
  auto it = suffix_hash_map_.find(suffix);

  if (it != suffix_hash_map_.end()) {
    auto ret = verifyContentObject(it->second, *c);

    switch (ret) {
      case VerificationPolicy::ACCEPT_PACKET: {
        suffix_hash_map_.erase(it);
        reassembly_->reassemble(std::move(c));
        break;
      }
      case VerificationPolicy::DROP_PACKET: {
        transport_protocol_->onPacketDropped(std::move(i), std::move(c));
        break;
      }
      case VerificationPolicy::ABORT_SESSION: {
        transport_protocol_->onContentReassembled(
            make_error_code(protocol_error::session_aborted));
        break;
      }
    }
  } else {
    unverified_segments_[suffix] = std::make_pair(std::move(i), std::move(c));
  }
}

uint32_t ManifestIndexManager::getNextSuffix() {
  auto ret = suffix_strategy_->getNextSuffix();

  if (ret <= final_suffix_ && ret != IndexManager::invalid_index) {
    suffix_queue_.push(ret);
    return ret;
  }

  return IndexManager::invalid_index;
}

uint32_t ManifestIndexManager::getFinalSuffix() {
  return suffix_strategy_->getFinalSuffix();
}

bool ManifestIndexManager::isFinalSuffixDiscovered() {
  return IncrementalIndexManager::isFinalSuffixDiscovered();
}

uint32_t ManifestIndexManager::getNextReassemblySegment() {
  if (suffix_queue_.empty()) {
    return IndexManager::invalid_index;
  }

  auto ret = suffix_queue_.front();
  suffix_queue_.pop();
  return ret;
}

void ManifestIndexManager::reset(std::uint32_t offset) {
  IncrementalIndexManager::reset(offset);
  suffix_hash_map_.clear();
  unverified_segments_.clear();
  SuffixQueue empty;
  std::swap(suffix_queue_, empty);
  suffix_strategy_->reset(offset);
}

}  // namespace protocol

}  // namespace transport
