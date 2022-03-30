/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

#include <core/facade.h>
#include <protocols/rtc/rtc_packet.h>
#include <protocols/rtc/rtc_verifier.h>

namespace transport {
namespace protocol {
namespace rtc {

RTCVerifier::RTCVerifier(std::shared_ptr<auth::Verifier> verifier,
                         uint32_t max_unverified_delay)
    : verifier_(verifier), max_unverified_delay_(max_unverified_delay) {}

void RTCVerifier::setState(std::shared_ptr<RTCState> rtc_state) {
  rtc_state_ = rtc_state;
}

void RTCVerifier::setVerifier(std::shared_ptr<auth::Verifier> verifier) {
  verifier_ = verifier;
}

void RTCVerifier::setMaxUnverifiedDelay(uint32_t max_unverified_delay) {
  max_unverified_delay_ = max_unverified_delay;
}

auth::VerificationPolicy RTCVerifier::verify(
    core::ContentObject &content_object, bool is_fec) {
  uint32_t suffix = content_object.getName().getSuffix();
  core::PayloadType payload_type = content_object.getPayloadType();

  bool is_probe = ProbeHandler::getProbeType(suffix) != ProbeType::NOT_PROBE;
  bool is_nack = !is_probe && content_object.payloadSize() == NACK_HEADER_SIZE;
  bool is_manifest = !is_probe && !is_nack && !is_fec &&
                     payload_type == core::PayloadType::MANIFEST;
  bool is_data = !is_probe && !is_nack && !is_fec &&
                 payload_type == core::PayloadType::DATA;

  if (is_probe) return verifyProbe(content_object);
  if (is_nack) return verifyNack(content_object);
  if (is_fec) return verifyFec(content_object);
  if (is_data) return verifyData(content_object);
  if (is_manifest) return verifyManifest(content_object);

  auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;
  verifier_->callVerificationFailedCallback(suffix, policy);
  return policy;
}

auth::VerificationPolicy RTCVerifier::verifyProbe(
    core::ContentObject &content_object) {
  switch (ProbeHandler::getProbeType(content_object.getName().getSuffix())) {
    case ProbeType::INIT: {
      auth::VerificationPolicy policy = verifyManifest(content_object);
      if (policy != auth::VerificationPolicy::ACCEPT) {
        return policy;
      }
      return processManifest(content_object);
    }
    case ProbeType::RTT:
      return verifyNack(content_object);
    default:
      auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;
      verifier_->callVerificationFailedCallback(
          content_object.getName().getSuffix(), policy);
      return policy;
  }
}

auth::VerificationPolicy RTCVerifier::verifyNack(
    core::ContentObject &content_object) {
  return verifier_->verifyPackets(&content_object);
}

auth::VerificationPolicy RTCVerifier::verifyFec(
    core::ContentObject &content_object) {
  return verifier_->verifyPackets(&content_object);
}

auth::VerificationPolicy RTCVerifier::verifyData(
    core::ContentObject &content_object) {
  uint32_t suffix = content_object.getName().getSuffix();

  if (_is_ah(content_object.getFormat())) {
    return verifier_->verifyPackets(&content_object);
  }

  unverified_bytes_[suffix] =
      content_object.headerSize() + content_object.payloadSize();
  unverified_packets_[suffix] =
      content_object.computeDigest(manifest_hash_algo_);

  // An alert is raised when too much packets remain unverified
  if (getTotalUnverified() > max_unverified_bytes_) {
    unverified_bytes_.clear();
    unverified_packets_.clear();

    auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;
    verifier_->callVerificationFailedCallback(suffix, policy);
    return policy;
  }

  return auth::VerificationPolicy::ACCEPT;
}

auth::VerificationPolicy RTCVerifier::verifyManifest(
    core::ContentObject &content_object) {
  return verifier_->verifyPackets(&content_object);
}

auth::VerificationPolicy RTCVerifier::processManifest(
    core::ContentObject &content_object) {
  uint32_t suffix = content_object.getName().getSuffix();

  core::ContentObjectManifest manifest(content_object);
  manifest.decode();

  // Update last manifest
  if (suffix > last_manifest_) {
    last_manifest_ = suffix;
  }

  // Extract parameters
  manifest_hash_algo_ = manifest.getHashAlgorithm();
  core::ParamsRTC params = manifest.getParamsRTC();

  if (params.prod_rate > 0) {
    max_unverified_bytes_ = static_cast<uint64_t>(
        (max_unverified_delay_ / 1000.0) * params.prod_rate);
  }

  if (max_unverified_bytes_ == 0 || !rtc_state_) {
    auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;
    verifier_->callVerificationFailedCallback(suffix, policy);
    return policy;
  }

  // Extract hashes
  auth::Verifier::SuffixMap suffix_map =
      core::ContentObjectManifest::getSuffixMap(&manifest);

  // Return early if the manifest is empty
  if (suffix_map.empty()) {
    return auth::VerificationPolicy::ACCEPT;
  }

  // Remove lost packets from digest map
  manifest_digests_.insert(suffix_map.begin(), suffix_map.end());
  for (auto it = manifest_digests_.begin(); it != manifest_digests_.end();) {
    if (rtc_state_->getPacketState(it->first) == PacketState::DEFINITELY_LOST) {
      unverified_packets_.erase(it->first);
      unverified_bytes_.erase(it->first);
      it = manifest_digests_.erase(it);
    } else {
      ++it;
    }
  }

  // Verify packets
  auth::Verifier::PolicyMap policies =
      verifier_->verifyHashes(unverified_packets_, manifest_digests_);

  for (const auto &policy : policies) {
    switch (policy.second) {
      case auth::VerificationPolicy::ACCEPT: {
        manifest_digests_.erase(policy.first);
        unverified_packets_.erase(policy.first);
        unverified_bytes_.erase(policy.first);
        break;
      }
      case auth::VerificationPolicy::UNKNOWN:
        break;
      case auth::VerificationPolicy::DROP:
      case auth::VerificationPolicy::ABORT:
        auth::VerificationPolicy p = policy.second;
        verifier_->callVerificationFailedCallback(policy.first, p);
        return p;
    }
  }

  return auth::VerificationPolicy::ACCEPT;
}

void RTCVerifier::onDataRecoveredFec(uint32_t suffix) {
  manifest_digests_.erase(suffix);
}

void RTCVerifier::onJumpForward(uint32_t next_suffix) {
  if (next_suffix <= last_manifest_ + 1) {
    return;
  }

  // When we jump forward in the suffix sequence, we remove packets that
  // probably won't be verified. Those packets have a suffix in the range
  // [last_manifest_ + 1, next_suffix[.
  for (auto it = unverified_packets_.begin();
       it != unverified_packets_.end();) {
    if (it->first > last_manifest_) {
      unverified_bytes_.erase(it->first);
      it = unverified_packets_.erase(it);
    } else {
      ++it;
    }
  }
}

uint32_t RTCVerifier::getTotalUnverified() const {
  uint32_t total = 0;

  for (auto bytes : unverified_bytes_) {
    if (bytes.second > UINT32_MAX - total) {
      total = UINT32_MAX;
      break;
    }
    total += bytes.second;
  }

  return total;
}

uint32_t RTCVerifier::getMaxUnverified() const { return max_unverified_bytes_; }

}  // end namespace rtc
}  // end namespace protocol
}  // end namespace transport
