/*
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
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
                         uint32_t factor_relevant, uint32_t factor_alert)
    : verifier_(verifier),
      factor_relevant_(factor_relevant),
      factor_alert_(factor_alert),
      manifest_max_capacity_(std::numeric_limits<uint8_t>::max()) {}

void RTCVerifier::setState(std::shared_ptr<RTCState> rtc_state) {
  rtc_state_ = rtc_state;
}

void RTCVerifier::setVerifier(std::shared_ptr<auth::Verifier> verifier) {
  verifier_ = verifier;
}

void RTCVerifier::setFactorRelevant(uint32_t factor_relevant) {
  factor_relevant_ = factor_relevant;
}

void RTCVerifier::setFactorAlert(uint32_t factor_alert) {
  factor_alert_ = factor_alert;
}

auth::VerificationPolicy RTCVerifier::verify(core::Interest &interest) {
  return verifier_->verifyPackets(&interest);
}

auth::VerificationPolicy RTCVerifier::verify(
    core::ContentObject &content_object, bool is_fec) {
  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy default_policy = auth::VerificationPolicy::ABORT;

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

  verifier_->callVerificationFailedCallback(suffix, default_policy);
  return default_policy;
}

auth::VerificationPolicy RTCVerifier::verifyProbe(
    core::ContentObject &content_object) {
  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;

  switch (ProbeHandler::getProbeType(suffix)) {
    case ProbeType::INIT:
      policy = verifyManifest(content_object);
      if (policy == auth::VerificationPolicy::ACCEPT) {
        policy = processManifest(content_object);
      }
      break;
    case ProbeType::RTT:
      policy = verifyNack(content_object);
      break;
    default:
      verifier_->callVerificationFailedCallback(suffix, policy);
      break;
  }

  return policy;
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
  if (_is_ah(content_object.getFormat())) {
    return verifier_->verifyPackets(&content_object);
  }

  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy policy = auth::VerificationPolicy::ABORT;

  uint32_t threshold_relevant = factor_relevant_ * manifest_max_capacity_;
  uint32_t threshold_alert = factor_alert_ * manifest_max_capacity_;

  // Flush packets outside relevance window
  for (auto it = packets_unverif_.set().begin();
       it != packets_unverif_.set().end();) {
    if (it->first > current_index_ - threshold_relevant) {
      break;
    }
    packets_unverif_erased_.insert((unsigned int)it->first);
    it = packets_unverif_.remove(it);
  }

  // Add packet to set of unverified packets
  packets_unverif_.add({current_index_, suffix},
                       content_object.computeDigest(manifest_hash_algo_));
  current_index_++;

  // Check that the number of unverified packets is below the alert threshold
  if (packets_unverif_.set().size() <= threshold_alert) {
    policy = auth::VerificationPolicy::ACCEPT;
  }

  verifier_->callVerificationFailedCallback(suffix, policy);
  return policy;
}

auth::VerificationPolicy RTCVerifier::verifyManifest(
    core::ContentObject &content_object) {
  return verifier_->verifyPackets(&content_object);
}

auth::VerificationPolicy RTCVerifier::processManifest(
    core::ContentObject &content_object) {
  auth::Suffix suffix = content_object.getName().getSuffix();
  auth::VerificationPolicy accept_policy = auth::VerificationPolicy::ACCEPT;

  // Decode manifest
  core::ContentObjectManifest manifest(content_object.shared_from_this());
  manifest.decode();

  // Extract manifest data
  manifest_max_capacity_ = manifest.getMaxCapacity();
  manifest_hash_algo_ = manifest.getHashAlgorithm();
  auth::Verifier::SuffixMap suffix_map = manifest.getSuffixMap();

  // Return early if the manifest is empty
  if (suffix_map.empty()) {
    verifier_->callVerificationFailedCallback(suffix, accept_policy);
    return accept_policy;
  }

  // Add hashes to map of all manifest hashes
  manifest_digests_.insert(suffix_map.begin(), suffix_map.end());

  // Remove discarded and definitely lost packets from digest map
  for (auto it = manifest_digests_.begin(); it != manifest_digests_.end();) {
    auto it_erased = packets_unverif_erased_.find(it->first);

    if (it_erased != packets_unverif_erased_.end()) {
      packets_unverif_erased_.erase(it_erased);
      it = manifest_digests_.erase(it);
      continue;
    }

    if (rtc_state_->getPacketState(it->first) == PacketState::DEFINITELY_LOST) {
      it = manifest_digests_.erase(it);
      continue;
    }

    ++it;
  }

  // Verify packets
  auth::Verifier::PolicyMap policies =
      verifier_->verifyHashes(packets_unverif_.suffixMap(), manifest_digests_);

  for (const auto &p : policies) {
    switch (p.second) {
      case auth::VerificationPolicy::ACCEPT: {
        packets_unverif_.remove(packets_unverif_.packet(p.first));
        manifest_digests_.erase(p.first);
        break;
      }
      case auth::VerificationPolicy::UNKNOWN:
        break;
      case auth::VerificationPolicy::DROP:
      case auth::VerificationPolicy::ABORT:
        return p.second;
    }
  }

  verifier_->callVerificationFailedCallback(suffix, accept_policy);
  return accept_policy;
}

void RTCVerifier::onDataRecoveredFec(uint32_t suffix) {
  manifest_digests_.erase(suffix);
}

std::pair<RTCVerifier::PacketSet::iterator, bool> RTCVerifier::Packets::add(
    const Packet &packet, const auth::CryptoHash &digest) {
  auto inserted = packets_.insert(packet);
  if (inserted.second) {
    packets_map_[packet.second] = inserted.first;
    suffix_map_[packet.second] = digest;
  }
  return inserted;
}

RTCVerifier::PacketSet::iterator RTCVerifier::Packets::remove(
    PacketSet::iterator packet_it) {
  packets_map_.erase(packet_it->second);
  suffix_map_.erase(packet_it->second);
  return packets_.erase(packet_it);
}

const std::set<RTCVerifier::Packet> &RTCVerifier::Packets::set() const {
  return packets_;
};

RTCVerifier::PacketSet::iterator RTCVerifier::Packets::packet(
    auth::Suffix suffix) {
  return packets_map_.at(suffix);
};

const auth::Verifier::SuffixMap &RTCVerifier::Packets::suffixMap() const {
  return suffix_map_;
}

}  // end namespace rtc
}  // end namespace protocol
}  // end namespace transport
