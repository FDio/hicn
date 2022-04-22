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
                         uint32_t max_unverified_interval,
                         double max_unverified_ratio)
    : verifier_(verifier),
      max_unverified_interval_(max_unverified_interval),
      max_unverified_ratio_(max_unverified_ratio) {}

void RTCVerifier::setState(std::shared_ptr<RTCState> rtc_state) {
  rtc_state_ = rtc_state;
}

void RTCVerifier::setVerifier(std::shared_ptr<auth::Verifier> verifier) {
  verifier_ = verifier;
}

void RTCVerifier::setMaxUnverifiedInterval(uint32_t max_unverified_interval) {
  max_unverified_interval_ = max_unverified_interval;
}

void RTCVerifier::setMaxUnverifiedRatio(double max_unverified_ratio) {
  max_unverified_ratio_ = max_unverified_ratio;
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
  Timestamp now = utils::SteadyTime::nowMs().count();

  // Flush old packets
  Timestamp oldest = flush_packets(now);

  // Add packet to map of unverified packets
  packets_unverif_.add(
      {.suffix = suffix, .timestamp = now, .size = content_object.length()},
      content_object.computeDigest(manifest_hash_algo_));

  // Check that the ratio of unverified packets stays below the limit
  if (now - oldest < max_unverified_interval_ ||
      getBufferRatio() < max_unverified_ratio_) {
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
  core::ContentObjectManifest manifest(content_object);
  manifest.decode();

  // Update last manifest
  if (suffix > last_manifest_) {
    last_manifest_ = suffix;
  }

  // Extract hash algorithm and hashes
  manifest_hash_algo_ = manifest.getHashAlgorithm();
  auth::Verifier::SuffixMap suffix_map =
      core::ContentObjectManifest::getSuffixMap(&manifest);

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
        auto packet_unverif_it = packets_unverif_.packetIt(p.first);
        Packet packet_verif = *packet_unverif_it;
        packets_unverif_.remove(packet_unverif_it);
        packets_verif_.add(packet_verif);
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

void RTCVerifier::onJumpForward(uint32_t next_suffix) {
  if (next_suffix <= last_manifest_ + 1) {
    return;
  }

  // When we jump forward in the suffix sequence, we remove packets that won't
  // be verified. Those packets have a suffix in the range [last_manifest_ + 1,
  // next_suffix[.
  for (auth::Suffix suffix = last_manifest_ + 1; suffix < next_suffix;
       ++suffix) {
    auto packet_it = packets_unverif_.packetIt(suffix);
    if (packet_it != packets_unverif_.set().end()) {
      packets_unverif_.remove(packet_it);
    }
  }
}

double RTCVerifier::getBufferRatio() const {
  size_t total = packets_verif_.size() + packets_unverif_.size();
  double total_unverified = static_cast<double>(packets_unverif_.size());
  return total ? total_unverified / total : 0.0;
}

RTCVerifier::Timestamp RTCVerifier::flush_packets(Timestamp now) {
  Timestamp oldest_verified = packets_verif_.set().empty()
                                  ? now
                                  : packets_verif_.set().begin()->timestamp;
  Timestamp oldest_unverified = packets_unverif_.set().empty()
                                    ? now
                                    : packets_unverif_.set().begin()->timestamp;

  // Prune verified packets older than the unverified interval
  for (auto it = packets_verif_.set().begin();
       it != packets_verif_.set().end();) {
    if (now - it->timestamp < max_unverified_interval_) {
      break;
    }
    it = packets_verif_.remove(it);
  }

  // Prune unverified packets older than the unverified interval
  for (auto it = packets_unverif_.set().begin();
       it != packets_unverif_.set().end();) {
    if (now - it->timestamp < max_unverified_interval_) {
      break;
    }
    packets_unverif_erased_.insert(it->suffix);
    it = packets_unverif_.remove(it);
  }

  return std::min(oldest_verified, oldest_unverified);
}

std::pair<RTCVerifier::PacketSet::iterator, bool> RTCVerifier::Packets::add(
    const Packet &packet) {
  auto inserted = packets_.insert(packet);
  size_ += inserted.second ? packet.size : 0;
  return inserted;
}

RTCVerifier::PacketSet::iterator RTCVerifier::Packets::remove(
    PacketSet::iterator packet_it) {
  size_ -= packet_it->size;
  return packets_.erase(packet_it);
}

const std::set<RTCVerifier::Packet> &RTCVerifier::Packets::set() const {
  return packets_;
};

size_t RTCVerifier::Packets::size() const { return size_; };

std::pair<RTCVerifier::PacketSet::iterator, bool>
RTCVerifier::PacketsUnverif::add(const Packet &packet,
                                 const auth::CryptoHash &digest) {
  auto inserted = add(packet);
  if (inserted.second) {
    packets_map_[packet.suffix] = inserted.first;
    digests_map_[packet.suffix] = digest;
  }
  return inserted;
}

RTCVerifier::PacketSet::iterator RTCVerifier::PacketsUnverif::remove(
    PacketSet::iterator packet_it) {
  size_ -= packet_it->size;
  packets_map_.erase(packet_it->suffix);
  digests_map_.erase(packet_it->suffix);
  return packets_.erase(packet_it);
}

RTCVerifier::PacketSet::iterator RTCVerifier::PacketsUnverif::packetIt(
    auth::Suffix suffix) {
  return packets_map_.at(suffix);
};

const auth::Verifier::SuffixMap &RTCVerifier::PacketsUnverif::suffixMap()
    const {
  return digests_map_;
}

}  // end namespace rtc
}  // end namespace protocol
}  // end namespace transport
