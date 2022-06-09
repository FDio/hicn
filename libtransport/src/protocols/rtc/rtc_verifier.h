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

#pragma once

#include <core/facade.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/core/content_object.h>
#include <protocols/rtc/rtc_state.h>

namespace transport {
namespace protocol {
namespace rtc {

class RTCVerifier {
 public:
  explicit RTCVerifier(std::shared_ptr<auth::Verifier> verifier,
                       uint32_t factor_relevant, uint32_t factor_alert);

  virtual ~RTCVerifier() = default;

  void setState(std::shared_ptr<RTCState> rtc_state);
  void setVerifier(std::shared_ptr<auth::Verifier> verifier);
  void setFactorRelevant(uint32_t factor_relevant);
  void setFactorAlert(uint32_t factor_alert);

  auth::VerificationPolicy verify(core::Interest &interest);
  auth::VerificationPolicy verify(core::ContentObject &content_object,
                                  bool is_fec = false);
  auth::VerificationPolicy verifyProbe(core::ContentObject &content_object);
  auth::VerificationPolicy verifyNack(core::ContentObject &content_object);
  auth::VerificationPolicy verifyFec(core::ContentObject &content_object);
  auth::VerificationPolicy verifyData(core::ContentObject &content_object);
  auth::VerificationPolicy verifyManifest(core::ContentObject &content_object);

  auth::VerificationPolicy processManifest(core::ContentObject &content_object);

  void onDataRecoveredFec(uint32_t suffix);

 protected:
  using Index = uint64_t;
  using Packet = std::pair<Index, auth::Suffix>;
  using PacketSet = std::set<Packet>;

  class Packets {
   public:
    std::pair<PacketSet::iterator, bool> add(const Packet &packet,
                                             const auth::CryptoHash &digest);
    PacketSet::iterator remove(PacketSet::iterator packet_it);
    const PacketSet &set() const;
    PacketSet::iterator packet(auth::Suffix suffix);
    const auth::Verifier::SuffixMap &suffixMap() const;

   private:
    PacketSet packets_;
    std::unordered_map<auth::Suffix, PacketSet::iterator> packets_map_;
    auth::Verifier::SuffixMap suffix_map_;
  };

  // The RTC state.
  std::shared_ptr<RTCState> rtc_state_;
  // The verifier instance.
  std::shared_ptr<auth::Verifier> verifier_;
  // Used to compute the relevance windows size (in packets).
  uint32_t factor_relevant_;
  // Used to compute the alert threshold (in packets).
  uint32_t factor_alert_;
  // The maximum number of entries a manifest can contain.
  uint8_t manifest_max_capacity_;
  // Hash algorithm used by manifests.
  auth::CryptoHashType manifest_hash_algo_;
  // Digests extracted from all manifests received.
  auth::Verifier::SuffixMap manifest_digests_;
  // The number of data packets processed.
  Index current_index_;
  // Unverified packets with index in relevance window.
  Packets packets_unverif_;
  // Unverified erased packets with index outside relevance window.
  std::unordered_set<auth::Suffix> packets_unverif_erased_;
};

}  // namespace rtc
}  // namespace protocol
}  // namespace transport
