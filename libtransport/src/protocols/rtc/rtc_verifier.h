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
                       uint32_t max_unverified_interval,
                       double max_unverified_ratio);

  virtual ~RTCVerifier() = default;

  void setState(std::shared_ptr<RTCState> rtc_state);

  void setVerifier(std::shared_ptr<auth::Verifier> verifier);

  void setMaxUnverifiedInterval(uint32_t max_unverified_interval);

  void setMaxUnverifiedRatio(double max_unverified_ratio);

  auth::VerificationPolicy verify(core::ContentObject &content_object,
                                  bool is_fec = false);
  auth::VerificationPolicy verifyProbe(core::ContentObject &content_object);
  auth::VerificationPolicy verifyNack(core::ContentObject &content_object);
  auth::VerificationPolicy verifyFec(core::ContentObject &content_object);
  auth::VerificationPolicy verifyData(core::ContentObject &content_object);
  auth::VerificationPolicy verifyManifest(core::ContentObject &content_object);

  auth::VerificationPolicy processManifest(core::ContentObject &content_object);

  void onDataRecoveredFec(uint32_t suffix);
  void onJumpForward(uint32_t next_suffix);

  double getBufferRatio() const;

 protected:
  struct Packet;
  using Timestamp = uint64_t;
  using PacketSet = std::set<Packet>;

  struct Packet {
    auth::Suffix suffix;
    Timestamp timestamp;
    size_t size;

    bool operator==(const Packet &b) const {
      return timestamp == b.timestamp && suffix == b.suffix;
    }
    bool operator<(const Packet &b) const {
      return timestamp == b.timestamp ? suffix < b.suffix
                                      : timestamp < b.timestamp;
    }
  };

  class Packets {
   public:
    virtual std::pair<PacketSet::iterator, bool> add(const Packet &packet);
    virtual PacketSet::iterator remove(PacketSet::iterator packet_it);
    const PacketSet &set() const;
    size_t size() const;

   protected:
    PacketSet packets_;
    size_t size_;
  };

  class PacketsVerif : public Packets {};

  class PacketsUnverif : public Packets {
   public:
    using Packets::add;
    std::pair<PacketSet::iterator, bool> add(const Packet &packet,
                                             const auth::CryptoHash &digest);
    PacketSet::iterator remove(PacketSet::iterator packet_it) override;
    PacketSet::iterator packetIt(auth::Suffix suffix);
    const auth::Verifier::SuffixMap &suffixMap() const;

   private:
    std::unordered_map<auth::Suffix, PacketSet::iterator> packets_map_;
    auth::Verifier::SuffixMap digests_map_;
  };

  // The RTC state.
  std::shared_ptr<RTCState> rtc_state_;
  // The verifier instance.
  std::shared_ptr<auth::Verifier> verifier_;
  // Window to consider when verifying packets.
  uint32_t max_unverified_interval_;
  // Ratio of unverified packets over which an alert is triggered.
  double max_unverified_ratio_;
  // The suffix of the last processed manifest.
  auth::Suffix last_manifest_;
  // Hash algorithm used by manifests.
  auth::CryptoHashType manifest_hash_algo_;
  // Digests extracted from all manifests received.
  auth::Verifier::SuffixMap manifest_digests_;
  // Verified packets with timestamp >= now - max_unverified_interval_.
  PacketsVerif packets_verif_;
  // Unverified packets with timestamp >= now - max_unverified_interval_.
  PacketsUnverif packets_unverif_;
  // Unverified erased packets with timestamp < now - max_unverified_interval_.
  std::unordered_set<auth::Suffix> packets_unverif_erased_;

  // Flushes all packets with timestamp < now - max_unverified_interval_.
  // Returns the timestamp of the oldest packet, verified or not.
  Timestamp flush_packets(Timestamp now);
};

}  // namespace rtc
}  // namespace protocol
}  // namespace transport
