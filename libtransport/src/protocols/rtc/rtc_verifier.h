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
  RTCVerifier(std::shared_ptr<auth::Verifier> verifier,
              uint32_t max_unverified_delay);

  virtual ~RTCVerifier() = default;

  void setState(std::shared_ptr<RTCState> rtc_state);

  void setVerifier(std::shared_ptr<auth::Verifier> verifier);

  void setMaxUnverifiedDelay(uint32_t max_unverified_delay);

  void onDataRecoveredFec(uint32_t suffix);
  void onJumpForward(uint32_t next_suffix);

  uint32_t getTotalUnverified() const;
  uint32_t getMaxUnverified() const;

  auth::VerificationPolicy verify(core::ContentObject &content_object,
                                  bool is_fec = false);
  auth::VerificationPolicy verifyProbe(core::ContentObject &content_object);
  auth::VerificationPolicy verifyNack(core::ContentObject &content_object);
  auth::VerificationPolicy verifyFec(core::ContentObject &content_object);
  auth::VerificationPolicy verifyData(core::ContentObject &content_object);
  auth::VerificationPolicy verifyManifest(core::ContentObject &content_object);

  auth::VerificationPolicy processManifest(core::ContentObject &content_object);

 protected:
  // The RTC state.
  std::shared_ptr<RTCState> rtc_state_;
  // The verifier instance.
  std::shared_ptr<auth::Verifier> verifier_;
  // Hash algorithm used by manifests.
  auth::CryptoHashType manifest_hash_algo_;
  // The last manifest processed.
  auth::Suffix last_manifest_;
  // Hold digests extracted from all manifests received.
  auth::Verifier::SuffixMap manifest_digests_;
  // Hold hashes of all content objects received before they are verified.
  auth::Verifier::SuffixMap unverified_packets_;
  // Hold number of unverified bytes.
  std::unordered_map<auth::Suffix, uint32_t> unverified_bytes_;
  // Maximum delay (in ms) for an unverified byte to become verifed.
  uint32_t max_unverified_delay_;
  // Maximum number of unverified bytes before aborting the connection.
  uint64_t max_unverified_bytes_;
};

}  // end namespace rtc
}  // namespace protocol
}  // namespace transport
