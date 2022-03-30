/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <hicn/transport/auth/policies.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <protocols/fec_utils.h>

#include <set>

namespace transport {

namespace implementation {
class ConsumerSocket;
}

namespace protocol {

class Reassembly;
class TransportProtocol;

class Indexer {
 public:
  static const constexpr uint32_t invalid_index =
      (std::numeric_limits<uint32_t>::max() - 1);

  Indexer(implementation::ConsumerSocket *socket, TransportProtocol *transport);

  virtual ~Indexer() = default;

  /**
   * Suffix getters
   */
  virtual uint32_t checkNextSuffix() const = 0;
  virtual uint32_t getNextSuffix() = 0;
  virtual uint32_t getNextReassemblySegment() = 0;

  /**
   * Set first suffix from where to start.
   */
  virtual void setFirstSuffix(uint32_t suffix) = 0;
  virtual uint32_t getFirstSuffix() const = 0;

  /**
   * Functions to set/enable/disable fec
   */
  virtual void setNFec(uint32_t n_fec) = 0;
  virtual uint32_t getNFec() const = 0;
  virtual void enableFec(fec::FECType fec_type) = 0;
  virtual void disableFec() = 0;
  virtual bool isFec(uint32_t index) { return false; }
  virtual double getFecOverhead() const { return 0.0; }
  virtual double getMaxFecOverhead() const { return 0.0; }

  /**
   * Final suffix helpers.
   */
  virtual bool isFinalSuffixDiscovered() = 0;
  virtual uint32_t getFinalSuffix() const = 0;

  /**
   * Set reassembly protocol
   */
  virtual void setReassembly(Reassembly *reassembly) {
    reassembly_ = reassembly;
  }

  /**
   * Set verifier using socket
   */
  virtual void setVerifier();

  /**
   * Apply a verification policy
   */
  virtual void applyPolicy(core::Interest &interest,
                           core::ContentObject &content_object, bool reassembly,
                           auth::VerificationPolicy policy) const;
  /**
   * Jump to suffix. This may be useful if, for any protocol dependent
   * mechanism, we need to suddenly change current suffix. This does not
   * modify the way suffixes re incremented/decremented (that's part of the
   * implementation).
   */
  virtual uint32_t jumpToIndex(uint32_t index) = 0;

  /**
   * Reset the indexer.
   */
  virtual void reset() = 0;

  /**
   * Process incoming content objects.
   */
  virtual void onContentObject(core::Interest &interest,
                               core::ContentObject &content_object,
                               bool reassembly = true) = 0;

 protected:
  implementation::ConsumerSocket *socket_;
  TransportProtocol *transport_;
  Reassembly *reassembly_;
  std::shared_ptr<auth::Verifier> verifier_;
  auth::CryptoHashType manifest_hash_type_;
};

}  // end namespace protocol

}  // end namespace transport
