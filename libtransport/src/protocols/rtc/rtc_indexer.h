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

#pragma once

#include <protocols/errors.h>
#include <protocols/fec_utils.h>
#include <protocols/indexer.h>
#include <protocols/rtc/rtc_consts.h>
#include <protocols/transport_protocol.h>

#include <deque>

namespace transport {

namespace interface {
class ConsumerSocket;
}

namespace protocol {

namespace rtc {

template <uint32_t LIMIT = MIN_PROBE_SEQ>
class RtcIndexer : public Indexer {
 public:
  RtcIndexer(implementation::ConsumerSocket *icn_socket,
             TransportProtocol *transport)
      : Indexer(icn_socket, transport),
        first_suffix_(1),
        next_suffix_(first_suffix_),
        fec_type_(fec::FECType::UNKNOWN),
        n_fec_(0),
        n_current_fec_(n_fec_) {}

  RtcIndexer(RtcIndexer &&other) : Indexer(std::forward<Indexer>(other)) {}

  ~RtcIndexer() {}

  void reset() override {
    next_suffix_ = first_suffix_;
    n_fec_ = 0;
  }

  uint32_t checkNextSuffix() override { return next_suffix_; }

  uint32_t getNextSuffix() override {
    if (isFec(next_suffix_)) {
      if (n_current_fec_) {
        auto ret = next_suffix_++;
        n_current_fec_--;
        return ret;
      } else {
        n_current_fec_ = n_fec_;
        next_suffix_ = nextSource(next_suffix_);
      }
    } else if (!n_current_fec_) {
      n_current_fec_ = n_fec_;
    }

    return (next_suffix_++ % LIMIT);
  }

  void setFirstSuffix(uint32_t suffix) override {
    first_suffix_ = suffix % LIMIT;
  }

  uint32_t getFirstSuffix() override { return first_suffix_; }

  uint32_t jumpToIndex(uint32_t index) override {
    next_suffix_ = index % LIMIT;
    return next_suffix_;
  }

  void onContentObject(core::Interest &interest,
                       core::ContentObject &content_object,
                       bool reassembly) override {
    setVerifier();
    auto ret = verifier_->verifyPackets(&content_object);

    switch (ret) {
      case auth::VerificationPolicy::ACCEPT: {
        if (reassembly) {
          reassembly_->reassemble(content_object);
        }
        break;
      }

      case auth::VerificationPolicy::UNKNOWN:
      case auth::VerificationPolicy::DROP: {
        transport_->onPacketDropped(
            interest, content_object,
            make_error_code(protocol_error::verification_failed));
        break;
      }

      case auth::VerificationPolicy::ABORT: {
        transport_->onContentReassembled(
            make_error_code(protocol_error::session_aborted));
        break;
      }
    }
  }

  /**
   * Retrieve the next segment to be reassembled.
   */
  uint32_t getNextReassemblySegment() override {
    throw errors::RuntimeException(
        "Get reassembly segment called on rtc indexer. RTC indexer does not "
        "provide "
        "reassembly.");
  }

  bool isFinalSuffixDiscovered() override { return true; }

  uint32_t getFinalSuffix() override { return LIMIT; }

  void enableFec(fec::FECType fec_type) override { fec_type_ = fec_type; }

  void disableFec() override { fec_type_ = fec::FECType::UNKNOWN; }

  void setNFec(uint32_t n_fec) override {
    n_fec_ = n_fec;
    n_current_fec_ = n_fec_;
  }

  uint32_t getNFec() override { return n_fec_; }

  bool isFec(uint32_t index) override {
    return isFec(fec_type_, index, first_suffix_);
  }

  double getFecOverhead() override {
    if (fec_type_ == fec::FECType::UNKNOWN) {
      return 0;
    }

    double k = (double)fec::FECUtils::getSourceSymbols(fec_type_);
    return (double)n_fec_ / k;
  }

  double getMaxFecOverhead() override {
    if (fec_type_ == fec::FECType::UNKNOWN) {
      return 0;
    }

    double k = (double)fec::FECUtils::getSourceSymbols(fec_type_);
    double n = (double)fec::FECUtils::getBlockSymbols(fec_type_);
    return (double)(n - k) / k;
  }

  static bool isFec(fec::FECType fec_type, uint32_t index,
                    uint32_t first_suffix) {
    if (index < LIMIT) {
      return fec::FECUtils::isFec(fec_type, index, first_suffix);
    }

    return false;
  }

  static uint32_t nextSource(fec::FECType fec_type, uint32_t index,
                             uint32_t first_suffix) {
    return fec::FECUtils::nextSource(fec_type, index, first_suffix) % LIMIT;
  }

 private:
  uint32_t nextSource(uint32_t index) {
    return nextSource(fec_type_, index, first_suffix_);
  }

 private:
  uint32_t first_suffix_;
  uint32_t next_suffix_;
  fec::FECType fec_type_;
  bool fec_enabled_;
  uint32_t n_fec_;
  uint32_t n_current_fec_;
};

}  // namespace rtc
}  // namespace protocol
}  // namespace transport
