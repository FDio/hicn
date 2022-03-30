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

#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/membuf.h>
#include <protocols/fec/fec_info.h>
#include <protocols/fec_base.h>

#include <rely/decoder.hpp>
#include <rely/encoder.hpp>

#define RELY_DEBUG 0

namespace transport {
namespace protocol {
namespace fec {

/**
 * @brief Table of used codes.
 */
#define foreach_rely_fec_type \
  _(Rely, 1, 2)               \
  _(Rely, 1, 3)               \
  _(Rely, 1, 4)               \
  _(Rely, 2, 3)               \
  _(Rely, 2, 6)               \
  _(Rely, 3, 9)               \
  _(Rely, 4, 5)               \
  _(Rely, 4, 6)               \
  _(Rely, 4, 7)               \
  _(Rely, 6, 10)              \
  _(Rely, 8, 10)              \
  _(Rely, 8, 11)              \
  _(Rely, 8, 12)              \
  _(Rely, 8, 14)              \
  _(Rely, 8, 16)              \
  _(Rely, 8, 32)              \
  _(Rely, 10, 30)             \
  _(Rely, 10, 40)             \
  _(Rely, 10, 90)             \
  _(Rely, 16, 21)             \
  _(Rely, 16, 23)             \
  _(Rely, 16, 24)             \
  _(Rely, 16, 27)             \
  _(Rely, 17, 21)             \
  _(Rely, 17, 34)             \
  _(Rely, 32, 41)             \
  _(Rely, 32, 46)             \
  _(Rely, 32, 54)             \
  _(Rely, 34, 42)             \
  _(Rely, 35, 70)             \
  _(Rely, 52, 62)

/**
 * @brief Base class to store common fields.
 */
class RelyBase : public virtual FECBase {
 protected:
  static const constexpr size_t kmax_stream_size = 125U;
  static const constexpr size_t kmtu = 1500U;
  static const constexpr size_t ktimeout = 100U;
  /**
   * @brief FEC Header, added to each packet to get sequence number upon
   * decoding operations. It may be removed once we know the meaning of the
   * fields in the rely header.
   */
  class fec_metadata {
   public:
    void setSeqNumberBase(uint32_t suffix) { seq_number = htonl(suffix); }
    uint32_t getSeqNumberBase() const { return ntohl(seq_number); }

    void setMetadataBase(uint32_t value) { metadata = htonl(value); }
    uint32_t getMetadataBase() const { return ntohl(metadata); }

   private:
    uint32_t seq_number;
    uint32_t metadata;
  };

  /**
   * @brief Construct a new Rely Base object.
   *
   * @param k The number of source symbol needed to generate n - k repair
   * symbols
   * @param n The sum of source packets and repair packets in a `block`
   * @param seq_offset offset to use if production suffixes starts from an index
   * != 0
   */
  RelyBase(uint32_t k, uint32_t n, uint32_t seq_offset = 0)
      : k_(k),
        n_(n),
        seq_offset_(seq_offset % n_),
        current_index_(seq_offset)
#if RELY_DEBUG
        ,
        time_(0)
#endif
  {
  }

  /**
   * @brief Get the current time in milliseconds
   *
   * @return int64_t Current time in milliseconds
   */
  int64_t getCurrentTime() {
    // Get the current time
#if RELY_DEBUG
    return time_++;
#else
    return utils::SteadyTime::nowMs().count();
#endif
  }

  uint32_t k_;
  uint32_t n_;

  std::uint32_t seq_offset_;

  /**
   * @brief Vector of packets to be passed to caller callbacks. For encoder it
   * will contain the repair packets, for decoder the recovered sources.
   */
  BufferArray packets_;

  /**
   * @brief Current index to be used for local packet count.
   *
   */
  uint32_t current_index_;
#if RELY_DEBUG
  uint32_t time_;
#endif
};

/**
 * @brief The Rely Encoder implementation.
 *
 */
class RelyEncoder : RelyBase, rely::encoder, public ProducerFEC {
 public:
  RelyEncoder(uint32_t k, uint32_t n, uint32_t seq_offset = 0);
  /**
   * Producers will call this function when they produce a data packet.
   */
  void onPacketProduced(core::ContentObject &content_object, uint32_t offset,
                        uint32_t metadata = FECBase::INVALID_METADATA) override;

  /**
   * @brief Get the fec header size, if added to source packets
   */
  std::size_t getFecHeaderSize() override {
    return header_bytes() + sizeof(fec_metadata) + 4;
  }

  void reset() override {
    // Nothing to do here
  }
};

class RelyDecoder : RelyBase, rely::decoder, public ConsumerFEC {
 public:
  RelyDecoder(uint32_t k, uint32_t n, uint32_t seq_offset = 0);

  /**
   * Consumers will call this function when they receive a data packet
   */
  void onDataPacket(core::ContentObject &content_object, uint32_t offset,
                    uint32_t metadata = FECBase::INVALID_METADATA) override;

  /**
   * @brief Get the fec header size, if added to source packets
   */
  std::size_t getFecHeaderSize() override {
    return header_bytes() + sizeof(fec_metadata);
  }

  void reset() override {
    // Nothing to do here
  }

 private:
  void producePackets();
  void flushOutOfOrder();
};

}  // namespace fec

}  // namespace protocol
}  // namespace transport
