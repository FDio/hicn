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

#include <hicn/transport/core/name.h>
#include <hicn/transport/core/payload_type.h>
#include <hicn/transport/errors/malformed_packet_exception.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/security/crypto_hasher.h>
#include <hicn/transport/security/crypto_suite.h>
#include <hicn/transport/security/key_id.h>
#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/membuf.h>
#include <hicn/transport/utils/object_pool.h>

namespace utils {
class Signer;
class Verifier;
}  // namespace utils

namespace transport {

namespace core {

/*
 * Basic IP packet, modelled as circular chain of buffers:
 * Header = H
 * Payload = P
 *
 * H_0 --> H_1 --> H_2 --> P_0 --> P_1 --> P_2
 *  \_______________________________________|
 */

class Packet : public std::enable_shared_from_this<Packet> {
  friend class utils::Signer;
  friend class utils::Verifier;

 public:
  using MemBufPtr = std::shared_ptr<utils::MemBuf>;
  using Format = hicn_format_t;
  static constexpr size_t default_mtu = 1500;

  /**
   * Create new IP packet. Here we allocate just the header,
   * the eventual payload will be added by prepending the payload buffer
   * to the buffer chain whose the fist buffer is the header itself.
   */
  Packet(Format format = HF_UNSPEC);

  /**
   * Create new IP packet using raw buffer.
   */
  Packet(const uint8_t *buffer, std::size_t size);
  Packet(MemBufPtr &&buffer);

  /*
   * Enforce zero-copy lifestyle.
   */
  Packet(const Packet &other) = delete;
  Packet &operator=(const Packet &other) = delete;

  /*
   * Move constructor.
   */
  Packet(Packet &&other);

  friend bool operator==(const Packet &l_packet, const Packet &r_packet);

  virtual ~Packet();

  static std::size_t getHeaderSizeFromFormat(Format format,
                                             std::size_t signature_size = 0) {
    std::size_t header_length;
    hicn_packet_get_header_length_from_format(format, &header_length);
    int is_ah = _is_ah(format);
    return is_ah * (header_length + signature_size) + (!is_ah) * header_length;
  }

  static std::size_t getHeaderSizeFromBuffer(Format format,
                                             const uint8_t *buffer);

  static std::size_t getPayloadSizeFromBuffer(Format format,
                                              const uint8_t *buffer);

  static bool isInterest(const uint8_t *buffer);

  static Format getFormatFromBuffer(const uint8_t *buffer) {
    Format format = HF_UNSPEC;

    if (TRANSPORT_EXPECT_FALSE(
            hicn_packet_get_format((const hicn_header_t *)buffer, &format) <
            0)) {
      throw errors::MalformedPacketException();
    }

    return format;
  }

  TRANSPORT_ALWAYS_INLINE void replace(MemBufPtr &&buffer) {
    packet_ = std::move(buffer);
    packet_start_ = reinterpret_cast<hicn_header_t *>(packet_->writableData());
    header_head_ = packet_.get();
    payload_head_ = nullptr;
    format_ = getFormatFromBuffer(reinterpret_cast<uint8_t *>(packet_start_));
    name_.clear();
  }

  std::size_t payloadSize() const;

  std::size_t headerSize() const;

  const std::shared_ptr<utils::MemBuf> acquireMemBufReference() const;

  virtual const Name &getName() const = 0;

  virtual Name &getWritableName() = 0;

  virtual void setName(const Name &name) = 0;

  virtual void setName(Name &&name) = 0;

  virtual void setLifetime(uint32_t lifetime) = 0;

  virtual uint32_t getLifetime() const = 0;

  Packet &appendPayload(const uint8_t *buffer, std::size_t length);

  Packet &appendPayload(std::unique_ptr<utils::MemBuf> &&payload);

  Packet &appendHeader(std::unique_ptr<utils::MemBuf> &&header);

  Packet &appendHeader(const uint8_t *buffer, std::size_t length);

  std::unique_ptr<utils::MemBuf> getPayload() const;

  std::pair<const uint8_t *, std::size_t> getPayloadReference() const {
    int signature_size = 0;
    if (_is_ah(format_)) {
      signature_size = (uint32_t)getSignatureSize();
    }

    auto header_size = getHeaderSizeFromFormat(format_, signature_size);
    auto payload_length = packet_->length() - header_size;

    return std::make_pair(packet_->data() + header_size,
                          payload_length);
  }

  Packet &updateLength(std::size_t length = 0);

  PayloadType getPayloadType() const;

  Packet &setPayloadType(PayloadType payload_type);

  Format getFormat() const;

  void dump() const;

  virtual void setLocator(const ip_address_t &locator) = 0;

  virtual ip_address_t getLocator() const = 0;

  void setSignatureTimestamp(const uint64_t &timestamp);

  uint64_t getSignatureTimestamp() const;

  void setValidationAlgorithm(const utils::CryptoSuite &validation_algorithm);

  utils::CryptoSuite getValidationAlgorithm() const;

  void setKeyId(const utils::KeyId &key_id);

  utils::KeyId getKeyId() const;

  virtual utils::CryptoHash computeDigest(
      utils::CryptoHashType algorithm) const;

  void setChecksum() {
    uint16_t partial_csum = 0;

    for (utils::MemBuf *current = header_head_->next();
         current && current != header_head_; current = current->next()) {
      if (partial_csum != 0) {
        partial_csum = ~partial_csum;
      }
      partial_csum = csum(current->data(), current->length(), partial_csum);
    }
    if (hicn_packet_compute_header_checksum(format_, packet_start_,
                                            partial_csum) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  bool checkIntegrity() const;

  Packet &setSyn();
  Packet &resetSyn();
  bool testSyn() const;
  Packet &setAck();
  Packet &resetAck();
  bool testAck() const;
  Packet &setRst();
  Packet &resetRst();
  bool testRst() const;
  Packet &setFin();
  Packet &resetFin();
  bool testFin() const;
  Packet &resetFlags();
  std::string printFlags() const;

  Packet &setSrcPort(uint16_t srcPort);
  Packet &setDstPort(uint16_t dstPort);
  uint16_t getSrcPort() const;
  uint16_t getDstPort() const;

  Packet &setTTL(uint8_t hops);
  uint8_t getTTL() const;

  void resetPayload();

 private:
  virtual void resetForHash() = 0;
  void setSignatureSize(std::size_t size_bytes);

  std::size_t getSignatureSize() const {
    size_t size_bytes;
    int ret =
        hicn_packet_get_signature_size(format_, packet_start_, &size_bytes);

    if (ret < 0) {
      throw errors::RuntimeException("Packet without Authentication Header.");
    }

    return size_bytes;
  }

  uint8_t *getSignature() const;
  void separateHeaderPayload();

 protected:
  Name name_;
  MemBufPtr packet_;
  hicn_header_t *packet_start_;
  utils::MemBuf *header_head_;
  utils::MemBuf *payload_head_;
  mutable Format format_;

  static const core::Name base_name;
};

}  // end namespace core

}  // end namespace transport
