/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/auth/crypto_suite.h>
#include <hicn/transport/auth/key_id.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/core/payload_type.h>
#include <hicn/transport/errors/malformed_packet_exception.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/membuf.h>
#include <hicn/transport/utils/object_pool.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/packet.h>
}

namespace transport {

namespace auth {
class Signer;
class Verifier;
}  // namespace auth

namespace core {

/*
 * Basic IP packet, modelled as circular chain of buffers:
 * Header = H
 * Payload = P
 *
 * H_0 --> H_1 --> H_2 --> P_0 --> P_1 --> P_2
 *  \_______________________________________|
 */

class Packet : public utils::MemBuf,
               public std::enable_shared_from_this<Packet> {
  friend class auth::Signer;
  friend class auth::Verifier;

 public:
  using Ptr = std::shared_ptr<Packet>;
  using MemBufPtr = std::shared_ptr<utils::MemBuf>;
  using Format = hicn_packet_format_t;
  using Type = hicn_packet_type_t;

  static constexpr size_t default_mtu = 1500;

  /**
   * Create new IP packet. Here we allocate just the header,
   * the eventual payload will be added by prepending the payload buffer
   * to the buffer chain whose the fist buffer is the header itself.
   */
  Packet(Type type, Format format, std::size_t additional_header_size = 0);
  /* Copy buffer */
  Packet(CopyBufferOp, const uint8_t *buffer, std::size_t size);
  /* Wrap buffer */
  Packet(WrapBufferOp, uint8_t *buffer, std::size_t length, std::size_t size);
  /* Create new using pre-allocated buffer */
  Packet(CreateOp, Type type, uint8_t *buffer, std::size_t length,
         std::size_t size, Format format,
         std::size_t additional_header_size = 0);

  Packet(MemBuf &&buffer);
  Packet(Packet &&other);
  Packet(const Packet &other);

  // Destructor
  virtual ~Packet();

  // Operators
  Packet &operator=(const Packet &other);
  friend bool operator==(const Packet &l_packet, const Packet &r_packet);

  // Cast to MemBuf
  std::shared_ptr<utils::MemBuf> acquireMemBufReference();

  // Format
  Format getFormat() const;
  void setFormat(Packet::Format format);

  void initialize(std::size_t additional_header_size = 0);
  void analyze();

  hicn_packet_type_t getType() const;
  void setType(Packet::Type type);

  void setBuffer();

  // Name
  virtual const Name &getName() const = 0;
  virtual Name &getWritableName() = 0;
  virtual void setName(const Name &name) = 0;

  // Lifetime
  virtual void setLifetime(uint32_t lifetime) = 0;
  virtual uint32_t getLifetime() const = 0;

  // Locator
  virtual void setLocator(const hicn_ip_address_t &locator) = 0;
  virtual hicn_ip_address_t getLocator() const = 0;

  // Payload type
  PayloadType getPayloadType() const;
  Packet &setPayloadType(PayloadType payload_type);

  // Payload
  std::unique_ptr<utils::MemBuf> getPayload() const;
  Packet &appendPayload(std::unique_ptr<utils::MemBuf> &&payload);
  Packet &appendPayload(const uint8_t *buffer, std::size_t length);

  // Sizes
  std::size_t headerSize() const;
  std::size_t payloadSize() const;

  // Digest
  auth::CryptoHash computeDigest(auth::CryptoHashType algorithm) const;

  bool isInterest();

  // Reset packet
  void reset();

  // Utils
  Packet &updateLength(std::size_t length = 0);
  void dump() const;

  // TCP methods
  void setChecksum();
  bool checkIntegrity() const;
  Packet &setSrcPort(uint16_t srcPort);
  Packet &setDstPort(uint16_t dstPort);
  uint16_t getSrcPort() const;
  uint16_t getDstPort() const;
  Packet &setTTL(uint8_t hops);
  uint8_t getTTL() const;

  // Authentication Header methods
  bool hasAH() const;
  utils::MemBuf::Ptr getSignature() const;
  std::size_t getSignatureFieldSize() const;
  std::size_t getSignatureSize() const;
  uint64_t getSignatureTimestamp() const;
  auth::KeyId getKeyId() const;
  auth::CryptoSuite getValidationAlgorithm() const;
  void setSignature(const utils::MemBuf::Ptr &signature);
  void setSignatureFieldSize(std::size_t size);
  void setSignatureSize(std::size_t size);
  void setSignatureTimestamp(const uint64_t &timestamp_ms);
  void setKeyId(const auth::KeyId &key_id);
  void setValidationAlgorithm(const auth::CryptoSuite &algo);

  void saveHeader(u8 *header, size_t *header_len);
  void loadHeader(u8 *header, size_t header_len);

  // Static methods
  static Format toAHFormat(const Format &format);
  static Format getFormatFromBuffer(const uint8_t *buffer, std::size_t length);
  static std::size_t getHeaderSizeFromFormat(Format format,
                                             std::size_t signature_size = 0);
  static std::size_t getHeaderSizeFromBuffer(const uint8_t *buffer,
                                             size_t length);
  static std::size_t getPayloadSizeFromBuffer(const uint8_t *buffer,
                                              size_t length);
  static void dump(uint8_t *buffer, std::size_t length);

 private:
  virtual void resetForHash() = 0;
  void prependPayload(const uint8_t **buffer, std::size_t *size);

 protected:
  hicn_packet_buffer_t pkbuf_;
  Name name_;
  mutable PayloadType payload_type_;
  static const core::Name base_name;
};

}  // end namespace core

}  // end namespace transport
