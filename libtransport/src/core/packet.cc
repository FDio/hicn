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

#include <glog/logging.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/errors/malformed_packet_exception.h>
#include <hicn/transport/utils/hash.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/base.h>
#include <hicn/error.h>
}

namespace transport {

namespace core {

const core::Name Packet::base_name("0::0|0");

Packet::Packet(Type type, Format format, std::size_t additional_header_size)
    : utils::MemBuf(utils::MemBuf(CREATE, 2048)),
      payload_type_(PayloadType::UNSPECIFIED) {
  /*
   * We define the format and the storage area of the packet buffer we
   * manipulate
   */
  setType(type);
  setFormat(format);
  setBuffer();
  initialize(additional_header_size);
}

Packet::Packet(CopyBufferOp, const uint8_t *buffer, std::size_t size)
    : utils::MemBuf(COPY_BUFFER, buffer, size),
      payload_type_(PayloadType::UNSPECIFIED) {
  setBuffer();
  analyze();
}

Packet::Packet(WrapBufferOp, uint8_t *buffer, std::size_t length,
               std::size_t size)
    : utils::MemBuf(WRAP_BUFFER, buffer, length, size),
      payload_type_(PayloadType::UNSPECIFIED) {
  setBuffer();
  analyze();
}

Packet::Packet(CreateOp, Type type, uint8_t *buffer, std::size_t length,
               std::size_t size, Format format,
               std::size_t additional_header_size)
    : utils::MemBuf(WRAP_BUFFER, buffer, length, size),
      payload_type_(PayloadType::UNSPECIFIED) {
  clear();
  setType(type);
  setFormat(format);
  setBuffer();
  initialize(additional_header_size);
}

Packet::Packet(MemBuf &&buffer)
    : utils::MemBuf(std::move(buffer)),
      payload_type_(PayloadType::UNSPECIFIED) {
  setBuffer();
  analyze();
}

/*
 * In the two following constructors, we inherit the pkbuf and only need to
 * recompute the pointer fields, aka the buffer.
 */

Packet::Packet(Packet &&other)
    : utils::MemBuf(std::move(other)),
      pkbuf_(other.pkbuf_),
      payload_type_(PayloadType::UNSPECIFIED) {
  hicn_packet_reset(&other.pkbuf_);
}

Packet::Packet(const Packet &other)
    : utils::MemBuf(other),
      pkbuf_(other.pkbuf_),
      payload_type_(PayloadType::UNSPECIFIED) {
  setBuffer();
}

Packet::~Packet() {}

Packet &Packet::operator=(const Packet &other) {
  if (this != &other) {
    *this = other;
    setBuffer();
  }

  return *this;
}

std::shared_ptr<utils::MemBuf> Packet::acquireMemBufReference() {
  return std::static_pointer_cast<utils::MemBuf>(shared_from_this());
}

Packet::Format Packet::getFormat() const {
  return hicn_packet_get_format(&pkbuf_);
}

void Packet::setFormat(Packet::Format format) {
  hicn_packet_set_format(&pkbuf_, format);
}

void Packet::initialize(std::size_t additional_header_size) {
  if (hicn_packet_init_header(&pkbuf_, additional_header_size) < 0) {
    throw errors::RuntimeException("Unexpected error initializing the packet.");
  }

  auto header_size = getHeaderSizeFromFormat(getFormat());
  DCHECK(header_size <= tailroom());
  append(header_size);
  DCHECK(additional_header_size <= tailroom());
  append(additional_header_size);
}

void Packet::analyze() {
  if (hicn_packet_analyze(&pkbuf_) < 0)
    throw errors::MalformedPacketException();
}

Packet::Type Packet::getType() const { return hicn_packet_get_type(&pkbuf_); }

void Packet::setType(Packet::Type type) { hicn_packet_set_type(&pkbuf_, type); }

void Packet::setBuffer() {
  hicn_packet_set_buffer(&pkbuf_, writableData(),
                         this->capacity() - this->headroom(), this->length());
}

PayloadType Packet::getPayloadType() const {
  if (payload_type_ == PayloadType::UNSPECIFIED) {
    hicn_payload_type_t ret;

    if (hicn_packet_get_payload_type(&pkbuf_, &ret) < 0) {
      throw errors::RuntimeException("Impossible to retrieve payload type.");
    }

    payload_type_ = (PayloadType)ret;
  }

  return payload_type_;
}

Packet &Packet::setPayloadType(PayloadType payload_type) {
  if (hicn_packet_set_payload_type(&pkbuf_, hicn_payload_type_t(payload_type)) <
      0) {
    throw errors::RuntimeException("Error setting payload type of the packet.");
  }

  payload_type_ = payload_type;
  return *this;
}

std::unique_ptr<utils::MemBuf> Packet::getPayload() const {
  auto ret = clone();
  ret->trimStart(headerSize());
  return ret;
}

Packet &Packet::appendPayload(std::unique_ptr<utils::MemBuf> &&payload) {
  prependChain(std::move(payload));
  updateLength();
  return *this;
}

Packet &Packet::appendPayload(const uint8_t *buffer, std::size_t length) {
  prependPayload(&buffer, &length);

  if (length) {
    appendPayload(utils::MemBuf::copyBuffer(buffer, length));
  }

  updateLength();
  return *this;
}

std::size_t Packet::headerSize() const {
  std::size_t len;
  hicn_packet_get_header_len(&pkbuf_, &len);
  return len;
}

std::size_t Packet::payloadSize() const {
  std::size_t len;
  hicn_packet_get_payload_len(&pkbuf_, &len);
  return len;
}

auth::CryptoHash Packet::computeDigest(auth::CryptoHashType algorithm) const {
  auth::CryptoHash hash;
  hash.setType(algorithm);

  // Copy IP+TCP/ICMP header before zeroing them
  u8 header_copy[HICN_HDRLEN_MAX];
  size_t header_len;
  hicn_packet_save_header(&pkbuf_, header_copy, &header_len,
                          /* copy_ah */ false);
  const_cast<Packet *>(this)->resetForHash();

  hash.computeDigest(this);
  hicn_packet_load_header(&pkbuf_, header_copy, header_len);

  return hash;
}

void Packet::reset() {
  clear();
  hicn_packet_reset(&pkbuf_);
  setBuffer();
  payload_type_ = PayloadType::UNSPECIFIED;
  name_.clear();

  if (isChained()) {
    separateChain(next(), prev());
  }
}

bool Packet::isInterest() {
  return hicn_packet_get_type(&pkbuf_) == HICN_PACKET_TYPE_INTEREST;
}

Packet &Packet::updateLength(std::size_t length) {
  std::size_t total_length = length;

  const utils::MemBuf *current = this;
  do {
    total_length += current->length();
    current = current->next();
  } while (current != this);

  if (hicn_packet_set_len(&pkbuf_, total_length) < 0) {
    throw errors::RuntimeException("Error setting the packet length.");
  }

  total_length -= headerSize();

  if (hicn_packet_set_payload_length(&pkbuf_, total_length) < 0) {
    throw errors::RuntimeException("Error setting the packet payload length.");
  }

  return *this;
}

void Packet::dump() const {
  LOG(INFO) << "HEADER -- Length: " << headerSize();
  LOG(INFO) << "PAYLOAD -- Length: " << payloadSize();

  const utils::MemBuf *current = this;
  do {
    LOG(INFO) << "MemBuf Length: " << current->length();
    dump((uint8_t *)current->data(), current->length());
    current = current->next();
  } while (current != this);
}

void Packet::setChecksum() {
  size_t header_len = 0;
  if (hicn_packet_get_header_len(&pkbuf_, &header_len) < 0)
    throw errors::RuntimeException(
        "Error setting getting packet header length.");

  uint16_t partial_csum = csum(data() + header_len, length() - header_len, 0);

  for (utils::MemBuf *current = next(); current != this;
       current = current->next()) {
    partial_csum = csum(current->data(), current->length(), ~partial_csum);
  }

  if (hicn_packet_compute_header_checksum(&pkbuf_, partial_csum) < 0) {
    throw errors::MalformedPacketException();
  }
}

bool Packet::checkIntegrity() const {
  size_t header_len = 0;
  if (hicn_packet_get_header_len(&pkbuf_, &header_len) < 0)
    throw errors::RuntimeException(
        "Error setting getting packet header length.");

  uint16_t partial_csum = csum(data() + header_len, length() - header_len, 0);

  for (const utils::MemBuf *current = next(); current != this;
       current = current->next()) {
    partial_csum = csum(current->data(), current->length(), ~partial_csum);
  }

  if (hicn_packet_check_integrity_no_payload(&pkbuf_, partial_csum) < 0) {
    return false;
  }

  return true;
}

Packet &Packet::setSrcPort(uint16_t srcPort) {
  if (hicn_packet_set_src_port(&pkbuf_, srcPort) < 0) {
    throw errors::RuntimeException("Error setting source port in the packet.");
  }

  return *this;
}

Packet &Packet::setDstPort(uint16_t dstPort) {
  if (hicn_packet_set_dst_port(&pkbuf_, dstPort) < 0) {
    throw errors::RuntimeException(
        "Error setting destination port in the packet.");
  }

  return *this;
}

uint16_t Packet::getSrcPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_src_port(&pkbuf_, &port) < 0) {
    throw errors::RuntimeException("Error reading source port in the packet.");
  }

  return port;
}

uint16_t Packet::getDstPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_dst_port(&pkbuf_, &port) < 0) {
    throw errors::RuntimeException(
        "Error reading destination port in the packet.");
  }

  return port;
}

Packet &Packet::setTTL(uint8_t hops) {
  if (hicn_packet_set_ttl(&pkbuf_, hops) < 0) {
    throw errors::RuntimeException("Error setting TTL.");
  }

  return *this;
}

uint8_t Packet::getTTL() const {
  uint8_t hops = 0;
  if (hicn_packet_get_ttl(&pkbuf_, &hops) < 0) {
    throw errors::RuntimeException("Error reading TTL.");
  }

  return hops;
}

bool Packet::hasAH() const { return _is_ah(hicn_packet_get_format(&pkbuf_)); }

utils::MemBuf::Ptr Packet::getSignature() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint8_t *signature;
  int ret = hicn_packet_get_signature(&pkbuf_, &signature);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting signature.");
  }

  utils::MemBuf::Ptr membuf = PacketManager<>::getInstance().getMemBuf();
  membuf->append(getSignatureFieldSize());
  memcpy(membuf->writableData(), signature, getSignatureFieldSize());

  return membuf;
}

std::size_t Packet::getSignatureFieldSize() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  size_t field_size;
  int ret = hicn_packet_get_signature_size(&pkbuf_, &field_size);
  if (ret < 0) {
    throw errors::RuntimeException("Error reading signature field size");
  }
  return field_size;
}

std::size_t Packet::getSignatureSize() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  size_t padding;
  int ret = hicn_packet_get_signature_padding(&pkbuf_, &padding);
  if (ret < 0) {
    throw errors::RuntimeException("Error reading signature padding");
  }

  size_t size = getSignatureFieldSize() - padding;
  if (size < 0) {
    throw errors::RuntimeException("Error reading signature size");
  }

  return size;
}

uint64_t Packet::getSignatureTimestamp() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint64_t timestamp;
  int ret = hicn_packet_get_signature_timestamp(&pkbuf_, &timestamp);
  if (ret < 0) {
    throw errors::RuntimeException("Error getting the signature timestamp.");
  }
  return timestamp;
}

auth::KeyId Packet::getKeyId() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  auth::KeyId key_id;
  int ret = hicn_packet_get_key_id(&pkbuf_, &key_id.first, &key_id.second);
  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }
  return key_id;
}

auth::CryptoSuite Packet::getValidationAlgorithm() const {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint8_t return_value;
  int ret = hicn_packet_get_validation_algorithm(&pkbuf_, &return_value);
  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }
  return auth::CryptoSuite(return_value);
}

void Packet::setSignature(const utils::MemBuf::Ptr &signature) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint8_t *signature_field;
  int ret = hicn_packet_get_signature(&pkbuf_, &signature_field);
  if (ret < 0) {
    throw errors::RuntimeException("Error getting signature.");
  }
  memcpy(signature_field, signature->data(), signature->length());
}

void Packet::setSignatureFieldSize(std::size_t size) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_signature_size(&pkbuf_, size);
  if (ret < 0) {
    throw errors::RuntimeException("Error setting signature size.");
  }
}

void Packet::setSignatureSize(std::size_t size) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  size_t padding = getSignatureFieldSize() - size;
  if (padding < 0) {
    throw errors::RuntimeException("Error setting signature padding.");
  }

  int ret = hicn_packet_set_signature_padding(&pkbuf_, padding);
  if (ret < 0) {
    throw errors::RuntimeException("Error setting signature padding.");
  }
}

void Packet::setSignatureTimestamp(const uint64_t &timestamp) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_signature_timestamp(&pkbuf_, timestamp);
  if (ret < 0) {
    throw errors::RuntimeException("Error setting the signature timestamp.");
  }
}

void Packet::setKeyId(const auth::KeyId &key_id) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_key_id(&pkbuf_, key_id.first, key_id.second);
  if (ret < 0) {
    throw errors::RuntimeException("Error setting the key id.");
  }
}

void Packet::setValidationAlgorithm(
    const auth::CryptoSuite &validation_algorithm) {
  if (!hasAH()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_validation_algorithm(&pkbuf_,
                                                 uint8_t(validation_algorithm));
  if (ret < 0) {
    throw errors::RuntimeException("Error setting the validation algorithm.");
  }
}

Packet::Format Packet::toAHFormat(const Format &format) {
  return hicn_get_ah_format(format);
}

Packet::Format Packet::getFormatFromBuffer(const uint8_t *buffer,
                                           std::size_t length) {
  hicn_packet_buffer_t pkbuf;
  /* un-const to be able to use pkbuf API */
  hicn_packet_set_buffer(&pkbuf, (uint8_t *)buffer, length, length);
  if (hicn_packet_analyze(&pkbuf) < 0) throw errors::MalformedPacketException();

  return hicn_packet_get_format(&pkbuf);
}

std::size_t Packet::getHeaderSizeFromFormat(Format format,
                                            std::size_t signature_size) {
  std::size_t header_length;
  hicn_packet_get_header_length_from_format(format, &header_length);
  int is_ah = _is_ah(format);
  return is_ah * (header_length + signature_size) + (!is_ah) * header_length;
}

std::size_t Packet::getHeaderSizeFromBuffer(const uint8_t *buffer,
                                            std::size_t length) {
  size_t header_length;

  hicn_packet_buffer_t pkbuf;
  /* un-const to be able to use pkbuf API */
  hicn_packet_set_buffer(&pkbuf, (uint8_t *)buffer, length, length);
  if (hicn_packet_analyze(&pkbuf) < 0) throw errors::MalformedPacketException();

  int rc = hicn_packet_get_header_len(&pkbuf, &header_length);
  if (TRANSPORT_EXPECT_FALSE(rc < 0)) throw errors::MalformedPacketException();

  return header_length;
}

std::size_t Packet::getPayloadSizeFromBuffer(const uint8_t *buffer,
                                             std::size_t length) {
  std::size_t payload_length;

  hicn_packet_buffer_t pkbuf;
  /* un-const to be able to use pkbuf API */
  hicn_packet_set_buffer(&pkbuf, (uint8_t *)buffer, length, length);
  if (hicn_packet_analyze(&pkbuf) < 0) throw errors::MalformedPacketException();

  int rc = hicn_packet_get_payload_len(&pkbuf, &payload_length);
  if (TRANSPORT_EXPECT_FALSE(rc < 0)) throw errors::MalformedPacketException();

  return payload_length;
}

void Packet::dump(uint8_t *buffer, std::size_t length) {
  hicn_packet_dump(buffer, length);
}

void Packet::prependPayload(const uint8_t **buffer, std::size_t *size) {
  auto last = prev();
  auto to_copy = std::min(*size, last->tailroom());
  std::memcpy(last->writableTail(), *buffer, to_copy);
  last->append(to_copy);
  *size -= to_copy;
  *buffer += to_copy;
}

void Packet::saveHeader(u8 *header, size_t *header_len) {
  hicn_packet_save_header(&pkbuf_, header, header_len, /* copy_ah */ false);
}

void Packet::loadHeader(u8 *header, size_t header_len) {
  hicn_packet_load_header(&pkbuf_, header, header_len);
}

}  // end namespace core

}  // end namespace transport
