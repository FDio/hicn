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

#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/errors/not_implemented_exception.h>

#include <functional>

namespace transport {
namespace protocol {

namespace fec {

using buffer = utils::MemBuf::Ptr;

class FECBufferInfo {
 public:
  FECBufferInfo()
      : index_(~0), metadata_(~0), received_(false), buffer_(nullptr) {}

  template <typename T>
  FECBufferInfo(uint32_t index, uint32_t metadata, T &&buffer)
      : index_(index),
        metadata_(metadata),
        received_(false),
        buffer_(std::forward<T>(buffer)) {}

  // Getters
  uint32_t getIndex() const { return index_; }

  uint32_t getMetadata() const { return metadata_; }

  bool getReceived() const { return received_; }

  buffer &getBuffer() { return buffer_; }

  // Setters
  void setReceived() { received_ = true; }

  FECBufferInfo &setIndex(uint32_t index) {
    index_ = index;
    return *this;
  }

  FECBufferInfo &setMetadata(uint32_t metadata) {
    metadata_ = metadata;
    return *this;
  }

  FECBufferInfo &setBuffer(buffer &buffer) {
    buffer_ = buffer;
    return *this;
  }

  FECBufferInfo &setBuffer(buffer &&buffer) {
    buffer_ = std::move(buffer);
    return *this;
  }

 private:
  uint32_t index_;
  uint32_t metadata_;
  bool received_;
  buffer buffer_;
};

using BufferArray = typename std::vector<FECBufferInfo>;

class FECBase {
 public:
  static inline uint32_t INVALID_METADATA = ~0;
  static inline uint32_t INVALID_INDEX = ~0;

  virtual ~FECBase() {}
  /**
   * Callback to be called after the encode or the decode operations. In the
   * former case it will contain the symbols, while in the latter the sources.
   */
  using PacketsReady = std::function<void(BufferArray &)>;

  /**
   * Callback to be called when a new buffer (for encoding / decoding) needs to
   * be allocated.
   */
  using BufferRequested = std::function<buffer(std::size_t size)>;

  /**
   * @brief Get size of FEC header.
   */
  virtual std::size_t getFecHeaderSize() = 0;

  /**
   * Set callback to call after packet encoding / decoding
   */
  template <typename Handler>
  void setFECCallback(Handler &&callback) {
    fec_callback_ = std::forward<Handler>(callback);
  }

  /**
   * Set a callback to request a buffer.
   */
  template <typename Handler>
  void setBufferCallback(Handler &&buffer_callback) {
    buffer_callback_ = buffer_callback;
  }

  /**
   * Creates the timer to flush packets. So far needed only if using Rely and
   * want to avoid expired packets blocked by missing pkts to wait for a new
   * packet to arrive and trigger the flush
   */
  void setIOService(asio::io_service &io_service) {
    flush_timer_ = std::make_unique<asio::steady_timer>(io_service);
  }

  virtual void reset() = 0;

 protected:
  PacketsReady fec_callback_{0};
  BufferRequested buffer_callback_{0};
  std::unique_ptr<asio::steady_timer> flush_timer_;
};

/**
 * Interface classes to integrate FEC inside any producer transport protocol
 */
class ProducerFEC : public virtual FECBase {
 public:
  virtual ~ProducerFEC() = default;
  /**
   * Producers will call this function upon production of a new packet.
   */
  virtual void onPacketProduced(
      core::ContentObject &content_object, uint32_t offset,
      uint32_t metadata = FECBase::INVALID_METADATA) = 0;
};

/**
 * Interface classes to integrate FEC inside any consumer transport protocol
 */
class ConsumerFEC : public virtual FECBase {
 public:
  virtual ~ConsumerFEC() = default;

  /**
   * Consumers will call this function when they receive a data packet
   */
  virtual void onDataPacket(core::ContentObject &content_object,
                            uint32_t offset,
                            uint32_t metadata = FECBase::INVALID_METADATA) = 0;
};

}  // namespace fec
}  // namespace protocol
}  // namespace transport
