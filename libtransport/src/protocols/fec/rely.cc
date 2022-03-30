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

#include <glog/logging.h>
#include <hicn/transport/core/global_object_pool.h>
#include <protocols/fec/rely.h>

#include <rely/packet.hpp>

namespace transport {
namespace protocol {
namespace fec {

RelyEncoder::RelyEncoder(uint32_t k, uint32_t n, uint32_t /* seq_offset */)
    : RelyBase(k, n) {
  configure(kmtu, ktimeout, kmax_stream_size);
  set_repair_trigger(k_, n_ - k_, n_ - k_);
}

void RelyEncoder::onPacketProduced(core::ContentObject &content_object,
                                   uint32_t offset, uint32_t metadata) {
  // Get pointer to payload, leaving space to insert FEC header.
  // TODO Check if this additional header is really needed.
  auto data = content_object.writableData() + offset - sizeof(fec_metadata);
  auto length = content_object.length() - offset + sizeof(fec_metadata);

  // Check packet length does not exceed maximum length supported by the
  // encoder (otherwise segmentation would take place).
  DCHECK(length < max_packet_bytes());
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Encoding packet of length " << length - sizeof(fec_metadata);

  // Get the suffix. With rely we need to write it in the fec_metadata in order
  // to be able to recognize the seq number upon recovery.
  auto suffix = content_object.getName().getSuffix();
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "Producing packet " << suffix
                               << " (index == " << current_index_ << ")";

  // Consume payload. Add fec_metadata in front before feeding payload to
  // encoder, and copy original content of packet
  fec_metadata *h = reinterpret_cast<fec_metadata *>(data);
  fec_metadata copy = *h;
  h->setSeqNumberBase(suffix);
  h->setMetadataBase(metadata);
  auto packets = consume(data, length, getCurrentTime());
  DCHECK(packets == 1);

  // Update packet counter
  current_index_ += packets;

  // Restore original packet content and increment data pointer to the correct
  // position
  *h = copy;
  data += sizeof(fec_metadata);

  // Check position of this packet inside N size block
  auto i = current_index_ % n_;

  // encoder will produce a source packet
  if (i <= k_) {
    // Rely modifies the payload of the packet. We replace the packet with the
    // one returned by rely.
    // TODO Optimize it by copying only the RELY header

    // Be sure encoder can produce
    DCHECK(can_produce());

    // Check new payload size and make sure it fits in packet buffer
    auto new_payload_size = produce_bytes();
    int difference = new_payload_size - length;

    DCHECK(difference > 0);
    DCHECK(content_object.ensureCapacity(difference));

    // Update length
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "The packet length will be incremented by "
                                 << difference + sizeof(fec_metadata);
    content_object.append(difference + sizeof(fec_metadata));
    content_object.updateLength();

    // Make sure we got a source packet, otherwise we would put a repair symbol
    // in a source packet
    DCHECK(rely::packet_is_systematic(produce_data()));

    // Copy rely packet replacing old source packet.
    std::memcpy(data, produce_data(), new_payload_size);

    // Advance the encoder to next symbol.
    produce_next();
  }

#if 0
  if (i == k_) {
    // Ensure repair are generated after k source packets
    flush_repair();
  }
#endif

  // Here we should produce all the repair packets
  while (can_produce()) {
    // The current index MUST be k_, because we enforce n - k repair to be
    // produced after k sources
    DCHECK(current_index_ == k_);

    buffer packet;
    if (!buffer_callback_) {
      // If no callback is installed, let's allocate a buffer from global pool
      packet = core::PacketManager<>::getInstance().getMemBuf();
      packet->append(produce_bytes());
    } else {
      // Otherwise let's ask a buffer to the caller.
      packet = buffer_callback_(produce_bytes());
    }

    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "Producing symbol of size " << produce_bytes();

    // Copy symbol to packet buffer
    std::memcpy(packet->writableData(), produce_data(), produce_bytes());

    // Push symbol in repair_packets
    packets_.emplace_back(0, metadata, std::move(packet));

    // Advance the encoder
    produce_next();
  }

  // Print number of unprotected symbols
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Number of unprotected symbols: " << unprotected_symbols();

  // If we have generated repair symbols, let's notify caller via the installed
  // callback
  if (packets_.size()) {
    DCHECK(packets_.size() == n_ - k_);
    fec_callback_(packets_);
    packets_.clear();
    current_index_ = 0;
  }
}

RelyDecoder::RelyDecoder(uint32_t k, uint32_t n, uint32_t seq_offset)
    : RelyBase(k, n, seq_offset) {
  configure(kmtu, ktimeout, kmax_stream_size);
}

void RelyDecoder::onDataPacket(core::ContentObject &content_object,
                               uint32_t offset, uint32_t metadata) {
  // Adjust pointers to point to packet payload
  auto data = content_object.writableData() + offset;
  auto size = content_object.length() - offset;

  // Pass payload to decoder
  consume(data, size, getCurrentTime());

  producePackets();
}

void RelyDecoder::producePackets() {
  // Drain decoder if possible
  while (can_produce()) {
    auto fec_header_size = sizeof(fec_metadata);
    auto payload_size = produce_bytes() - sizeof(fec_metadata);

    buffer packet;
    if (!buffer_callback_) {
      packet = core::PacketManager<>::getInstance().getMemBuf();
      packet->append(payload_size);
    } else {
      packet = buffer_callback_(payload_size);
    }

    // Read seq number
    const fec_metadata *h =
        reinterpret_cast<const fec_metadata *>(produce_data());
    uint32_t index = h->getSeqNumberBase();
    uint32_t metadata = h->getMetadataBase();

    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "The index written in the packet is " << index;

    // Copy payload
    std::memcpy(packet->writableData(), produce_data() + fec_header_size,
                payload_size);

    // Save packet in buffer
    packets_.emplace_back(index, metadata, std::move(packet));

    // Advance to next packet
    produce_next();
  }

  // If we produced packets, lets notify the caller via the callback
  if (packets_.size() > 0) {
    fec_callback_(packets_);
    packets_.clear();
  }

  flushOutOfOrder();
}

void RelyDecoder::flushOutOfOrder() {
  if (flush_timer_ == nullptr) return;
  flush_timer_->cancel();

  if (has_upcoming_flush()) {
    flush_timer_->expires_from_now(std::chrono::milliseconds(
        std::max((int64_t)0, upcoming_flush(getCurrentTime()))));

    flush_timer_->async_wait([this](const std::error_code &ec) {
      if (ec) return;
      if (has_upcoming_flush()) {
        flush(getCurrentTime());
        producePackets();
      }
    });
  }
}

}  // namespace fec
}  // namespace protocol
}  // namespace transport
