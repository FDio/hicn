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

RelyEncoder::RelyEncoder(uint32_t k, uint32_t n, uint32_t seq_offset)
    : RelyBase(k, n) {
  configure(kmtu, ktimeout, kmax_stream_size);
  set_repair_trigger(k_, n_ - k_, n_ - k_);
}

void RelyEncoder::onPacketProduced(core::ContentObject &content_object,
                                   uint32_t offset) {
  // Get pointer to payload, leaving space to insert FEC header.
  // TODO Check if this additional header is really needed.
  auto data = content_object.writableData() + offset - sizeof(fec_header);
  auto length = content_object.length() - offset + sizeof(fec_header);

  // Check packet length does not exceed maximum length supported by the
  // encoder (otherwise segmentation would take place).
  assert(length < max_packet_bytes());
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Encoding packet of length " << length - sizeof(fec_header);

  // Get the suffix. With rely we need to write it in the fec_header in order to
  // be able to recognize the seq number upon recovery.
  auto suffix = content_object.getName().getSuffix();
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "Producing packet " << suffix
                               << " (index == " << current_index_ << ")";

  // Consume payload. Add fec_header in front before feeding payload to encoder,
  // and copy original content of packet
  fec_header *h = reinterpret_cast<fec_header *>(data);
  fec_header copy = *h;
  h->setSeqNumberBase(suffix);
  auto packets = consume(data, length, getCurrentTime());
  assert(packets == 1);

  // Update packet counter
  current_index_ += packets;

  // Restore original packet content and increment data pointer to the correct
  // position
  *h = copy;
  data += sizeof(fec_header);

  // Check position of this packet inside N size block
  auto i = current_index_ % n_;

  // encoder will produce a source packet
  if (i <= k_) {
    // Rely modifies the payload of the packet. We replace the packet with the
    // one returned by rely.
    // TODO Optimize it by copying only the RELY header

    // Be sure encoder can produce
    assert(can_produce());

    // Check new payload size and make sure it fits in packet buffer
    auto new_payload_size = produce_bytes();
    int difference = new_payload_size - length;

    assert(difference > 0);
    assert(content_object.ensureCapacity(difference));

    // Update length
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "The packet length will be incremented by "
                                 << difference + sizeof(fec_header);
    content_object.append(difference + sizeof(fec_header));
    content_object.updateLength();

    // Make sure we got a source packet, otherwise we would put a repair symbol
    // in a source packet
    assert(rely::packet_is_systematic(produce_data()));

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
    assert(current_index_ == k_);

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
    packets_.emplace_back(0, std::move(packet));

    // Advance the encoder
    produce_next();
  }

  // Print number of unprotected symbols
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Number of unprotected symbols: " << unprotected_symbols();

  // If we have generated repair symbols, let's notify caller via the installed
  // callback
  if (packets_.size()) {
    assert(packets_.size() == n_ - k_);
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
                               uint32_t offset) {
  // Adjust pointers to point to packet payload
  auto data = content_object.writableData() + offset;
  auto size = content_object.length() - offset;

  // Pass payload to decoder
  consume(data, size, getCurrentTime());

  // Drain decoder if possible
  while (can_produce()) {
    // Get size of decoded packet
    auto size = produce_bytes();

    // Get buffer to copy packet in
    auto packet = core::PacketManager<>::getInstance().getMemBuf();

    // Copy buffer
    packet->append(size);
    std::memcpy(packet->writableData(), produce_data(), size);

    // Read seq number
    fec_header *h = reinterpret_cast<fec_header *>(packet->writableData());
    uint32_t index = h->getSeqNumberBase();

    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "The index written in the packet is " << index;

    // Remove FEC header
    packet->trimStart(sizeof(fec_header));

    // Save packet in buffer
    packets_.emplace_back(index, std::move(packet));

    // Advance to next packet
    produce_next();
  }

  // If we produced packets, lets notify the caller via the callback
  if (packets_.size() > 0) {
    fec_callback_(packets_);
    packets_.clear();
  }
}

}  // namespace fec
}  // namespace protocol
}  // namespace transport