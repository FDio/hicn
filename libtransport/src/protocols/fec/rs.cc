
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
#include <protocols/fec/fec.h>
#include <protocols/fec/rs.h>

#include <cassert>

namespace transport {
namespace protocol {
namespace fec {

BlockCode::BlockCode(uint32_t k, uint32_t n, uint32_t seq_offset,
                     struct fec_parms *code, rs &params)
    : Packets(),
      k_(k),
      n_(n),
      seq_offset_(seq_offset),
      code_(code),
      max_buffer_size_(0),
      current_block_size_(0),
      to_decode_(false),
      params_(params) {
  sorted_index_.reserve(n);
  UNUSED(seq_offset_);
}

bool BlockCode::addRepairSymbol(const fec::buffer &packet, uint32_t i,
                                uint32_t offset) {
  // Get index
  to_decode_ = true;
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "Adding symbol of size " << packet->length();
  return addSymbol(packet, i, offset,
                   packet->length() - sizeof(fec_header) - offset,
                   FECBase::INVALID_METADATA);
}

bool BlockCode::addSourceSymbol(const fec::buffer &packet, uint32_t i,
                                uint32_t offset, uint32_t metadata) {
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "Adding source symbol of size "
                               << packet->length() << ", offset " << offset;
  return addSymbol(packet, i, offset, packet->length() - offset, metadata);
}

bool BlockCode::addSymbol(const fec::buffer &packet, uint32_t i,
                          uint32_t offset, std::size_t size,
                          uint32_t metadata) {
  if (size > max_buffer_size_) {
    max_buffer_size_ = size;
  }

  operator[](current_block_size_) = RSBufferInfo(offset, i, metadata, packet);
  current_block_size_++;

  if (current_block_size_ >= k_) {
    if (to_decode_) {
      decode();
    } else {
      encode();
    }

    clear();
    return false;
  }

  return true;
}

void BlockCode::encode() {
  gf *data[n_];
  uint32_t base = operator[](0).getIndex();

  // Set packet length in first 2 bytes
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).getBuffer();
    auto offset = operator[](i).getOffset();
    auto metadata_base = operator[](i).getMetadata();

    auto ret =
        packet->ensureCapacityAndFillUnused(max_buffer_size_ + offset, 0);
    if (TRANSPORT_EXPECT_FALSE(ret == false)) {
      throw errors::RuntimeException(
          "Provided packet is not suitable to be used as FEC source packet. "
          "Aborting.");
    }

    // Buffers should hold 2 *after* the padding, in order to be
    // able to set the length for the encoding operation.
    // packet->trimStart(offset);
    fec_metadata *metadata = reinterpret_cast<fec_metadata *>(
        packet->writableData() + max_buffer_size_ + offset);
    auto buffer_length = packet->length() - offset;
    metadata->setPacketLength(buffer_length);
    metadata->setMetadataBase(metadata_base);

    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Current buffer size: " << packet->length();

    data[i] = packet->writableData() + offset;
  }

  // Finish to fill source block with the buffers to hold the repair symbols
  auto length = max_buffer_size_ + sizeof(fec_header) + METADATA_BYTES;
  for (uint32_t i = k_; i < n_; i++) {
    buffer packet;
    if (!params_.buffer_callback_) {
      // If no callback is installed, let's allocate a buffer from global pool
      packet = core::PacketManager<>::getInstance().getMemBuf();
      packet->append(length);
    } else {
      // Otherwise let's ask a buffer to the caller.
      packet = params_.buffer_callback_(length);
    }

    fec_header *fh = reinterpret_cast<fec_header *>(packet->writableData());

    fh->setSeqNumberBase(base);
    fh->setNFecSymbols(n_ - k_);
    fh->setEncodedSymbolId(i);
    fh->setSourceBlockLen(n_);

    packet->trimStart(sizeof(fec_header));

    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Current symbol size: " << packet->length();

    data[i] = packet->writableData();
    operator[](i) = RSBufferInfo(uint32_t(0), i, FECBase::INVALID_METADATA,
                                 std::move(packet));
  }

  // Generate repair symbols and put them in corresponding buffers
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling encode with max_buffer_size_ = " << max_buffer_size_;
  for (uint32_t i = k_; i < n_; i++) {
    fec_encode(code_, data, data[i], i, max_buffer_size_ + METADATA_BYTES);
  }

  // Re-include header in repair packets
  for (uint32_t i = k_; i < n_; i++) {
    auto &packet = operator[](i).getBuffer();
    packet->prepend(sizeof(fec_header));
    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "Produced repair symbol of size = " << packet->length();
  }
}

void BlockCode::decode() {
  gf *data[n_];
  uint32_t index[k_];
  buffer aux_fec_packets[n_ - k_];
  // FEC packet number  k0
  uint32_t k0 = 0;

  // Reorder block by index with in-place sorting
  for (uint32_t i = 0; i < k_;) {
    uint32_t idx = operator[](i).getIndex();
    if (idx >= k_ || idx == i) {
      i++;
    } else {
      std::swap(operator[](i), operator[](idx));
    }
  }

  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).getBuffer();
    index[i] = operator[](i).getIndex();
    auto offset = operator[](i).getOffset();
    auto metadata_base = operator[](i).getMetadata();
    sorted_index_[i] = index[i];

    if (index[i] < k_) {
      operator[](i).setReceived();
      DLOG_IF(INFO, VLOG_IS_ON(4))
          << "DECODE SOURCE - index " << index[i]
          << " - Current buffer size: " << packet->length();
      // This is a source packet. We need to fill
      // additional space to 0 and append the length

      // Buffers should hold 2 bytes at the end, in order to be
      // able to set the length for the encoding operation
      packet->trimStart(offset);
      packet->ensureCapacityAndFillUnused(max_buffer_size_, 0);
      fec_metadata *metadata = reinterpret_cast<fec_metadata *>(
          packet->writableData() + max_buffer_size_ - METADATA_BYTES);
      metadata->setPacketLength(packet->length());
      metadata->setMetadataBase(metadata_base);
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(4))
          << "DECODE SYMBOL - index " << index[i]
          << " - Current buffer size: " << packet->length();
      packet->trimStart(sizeof(fec_header) + offset);
      aux_fec_packets[k0] = core::PacketManager<>::getInstance().getMemBuf();
      data[k_ + k0] = aux_fec_packets[k0]->writableData();
      k0++;
    }
    data[i] = packet->writableData();
  }
  // We decode the source block
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling decode with max_buffer_size_ = " << max_buffer_size_;

  fec_decode(code_, data, reinterpret_cast<int *>(index), max_buffer_size_);

  // Find the index in the block for recovered packets
  for (uint32_t i = 0, j = 0; i < k_; i++) {
    if (index[i] >= k_) {
      operator[](i).setBuffer(aux_fec_packets[j++]);
      operator[](i).setIndex(i);
    }
  }

  // Adjust length according to the one written in the source packet
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).getBuffer();
    fec_metadata *metadata = reinterpret_cast<fec_metadata *>(
        packet->writableData() + max_buffer_size_ - METADATA_BYTES);
    // Adjust buffer length
    packet->setLength(metadata->getPacketLength());
    // Adjust metadata
    operator[](i).setMetadata(metadata->getMetadataBase());

    // reset the point to the beginning of the packets for all received packets
    if (operator[](i).getReceived()) {
      auto &packet = operator[](i).getBuffer();
      auto offset = operator[](i).getOffset();
      packet->prepend(offset);
    }
  }
}

void BlockCode::clear() {
  current_block_size_ = 0;
  max_buffer_size_ = 0;
  sorted_index_.clear();
  to_decode_ = false;
}

void rs::MatrixDeleter::operator()(struct fec_parms *params) {
  fec_free(params);
}

rs::Codes rs::createCodes() {
  Codes ret;

#define _(name, k, n) \
  ret.emplace(std::make_pair(k, n), Matrix(fec_new(k, n), MatrixDeleter()));
  foreach_rs_fec_type
#undef _

      return ret;
}

rs::Codes rs::codes_ = createCodes();

rs::rs(uint32_t k, uint32_t n, uint32_t seq_offset)
    : k_(k), n_(n), seq_offset_(seq_offset % n) {}

RSEncoder::RSEncoder(uint32_t k, uint32_t n, uint32_t seq_offset)
    : rs(k, n, seq_offset),
      current_code_(codes_[std::make_pair(k, n)].get()),
      source_block_(k_, n_, seq_offset_, current_code_, *this) {}

void RSEncoder::consume(const fec::buffer &packet, uint32_t index,
                        uint32_t offset, uint32_t metadata) {
  if (!source_block_.addSourceSymbol(packet, index, offset, metadata)) {
    fec::BufferArray repair_packets;
    for (uint32_t i = k_; i < n_; i++) {
      repair_packets.emplace_back(std::move(source_block_[i]));
    }

    fec_callback_(repair_packets);
  }
}

void RSEncoder::onPacketProduced(core::ContentObject &content_object,
                                 uint32_t offset, uint32_t metadata) {
  consume(content_object.shared_from_this(),
          content_object.getName().getSuffix(), offset, metadata);
}

RSDecoder::RSDecoder(uint32_t k, uint32_t n, uint32_t seq_offset)
    : rs(k, n, seq_offset) {}

void RSDecoder::recoverPackets(SourceBlocks::iterator &src_block_it) {
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "recoverPackets for " << k_;
  auto &src_block = src_block_it->second;
  auto base_index = src_block_it->first;
  BufferArray source_packets(k_);

  // Iterate over packets in the block and adjust indexed accordingly. This must
  // be done because indexes are from 0 to (n - k - 1), but we need indexes from
  // base_index to base_index + (n - k - 1)
  for (uint32_t i = 0; i < src_block.getK(); i++) {
    src_block[i].setIndex(base_index + src_block[i].getIndex());
    source_packets[i] = FECBufferInfo(std::move(src_block[i]));
  }

  setProcessed(src_block_it->first);

  fec_callback_(source_packets);
  processed_source_blocks_.emplace(src_block_it->first);

  auto it = parked_packets_.find(src_block_it->first);
  if (it != parked_packets_.end()) {
    parked_packets_.erase(it);
  }

  src_blocks_.erase(src_block_it);
}

void RSDecoder::consumeSource(const fec::buffer &packet, uint32_t index,
                              uint32_t offset, uint32_t metadata) {
  // Normalize index
  DCHECK(index >= seq_offset_);
  auto i = (index - seq_offset_) % n_;

  // Get base
  uint32_t base = index - i;

  if (processed(base)) {
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Decoder consume called for source symbol. BASE = " << base
      << ", index = " << index << " and i = " << i;

  // check if a source block already exist for this symbol. If it does not
  // exist, we lazily park this packet until we receive a repair symbol for the
  // same block. This is done for 2 reason:
  // 1) If we receive all the source packets of a block, we do not need to
  //    recover anything.
  // 2) Sender may change n and k at any moment, so we construct the source
  //    block based on the (n, k) values written in the fec header. This is
  //    actually not used right now, since we use fixed value of n and k passed
  //    at construction time, but it paves the ground for a more dynamic
  //    protocol that may come in the future.
  auto it = src_blocks_.find(base);
  if (it != src_blocks_.end()) {
    auto ret = it->second.addSourceSymbol(packet, i, offset, metadata);
    if (!ret) {
      recoverPackets(it);
    }
  } else {
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Adding to parked source packets";
    auto ret = parked_packets_.emplace(base, BufferInfoArray());
    ret.first->second.emplace_back(offset, i, metadata, packet);

    /**
     * If we reached k source packets, we do not have any missing packet to
     * recover via FEC. Delete the block.
     */
    if (ret.first->second.size() >= k_) {
      setProcessed(ret.first->first);
      parked_packets_.erase(ret.first);
    }
  }
}

void RSDecoder::consumeRepair(const fec::buffer &packet, uint32_t offset) {
  // Repair symbol! Get index and base source block.
  fec_header *h =
      reinterpret_cast<fec_header *>(packet->writableData() + offset);
  auto i = h->getEncodedSymbolId();
  auto base = h->getSeqNumberBase();
  auto n = h->getSourceBlockLen();
  auto k = n - h->getNFecSymbols();

  if (processed(base)) {
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Decoder consume called for repair symbol. BASE = " << base
      << ", index = " << base + i << " and i = " << (int)i << ". K=" << (int)k
      << ", N=" << (int)n;

  // check if a source block already exist for this symbol
  auto it = src_blocks_.find(base);
  if (it == src_blocks_.end()) {
    // Create new source block
    auto code_it = codes_.find(std::make_pair(k, n));
    if (code_it == codes_.end()) {
      LOG(ERROR) << "Code for k = " << k << " and n = " << n
                 << " does not exist.";
      return;
    }

    auto emplace_result = src_blocks_.emplace(
        base, BlockCode(k, n, seq_offset_, code_it->second.get(), *this));
    it = emplace_result.first;

    // Check in the parked packets and insert any packet that is part of this
    // source block

    auto it2 = parked_packets_.find(base);
    if (it2 != parked_packets_.end()) {
      for (auto &packet_index : it2->second) {
        auto ret = it->second.addSourceSymbol(
            packet_index.getBuffer(), packet_index.getIndex(),
            packet_index.getOffset(), packet_index.getMetadata());
        if (!ret) {
          recoverPackets(it);
          // Finish to delete packets in same source block that were
          // eventually not used
          return;
        }
      }
    }
  }

  auto ret = it->second.addRepairSymbol(packet, i, offset);
  if (!ret) {
    recoverPackets(it);
  }
}

void RSDecoder::onDataPacket(core::ContentObject &content_object,
                             uint32_t offset, uint32_t metadata) {
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling fec for data packet " << content_object.getName()
      << ". Offset: " << offset;

  auto suffix = content_object.getName().getSuffix();

  if (isSymbol(suffix)) {
    consumeRepair(content_object.shared_from_this(), offset);
  } else {
    consumeSource(content_object.shared_from_this(), suffix, offset, metadata);
  }
}

}  // namespace fec
}  // namespace protocol
}  // namespace transport
