
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
                   packet->length() - sizeof(fec_header) - offset);
}

bool BlockCode::addSourceSymbol(const fec::buffer &packet, uint32_t i,
                                uint32_t offset) {
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "Adding source symbol of size "
                               << packet->length() << ", offset " << offset;
  return addSymbol(packet, i, offset, packet->length() - offset);
}

bool BlockCode::addSymbol(const fec::buffer &packet, uint32_t i,
                          uint32_t offset, std::size_t size) {
  if (size > max_buffer_size_) {
    max_buffer_size_ = size;
  }

  operator[](current_block_size_++) = std::make_tuple(i, packet, offset);

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
  uint32_t base = std::get<0>(operator[](0));

  // Set packet length in first 2 bytes
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = std::get<1>(operator[](i));
    auto offset = std::get<2>(operator[](i));

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
    uint16_t *length = reinterpret_cast<uint16_t *>(packet->writableData() +
                                                    max_buffer_size_ + offset);
    auto buffer_length = packet->length() - offset;
    *length = htons(buffer_length);

    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Current buffer size: " << packet->length();

    data[i] = packet->writableData() + offset;
  }

  // Finish to fill source block with the buffers to hold the repair symbols
  auto length = max_buffer_size_ + sizeof(fec_header) + LEN_SIZE_BYTES;
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
    operator[](i) = std::make_tuple(i, std::move(packet), uint32_t(0));
  }

  // Generate repair symbols and put them in corresponding buffers
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling encode with max_buffer_size_ = " << max_buffer_size_;
  for (uint32_t i = k_; i < n_; i++) {
    fec_encode(code_, data, data[i], i, max_buffer_size_ + LEN_SIZE_BYTES);
  }

  // Re-include header in repair packets
  for (uint32_t i = k_; i < n_; i++) {
    auto &packet = std::get<1>(operator[](i));
    packet->prepend(sizeof(fec_header));
    DLOG_IF(INFO, VLOG_IS_ON(4))
        << "Produced repair symbol of size = " << packet->length();
  }
}

void BlockCode::decode() {
  gf *data[k_];
  uint32_t index[k_];

  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = std::get<1>(operator[](i));
    index[i] = std::get<0>(operator[](i));
    auto offset = std::get<2>(operator[](i));
    sorted_index_[i] = index[i];

    if (index[i] < k_) {
      DLOG_IF(INFO, VLOG_IS_ON(4))
          << "DECODE SOURCE - index " << index[i]
          << " - Current buffer size: " << packet->length();
      // This is a source packet. We need to fill
      // additional space to 0 and append the length

      // Buffers should hold 2 bytes at the end, in order to be
      // able to set the length for the encoding operation
      packet->trimStart(offset);
      packet->ensureCapacityAndFillUnused(max_buffer_size_, 0);
      uint16_t *length = reinterpret_cast<uint16_t *>(
          packet->writableData() + max_buffer_size_ - LEN_SIZE_BYTES);

      *length = htons(packet->length());
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(4))
          << "DECODE SYMBOL - index " << index[i]
          << " - Current buffer size: " << packet->length();
      packet->trimStart(sizeof(fec_header) + offset);
    }

    data[i] = packet->writableData();
  }

  // We decode the source block
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling decode with max_buffer_size_ = " << max_buffer_size_;
  fec_decode(code_, data, reinterpret_cast<int *>(index), max_buffer_size_);

  // Find the index in the block for recovered packets
  for (uint32_t i = 0; i < k_; i++) {
    if (index[i] != i) {
      for (uint32_t j = 0; j < k_; j++)
        if (sorted_index_[j] == uint32_t(index[i])) {
          sorted_index_[j] = i;
        }
    }
  }

  // Reorder block by index with in-place sorting
  for (uint32_t i = 0; i < k_; i++) {
    for (uint32_t j = sorted_index_[i]; j != i; j = sorted_index_[i]) {
      std::swap(sorted_index_[j], sorted_index_[i]);
      std::swap(operator[](j), operator[](i));
    }
  }

  // Adjust length according to the one written in the source packet
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = std::get<1>(operator[](i));
    uint16_t *length = reinterpret_cast<uint16_t *>(
        packet->writableData() + max_buffer_size_ - LEN_SIZE_BYTES);
    packet->setLength(ntohs(*length));
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
                        uint32_t offset) {
  if (!source_block_.addSourceSymbol(packet, index, offset)) {
    std::vector<std::pair<uint32_t, buffer>> repair_packets;
    for (uint32_t i = k_; i < n_; i++) {
      repair_packets.emplace_back(std::move(std::get<0>(source_block_[i])),
                                  std::move(std::get<1>(source_block_[i])));
    }

    fec_callback_(repair_packets);
  }
}

void RSEncoder::onPacketProduced(core::ContentObject &content_object,
                                 uint32_t offset) {
  consume(content_object.shared_from_this(),
          content_object.getName().getSuffix(), offset);
}

RSDecoder::RSDecoder(uint32_t k, uint32_t n, uint32_t seq_offset)
    : rs(k, n, seq_offset) {}

void RSDecoder::recoverPackets(SourceBlocks::iterator &src_block_it) {
  DLOG_IF(INFO, VLOG_IS_ON(4)) << "recoverPackets for " << k_;
  auto &src_block = src_block_it->second;
  std::vector<std::pair<uint32_t, buffer>> source_packets(k_);
  for (uint32_t i = 0; i < src_block.getK(); i++) {
    source_packets[i] = std::make_pair(
        src_block_it->first + i,
        std::move(std::get<1>(src_block[i])));
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
                              uint32_t offset) {
  // Normalize index
  assert(index >= seq_offset_);
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
    auto ret = it->second.addSourceSymbol(packet, i, offset);
    if (!ret) {
      recoverPackets(it);
    }
  } else {
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "Adding to parked source packets";
    auto ret = parked_packets_.emplace(
        base, std::vector<std::pair<buffer, uint32_t>>());
    ret.first->second.emplace_back(packet, i);

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
      << ", index = " << base + i << " and i = " << i << ". K=" << k
      << ", N=" << n;

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
        auto ret = it->second.addSourceSymbol(packet_index.first,
                                              packet_index.second, offset);
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
                             uint32_t offset) {
  DLOG_IF(INFO, VLOG_IS_ON(4))
      << "Calling fec for data packet " << content_object.getName()
      << ". Offset: " << offset;

  auto suffix = content_object.getName().getSuffix();

  if (isSymbol(suffix)) {
    consumeRepair(content_object.shared_from_this(), offset);
  } else {
    consumeSource(content_object.shared_from_this(), suffix, offset);
  }
}

}  // namespace fec
}  // namespace protocol
}  // namespace transport
