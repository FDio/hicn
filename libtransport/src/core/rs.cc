
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

#include <core/fec.h>
#include <core/rs.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/utils/log.h>

#include <cassert>

namespace transport {
namespace core {
namespace fec {

BlockCode::BlockCode(uint32_t k, uint32_t n, struct fec_parms *code)
    : Packets(),
      k_(k),
      n_(n),
      code_(code),
      max_buffer_size_(0),
      current_block_size_(0),
      to_decode_(false) {
  sorted_index_.reserve(n);
}

bool BlockCode::addRepairSymbol(const fec::buffer &packet, uint32_t i) {
  // Get index
  to_decode_ = true;
  TRANSPORT_LOGD("adding symbol of size %zu", packet->length());
  return addSymbol(packet, i, packet->length() - sizeof(fec_header));
}

bool BlockCode::addSourceSymbol(const fec::buffer &packet, uint32_t i) {
  return addSymbol(packet, i, packet->length());
}

bool BlockCode::addSymbol(const fec::buffer &packet, uint32_t i,
                          std::size_t size) {
  if (size > max_buffer_size_) {
    max_buffer_size_ = size;
  }

  operator[](current_block_size_++) = std::make_pair(i, packet);

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
  gf **data = new gf*[k_];
  uint32_t *old_values = new uint32_t[k_];
  uint32_t base = operator[](0).first;

  // Set packet length in first 2 bytes
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).second;

    TRANSPORT_LOGD("Current buffer size: %zu", packet->length());

    auto ret = packet->ensureCapacityAndFillUnused(max_buffer_size_, 0);
    if (TRANSPORT_EXPECT_FALSE(ret == false)) {
      throw errors::RuntimeException(
          "Provided packet is not suitable to be used as FEC source packet. "
          "Aborting.");
    }

    // Buffers should hold 2 bytes before the starting pointer, in order to be
    // able to set the length for the encoding operation
    packet->prepend(2);
    uint16_t *length = reinterpret_cast<uint16_t *>(packet->writableData());

    old_values[i] = *length;
    *length = htons(u_short(packet->length() - LEN_SIZE_BYTES));

    data[i] = packet->writableData();
    delete [] data;
    delete [] old_values;
  }

  // Finish to fill source block with the buffers to hold the repair symbols
  for (uint32_t i = k_; i < n_; i++) {
    // For the moment we get a packet from the pool here.. later we'll need to
    // require a packet from the caller with a callback.
    auto packet = PacketManager<>::getInstance().getMemBuf();
    packet->append(max_buffer_size_ + sizeof(fec_header) + LEN_SIZE_BYTES);
    fec_header *fh = reinterpret_cast<fec_header *>(packet->writableData());

    fh->setSeqNumberBase(base);
    fh->setNFecSymbols(n_ - k_);
    fh->setEncodedSymbolId(i);
    fh->setSourceBlockLen(n_);

    packet->trimStart(sizeof(fec_header));

    data[i] = packet->writableData();
    operator[](i) = std::make_pair(i, std::move(packet));
  }

  // Generate repair symbols and put them in corresponding buffers
  TRANSPORT_LOGD("Calling encode with max_buffer_size_ = %zu",
                 max_buffer_size_);
  for (uint32_t i = k_; i < n_; i++) {
    fec_encode(code_, data, data[i], i, (int)(max_buffer_size_ + LEN_SIZE_BYTES));
  }

  // Restore original content of buffer space used to store the length
  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).second;
    uint16_t *length = reinterpret_cast<uint16_t *>(packet->writableData());
    *length = old_values[i];
    packet->trimStart(2);
  }

  // Re-include header in repair packets
  for (uint32_t i = k_; i < n_; i++) {
    auto &packet = operator[](i).second;
    TRANSPORT_LOGD("Produced repair symbol of size = %zu", packet->length());
    packet->prepend(sizeof(fec_header));
  }

}

void BlockCode::decode() {
  gf **data = new gf*[k_];
  uint32_t *index = new uint32_t[k_];

  for (uint32_t i = 0; i < k_; i++) {
    auto &packet = operator[](i).second;
    index[i] = operator[](i).first;
    sorted_index_[i] = index[i];

    if (index[i] < k_) {
      TRANSPORT_LOGD("DECODE SOURCE - index %u - Current buffer size: %zu",
                     index[i], packet->length());
      // This is a source packet. We need to prepend the length and fill
      // additional space to 0

      // Buffers should hold 2 bytes before the starting pointer, in order to be
      // able to set the length for the encoding operation
      packet->prepend(LEN_SIZE_BYTES);
      packet->ensureCapacityAndFillUnused(max_buffer_size_, 0);
      uint16_t *length = reinterpret_cast<uint16_t *>(packet->writableData());

      *length = htons(u_short(packet->length() - LEN_SIZE_BYTES));
    } else {
      TRANSPORT_LOGD("DECODE SYMBOL - index %u - Current buffer size: %zu",
                     index[i], packet->length());
      packet->trimStart(sizeof(fec_header));
    }

    data[i] = packet->writableData();
    delete [] data;
    delete [] index;
  }

  // We decode the source block
  TRANSPORT_LOGD("Calling decode with max_buffer_size_ = %zu",
                 max_buffer_size_);
  fec_decode(code_, data, reinterpret_cast<int *>(index), (int)max_buffer_size_);

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
    auto &packet = operator[](i).second;
    uint16_t *length = reinterpret_cast<uint16_t *>(packet->writableData());
    packet->trimStart(2);
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

  ret.emplace(std::make_pair(1, 3), Matrix(fec_new(1, 3), MatrixDeleter()));
  ret.emplace(std::make_pair(6, 10), Matrix(fec_new(6, 10), MatrixDeleter()));
  ret.emplace(std::make_pair(8, 32), Matrix(fec_new(8, 32), MatrixDeleter()));
  ret.emplace(std::make_pair(10, 30), Matrix(fec_new(10, 30), MatrixDeleter()));
  ret.emplace(std::make_pair(16, 24), Matrix(fec_new(16, 24), MatrixDeleter()));
  ret.emplace(std::make_pair(10, 40), Matrix(fec_new(10, 40), MatrixDeleter()));
  ret.emplace(std::make_pair(10, 60), Matrix(fec_new(10, 60), MatrixDeleter()));
  ret.emplace(std::make_pair(10, 90), Matrix(fec_new(10, 90), MatrixDeleter()));

  return ret;
}

rs::Codes rs::codes_ = createCodes();

rs::rs(uint32_t k, uint32_t n) : k_(k), n_(n) {}

void rs::setFECCallback(const PacketsReady &callback) {
  fec_callback_ = callback;
}

encoder::encoder(uint32_t k, uint32_t n)
    : rs(k, n),
      current_code_(codes_[std::make_pair(k, n)].get()),
      source_block_(k_, n_, current_code_) {}

void encoder::consume(const fec::buffer &packet, uint32_t index) {
  if (!source_block_.addSourceSymbol(packet, index)) {
    std::vector<buffer> repair_packets;
    for (uint32_t i = k_; i < n_; i++) {
      repair_packets.emplace_back(std::move(source_block_[i].second));
    }
    fec_callback_(repair_packets);
  }
}

decoder::decoder(uint32_t k, uint32_t n) : rs(k, n) {}

void decoder::recoverPackets(SourceBlocks::iterator &src_block_it) {
  TRANSPORT_LOGD("recoverPackets for %u", k_);
  auto &src_block = src_block_it->second;
  std::vector<buffer> source_packets(k_);
  for (uint32_t i = 0; i < src_block.getK(); i++) {
    source_packets[i] = std::move(src_block[i].second);
  }

  fec_callback_(source_packets);
  processed_source_blocks_.emplace(src_block_it->first);

  auto it = parked_packets_.find(src_block_it->first);
  if (it != parked_packets_.end()) {
    parked_packets_.erase(it);
  }

  src_blocks_.erase(src_block_it);
}

void decoder::consume(const fec::buffer &packet, uint32_t index) {
  // Normalize index
  auto i = index % n_;

  // Get base
  uint32_t base = index - i;

  TRANSPORT_LOGD(
      "Decoder consume called for source symbol. BASE = %u, index = %u and i = "
      "%u",
      base, index, i);

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
    auto ret = it->second.addSourceSymbol(packet, i);
    if (!ret) {
      recoverPackets(it);
    }
  } else {
    TRANSPORT_LOGD("Adding to parked source packets");
    auto ret = parked_packets_.emplace(
        base, std::vector<std::pair<buffer, uint32_t> >());
    ret.first->second.emplace_back(packet, i);
  }
}

void decoder::consume(const fec::buffer &packet) {
  // Repair symbol! Get index and base source block.
  fec_header *h = reinterpret_cast<fec_header *>(packet->writableData());
  auto i = h->getEncodedSymbolId();
  auto base = h->getSeqNumberBase();
  auto n = h->getSourceBlockLen();
  auto k = n - h->getNFecSymbols();

  TRANSPORT_LOGD(
      "Decoder consume called for repair symbol. BASE = %u, index = %u and i = "
      "%u",
      base, base + i, i);

  // check if a source block already exist for this symbol
  auto it = src_blocks_.find(base);
  if (it == src_blocks_.end()) {
    // Create new source block
    auto code_it = codes_.find(std::make_pair(k, n));
    if (code_it == codes_.end()) {
      TRANSPORT_LOGE("Code for k = %u and n = %u does not exist.", k_, n_);
      return;
    }

    auto emplace_result =
        src_blocks_.emplace(base, BlockCode(k, n, code_it->second.get()));
    it = emplace_result.first;

    // Check in the parked packets and insert any packet that is part of this
    // source block

    auto it2 = parked_packets_.find(base);
    if (it2 != parked_packets_.end()) {
      for (auto &packet_index : it2->second) {
        auto ret =
            it->second.addSourceSymbol(packet_index.first, packet_index.second);
        if (!ret) {
          recoverPackets(it);
          // Finish to delete packets in same source block that were
          // eventually not used
          return;
        }
      }
    }
  }

  auto ret = it->second.addRepairSymbol(packet, i);
  if (!ret) {
    recoverPackets(it);
  }
}

}  // namespace fec
}  // namespace core
}  // namespace transport
