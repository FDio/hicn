
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

#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <hicn/transport/utils/membuf.h>
#include <protocols/fec_base.h>

#include <array>
#include <cstdint>
#include <map>
#include <unordered_set>
#include <vector>

namespace transport {
namespace core {

namespace fec {

static const constexpr uint16_t MAX_SOURCE_BLOCK_SIZE = 128;

using buffer = typename utils::MemBuf::Ptr;
/**
 * We use a std::array in place of std::vector to avoid to allocate a new vector
 * in the heap every time we build a new source block, which would be bad if
 * the decoder has to allocate several source blocks for many concurrent bases.
 * std::array allows to be constructed in place, saving the allocation at the
 * price os knowing in advance its size.
 */
using Packets = std::array<std::pair<uint32_t, buffer>, MAX_SOURCE_BLOCK_SIZE>;

/**
 * FEC Header, prepended to symbol packets.
 */
struct fec_header {
  /**
   * The base source packet seq_number this FES symbol refers to
   */
  uint32_t seq_number;

  /**
   * The index of the symbol inside the source block, between k and n - 1
   */
  uint8_t encoded_symbol_id;

  /**
   * Total length of source block (n)
   */
  uint8_t source_block_len;

  /**
   * Total number of symbols (n - k)
   */
  uint8_t n_fec_symbols;

  /**
   * Align header to 64 bits
   */
  uint8_t padding;

  void setSeqNumberBase(uint32_t suffix) { seq_number = htonl(suffix); }
  uint32_t getSeqNumberBase() { return ntohl(seq_number); }
  void setEncodedSymbolId(uint8_t esi) { encoded_symbol_id = esi; }
  uint8_t getEncodedSymbolId() { return encoded_symbol_id; }
  void setSourceBlockLen(uint8_t k) { source_block_len = k; }
  uint8_t getSourceBlockLen() { return source_block_len; }
  void setNFecSymbols(uint8_t n_r) { n_fec_symbols = n_r; }
  uint8_t getNFecSymbols() { return n_fec_symbols; }
};

/**
 * This class models the source block itself.
 */
class BlockCode : public Packets {
  /**
   * For variable length packet we need to prepend to the padded payload the
   * real length of the packet. This is *not* sent over the network.
   */
  static constexpr std::size_t LEN_SIZE_BYTES = 2;

 public:
  BlockCode(uint32_t k, uint32_t n, struct fec_parms *code);

  /**
   * Add a repair symbol to the dource block.
   */
  bool addRepairSymbol(const fec::buffer &packet, uint32_t i);

  /**
   * Add a source symbol to the source block.
   */
  bool addSourceSymbol(const fec::buffer &packet, uint32_t i);

  /**
   * Get current length of source block.
   */
  std::size_t length() { return current_block_size_; }

  /**
   * Get N
   */
  uint32_t getN() { return n_; }

  /**
   * Get K
   */
  uint32_t getK() { return k_; }

  /**
   * Clear source block
   */
  void clear();

 private:
  /**
   * Add symbol to source block
   **/
  bool addSymbol(const fec::buffer &packet, uint32_t i, std::size_t size);

  /**
   * Starting from k source symbols, get the n - k repair symbols
   */
  void encode();

  /**
   * Starting from k symbols (mixed repair and source), get k source symbols.
   * NOTE: It does not make sense to retrieve the k source symbols using the
   * very same k source symbols. With the current implementation that case can
   * never happen.
   */
  void decode();

 private:
  uint32_t k_;
  uint32_t n_;
  struct fec_parms *code_;
  std::size_t max_buffer_size_;
  std::size_t current_block_size_;
  std::vector<uint32_t> sorted_index_;
  bool to_decode_;
};

/**
 * This class contains common parameters between the fec encoder and decoder.
 * In particular it contains:
 *  - The callback to be called when symbols are encoded / decoded
 *  - The reference to the static reed-solomon parameters, allocated at program
 * startup
 *  - N and K. Ideally they are useful only for the encoder (the decoder can
 * retrieve them from the FEC header). However right now we assume sender and
 * receiver agreed on the parameters k and n to use. We will introduce a control
 * message later to negotiate them, so that decoder cah dynamically change them
 * during the download.
 */
class rs {
  /**
   * Deleter for static preallocated reed-solomon parameters.
   */
  struct MatrixDeleter {
    void operator()(struct fec_parms *params);
  };

  /**
   * unique_ptr to reed-solomon parameters, with custom deleter to call fec_free
   * at the end of the program
   */
  using Matrix = std::unique_ptr<struct fec_parms, MatrixDeleter>;

  /**
   * Key to retrieve static preallocated reed-solomon parameters. It is pair of
   * k and n
   */
  using Code = std::pair<std::uint32_t /* k */, std::uint32_t /* n */>;

  /**
   * Custom hash function for (k, n) pair.
   */
  struct CodeHasher {
    std::size_t operator()(const transport::core::fec::rs::Code &code) const {
      uint64_t ret = uint64_t(code.first) << 32 | uint64_t(code.second);
      return std::hash<uint64_t>{}(ret);
    }
  };

 protected:
  /**
   * Callback to be called after the encode or the decode operations. In the
   * former case it will contain the symbols, while in the latter the sources.
   */
  using PacketsReady = std::function<void(std::vector<buffer> &)>;

  /**
   * The sequence number base.
   */
  using SNBase = std::uint32_t;

  /**
   * The map of source blocks, used at the decoder side. For the encoding
   * operation we can use one source block only, since packet are produced in
   * order.
   */
  using SourceBlocks = std::unordered_map<SNBase, BlockCode>;

  /**
   * Map (k, n) -> reed-solomon parameter
   */
  using Codes = std::unordered_map<Code, Matrix, CodeHasher>;

 public:
  rs(uint32_t k, uint32_t n);
  ~rs() = default;

  /**
   * Set callback to call after packet encoding / decoding
   */
  void setFECCallback(const PacketsReady &callback);

  virtual void clear() { processed_source_blocks_.clear(); }

 private:
  /**
   * Create reed-solomon codes at program startup.
   */
  static Codes createCodes();

 protected:
  bool processed(SNBase seq_base) {
    return processed_source_blocks_.find(seq_base) !=
           processed_source_blocks_.end();
  }

  std::uint32_t k_;
  std::uint32_t n_;
  PacketsReady fec_callback_;

  /**
   * Keep track of processed source blocks
   */
  std::unordered_set<SNBase> processed_source_blocks_;

  static Codes codes_;
};

/**
 * The reed-solomon encoder. It is feeded with source symbols and it provide
 * repair-symbols through the fec_callback_
 */
class encoder : public rs {
 public:
  encoder(uint32_t k, uint32_t n);
  /**
   * Always consume source symbols.
   */
  void consume(const fec::buffer &packet, uint32_t index);

  void clear() override {
    rs::clear();
    source_block_.clear();
  }

 private:
  struct fec_parms *current_code_;
  /**
   * The source block. As soon as it is filled with k source symbols, the
   * encoder calls the callback fec_callback_ and the resets the block 0, ready
   * to accept another batch of k source symbols.
   */
  BlockCode source_block_;
};

/**
 * The reed-solomon encoder. It is feeded with source/repair symbols and it
 * provides the original source symbols through the fec_callback_
 */
class decoder : public rs {
 public:
  decoder(uint32_t k, uint32_t n);

  /**
   * Consume source symbol
   */
  void consume(const fec::buffer &packet, uint32_t i);

  /**
   * Consume repair symbol
   */
  void consume(const fec::buffer &packet);

  /**
   * Clear decoder to reuse
   */
  void clear() override {
    rs::clear();
    src_blocks_.clear();
    parked_packets_.clear();
  }

 private:
  void recoverPackets(SourceBlocks::iterator &src_block_it);

 private:
  /**
   * Map of source blocks. We use a map because we may receive symbols belonging
   * to diffreent source blocks at the same time, so we need to be able to
   * decode many source symbols at the same time.
   */
  SourceBlocks src_blocks_;

  /**
   * Unordered Map of source symbols for which we did not receive any repair
   * symbol in the same source block. Notably this happens when:
   *
   * - We receive the source symbols first and the repair symbols after
   * - We received only source symbols for a given block. In that case it does
   * not make any sense to build the source block, since we received all the
   * source packet of the block.
   */
  std::unordered_map<uint32_t, std::vector<std::pair<buffer, uint32_t>>>
      parked_packets_;
};

}  // namespace fec

}  // namespace core

}  // namespace transport
