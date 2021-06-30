
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

#include <gtest/gtest.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/global_object_pool.h>
#include <protocols/fec/rs.h>

#include <algorithm>
#include <iostream>
#include <random>

namespace transport {
namespace protocol {

double ReedSolomonTest(int k, int n, int seq_offset, int size) {
  fec::RSEncoder encoder(k, n, seq_offset);
  fec::RSDecoder decoder(k, n, seq_offset);

  std::vector<fec::buffer> tx_block(k);
  std::vector<fec::buffer> rx_block(k);
  int count = 0;
  int run = 0;

  int iterations = 100;
  auto &packet_manager = core::PacketManager<>::getInstance();

  encoder.setFECCallback(
      [&tx_block](
          std::vector<std::pair<uint32_t, fec::buffer>> &repair_packets) {
        for (auto &p : repair_packets) {
          // Append repair symbols to tx_block
          tx_block.emplace_back(std::move(p).second);
        }
      });

  decoder.setFECCallback(
      [&](std::vector<std::pair<uint32_t, fec::buffer>> &source_packets) {
        for (int i = 0; i < k; i++) {
          // Compare decoded source packets with original transmitted packets.
          if (*tx_block[i] != *source_packets[i].second) {
            count++;
          }
        }
      });

  do {
    // Discard eventual packet appended in previous callback call
    tx_block.erase(tx_block.begin() + k, tx_block.end());
    auto _seq_offet = seq_offset;

    // Initialization. Feed encoder with first k source packets
    for (int i = 0; i < k; i++) {
      // Get new buffer from pool
      auto packet = packet_manager.getMemBuf();

      // Let's append a bit less than size, so that the FEC class will take care
      // of filling the rest with zeros
      auto cur_size = size - (rand() % 100);

      // Set payload, saving 2 bytes at the beginning of the buffer for encoding
      // the length
      packet->append(cur_size);
      packet->trimStart(2);
      std::generate(packet->writableData(), packet->writableTail(), rand);
      std::fill(packet->writableData(), packet->writableTail(), i + 1);

      // Set first byte of payload to seq_offset, to reorder at receiver side
      packet->writableData()[0] = uint8_t(_seq_offet++);

      // Store packet in tx buffer and clear rx buffer
      tx_block[i] = std::move(packet);
    }

    // Create the repair packets
    for (auto &tx : tx_block) {
      encoder.consume(tx, tx->writableBuffer()[0]);
    }

    // Simulate transmission on lossy channel
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<bool> losses(n, false);
    for (int i = 0; i < n - k; i++) losses[i] = true;

    int rxi = 0;
    std::shuffle(losses.begin(), losses.end(),
                 std::default_random_engine(seed));
    for (int i = 0; i < n && rxi < k; i++)
      if (losses[i] == false) {
        rx_block[rxi++] = tx_block[i];
        if (i < k) {
          // Source packet
          decoder.consumeSource(rx_block[rxi - 1],
                                rx_block[rxi - 1]->data()[0]);
        } else {
          // Repair packet
          decoder.consumeRepair(rx_block[rxi - 1]);
        }
      }

    decoder.clear();
    encoder.clear();
  } while (++run < iterations);

  return count;
}

void ReedSolomonMultiBlockTest(int n_sourceblocks) {
  int k = 16;
  int n = 24;
  int size = 1000;

  fec::RSEncoder encoder(k, n);
  fec::RSDecoder decoder(k, n);

  auto &packet_manager = core::PacketManager<>::getInstance();

  std::vector<std::pair<fec::buffer, uint32_t>> tx_block;
  std::vector<std::pair<fec::buffer, uint32_t>> rx_block;
  int count = 0;
  int i = 0;

  // Receiver will receive packet for n_sourceblocks in a random order.
  int total_packets = n * n_sourceblocks;
  int tx_packets = k * n_sourceblocks;
  unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();

  encoder.setFECCallback(
      [&](std::vector<std::pair<uint32_t, fec::buffer>> &repair_packets) {
        for (auto &p : repair_packets) {
          // Append repair symbols to tx_block
          tx_block.emplace_back(std::move(p.second), ++i);
        }

        EXPECT_EQ(tx_block.size(), size_t(n));

        // Select k packets to send, including at least one symbol. We start
        // from the end for this reason.
        for (int j = n - 1; j > n - k - 1; j--) {
          rx_block.emplace_back(std::move(tx_block[j]));
        }

        // Clear tx block for next source block
        tx_block.clear();
        encoder.clear();
      });

  // The decode callback must be called exactly n_sourceblocks times
  decoder.setFECCallback(
      [&](std::vector<std::pair<uint32_t, fec::buffer>> &source_packets) {
        count++;
      });

  // Produce n * n_sourceblocks
  //  - (  k  ) * n_sourceblocks source packets
  //  - (n - k) * n_sourceblocks symbols)
  for (i = 0; i < total_packets; i++) {
    // Get new buffer from pool
    auto packet = packet_manager.getMemBuf();

    // Let's append a bit less than size, so that the FEC class will take care
    // of filling the rest with zeros
    auto cur_size = size - (rand() % 100);

    // Set payload, saving 2 bytes at the beginning of the buffer for encoding
    // the length
    packet->append(cur_size);
    packet->trimStart(2);
    std::fill(packet->writableData(), packet->writableTail(), i + 1);

    // Set first byte of payload to i, to reorder at receiver side
    packet->writableData()[0] = uint8_t(i);

    // Store packet in tx buffer
    tx_block.emplace_back(packet, i);

    // Feed encoder with packet
    encoder.consume(packet, i);
  }

  // Here rx_block must contains k * n_sourceblocks packets
  EXPECT_EQ(size_t(tx_packets), size_t(rx_block.size()));

  // Lets shuffle the rx_block before starting feeding the decoder.
  std::shuffle(rx_block.begin(), rx_block.end(),
               std::default_random_engine(seed));

  for (auto &p : rx_block) {
    int index = p.second % n;
    if (index < k) {
      // Source packet
      decoder.consumeSource(p.first, p.second);
    } else {
      // Repair packet
      decoder.consumeRepair(p.first);
    }
  }

  // Simple test to check we get all the source packets
  EXPECT_EQ(count, n_sourceblocks);
}

/**
 * @brief Use foreach_rs_fec_type to automatically generate the code of the
 * tests and avoid copy/paste the same function.
 */
#define _(name, k, n)                                      \
  TEST(ReedSolomonTest, RSK##k##N##n) {                    \
    int K = k;                                             \
    int N = n;                                             \
    int seq_offset = 0;                                    \
    int size = 1000;                                       \
    EXPECT_LE(ReedSolomonTest(K, N, seq_offset, size), 0); \
    seq_offset = 12345;                                    \
    EXPECT_LE(ReedSolomonTest(K, N, seq_offset, size), 0); \
  }
foreach_rs_fec_type
#undef _

TEST(ReedSolomonMultiBlockTest, RSMB10) {
  int blocks = 10;
  ReedSolomonMultiBlockTest(blocks);
}

TEST(ReedSolomonMultiBlockTest, RSMB100) {
  int blocks = 100;
  ReedSolomonMultiBlockTest(blocks);
}

TEST(ReedSolomonMultiBlockTest, RSMB1000) {
  int blocks = 1000;
  ReedSolomonMultiBlockTest(blocks);
}

}  // namespace protocol
}  // namespace transport
