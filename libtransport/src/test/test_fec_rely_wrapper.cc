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
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/utils/log.h>
#include <protocols/fec/rely.h>

#include <queue>

namespace transport {
namespace protocol {

std::string printMissing(
    const std::map<uint32_t, core::ContentObject::Ptr> &missing) {
  std::stringstream stream;

  for (auto &[seq, packet] : missing) {
    stream << " " << seq;
  }

  stream << "\n";

  return stream.str();
}

/**
 * @brief Test encode-decode operations performed using the wrapper for rely
 *
 * @param k Number of source symbols
 * @param n Sum of source symbols and repair symbols
 * @param max_packet_size The max packet size the decoder will expect.
 * @param timeout The timeout used by rely
 * https://rely.steinwurf.com/docs/6.1.0/design/timeout_configuration.html
 * @param max_iterations The number of packets to send
 * @param loss_rate The loss rate
 */
void testRelyEncoderDecoder(uint32_t k, uint32_t n, size_t max_packet_size,
                            int64_t timeout, uint32_t max_iterations,
                            int loss_rate) {
  // Create 1 encoder and 1 decoder
  fec::RelyEncoder _encoder(k, n);
  fec::RelyDecoder _decoder(k, n);

  // Seed the pseudo-random with known value to always get same loss pattern
  srand(k * n);

  // We will interact with rely encoder/decoder using the interface
  fec::ProducerFEC &encoder = _encoder;
  fec::ConsumerFEC &decoder = _decoder;

  // Initialize current iteration
  uint32_t iterations = 0;

  // Packet allocator
  auto &packet_manager = core::PacketManager<>::getInstance();

  // Store packets to verify them in the decoder callback
  std::map<uint32_t, core::ContentObject::Ptr> saved_packets;

  // Save repair packets here in encoder callback
  std::queue<fec::buffer> pending_repair_packets;

  // Set callback called by encoder when a buffer is required.
  encoder.setBufferCallback([](std::size_t size) -> fec::buffer {
    auto ret =
        core::PacketManager<>::getInstance().getPacket<core::ContentObject>();
    ret->updateLength(size);
    ret->append(size);
    ret->trimStart(ret->headerSize());
    assert(ret->length() >= size);

    return ret;
  });

  // Set callback to be called by encoder when repair packets are ready
  encoder.setFECCallback(
      [&](std::vector<std::pair<uint32_t, fec::buffer>> &packets) {
        // We must get n - k symbols
        EXPECT_EQ(packets.size(), n - k);
        // TRANSPORT_LOGD("Got %zu symbols", packets.size());

        // Save symbols in pending_repair_packets queue and increment iterations
        for (auto &packet : packets) {
          ++iterations;
          pending_repair_packets.push(packet.second);
        }
      });

  // Set callback to be called when decoder recover a packet
  decoder.setFECCallback(
      [&](std::vector<std::pair<uint32_t, fec::buffer>> &packets) {
        for (auto &packet : packets) {
          // TRANSPORT_LOGD("Recovering packet %u", packet.first);

          // Ensure recovered packet is in packets actually produced by encoder
          auto original = saved_packets.find(packet.first);
          ASSERT_TRUE(original != saved_packets.end());
          auto &original_packet = *original->second;

          // Remove additional headers at the beginning of the packet. This may
          // change in the future.
          original_packet.trimStart(60 /* Ip + TCP */ + 28 /* Rely header */ +
                                    4 /* Packet size */);

          // Recovered packet should be equal to the original one
          EXPECT_TRUE(original_packet == *packet.second);

          // Restore removed headers
          original_packet.prepend(60 + 28 + 4);

          // Erase packet from saved packet list
          saved_packets.erase(original);
        }
      });

  // Send max_iterations packets from encoder to decoder
  while (iterations < max_iterations) {
    // Create a payload, the size is between 50 and 1350 bytes.
    auto payload_size = 50 + (rand() % 1300);
    uint8_t payload[max_packet_size];
    std::generate(payload, payload + payload_size, rand);

    // Get a packet from global pool and set name
    auto buffer = packet_manager.getPacket<core::ContentObject>();
    buffer->setName(core::Name("b001::abcd", iterations));

    // Get offset
    auto offset = buffer->headerSize();

    // Copy payload into packet. We keep the payload to compare returned packet
    // with original one (since rely encoder does modify the packet by adding
    // its own header).
    buffer->appendPayload(payload, payload_size);

    // Save packet in the saving_packets list
    // TRANSPORT_LOGD("Saving packet with index %lu", iterations);
    saved_packets.emplace(iterations, buffer);

    // Feed buffer into the encoder. This will eventually trigger a call to the
    // FEC callback as soon as k packets are fed into the endocer.
    encoder.onPacketProduced(*buffer, offset);

    // Check returned packet. We calculate the difference in size and we compare
    // only the part of the returned packet corresponding to the original
    // payload. Rely should only add a header and should not modify the actual
    // payload content. If it does it, this check will fail.
    auto diff = buffer->length() - payload_size - offset;
    // TRANSPORT_LOGD("Difference is %zu", diff);
    auto cmp =
        std::memcmp(buffer->data() + offset + diff, payload, payload_size);
    EXPECT_FALSE(cmp);

    // Drop condition. Id addition to the loss rate, we ensure that no drops are
    // perfomed in the last 10% of the total iterations. This is done because
    // rely uses a sliding-window mechanism to recover, and if we suddenly stop
    // we may not be able to recover missing packets that would be recovered
    // using future packets that are not created in the test. For this reason,
    // we ensure the test ends without losses.
#define DROP_CONDITION(loss_rate, max_iterations) \
  (rand() % 100) >= loss_rate || iterations >= max_iterations * 0.9

    // Handle the source packet to the decoder, id drop condition returns true
    if (DROP_CONDITION(loss_rate, max_iterations)) {
      // Pass packet to decoder
      // TRANSPORT_LOGD("Passing packet %u to decoder",
      //                buffer->getName().getSuffix());
      decoder.onDataPacket(*buffer, offset);
    } else {
      // TRANSPORT_LOGD("Packet %u, dropped", buffer->getName().getSuffix());
    }

    // Check if previous call to encoder.consumer() generated repair packets,
    // and if yes, feed them to the decoder.
    while (pending_repair_packets.size()) {
      // Also repair packets can be lost
      if (DROP_CONDITION(loss_rate, max_iterations)) {
        auto &packet = pending_repair_packets.front();
        // TRANSPORT_LOGD("Passing packet %u to decoder", iterations);
        core::ContentObject &co = (core::ContentObject &)(*packet);
        decoder.onDataPacket(co, 0);
      } else {
        // TRANSPORT_LOGD("Packet (repair) %u dropped", iterations);
      }

      // Remove packet from the queue
      pending_repair_packets.pop();
    }

    ++iterations;
  }

  // We expect this test to terminate with a full recover of all the packets and
  // 0.001 residual losses
  EXPECT_LE(saved_packets.size(), iterations * 0.001)
      << printMissing(saved_packets);

  // Reset seed
  srand(time(0));
}

/**
 * @brief Use foreach_rely_fec_type to automatically generate the code of the
 * tests and avoid copy/paste the same function.
 */
#define _(name, k, n)                                                       \
  TEST(RelyTest, RelyK##k##N##n) {                                          \
    int K = k;                                                              \
    int N = n;                                                              \
    uint32_t max_iterations = 1000;                                         \
    int size = 1400;                                                        \
    int64_t timeout = 120;                                                  \
    int loss_rate = 10;                                                     \
    testRelyEncoderDecoder(K, N, size, timeout, max_iterations, loss_rate); \
  }
foreach_rely_fec_type
#undef _

}  // namespace protocol
}  // namespace transport
