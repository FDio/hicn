/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <hicn/transport/interfaces/rtc_socket_producer.h>
#include <stdlib.h>
#include <time.h>

#define NACK_HEADER_SIZE 8  // bytes
#define TIMESTAMP_LEN 8     // bytes
#define TCP_HEADER_SIZE 20
#define IP6_HEADER_SIZE 40
#define INIT_PACKET_PRODUCTION_RATE 100  // pps random value (almost 1Mbps)
#define STATS_INTERVAL_DURATION 500      // ms
#define INTEREST_LIFETIME_REDUCTION_FACTOR 0.8
#define INACTIVE_TIME \
  500                        // ms without producing before the socket
                             // is considered inactive
#define MILLI_IN_A_SEC 1000  // ms in a second

#define HICN_MAX_DATA_SEQ 0xefffffff

// NACK HEADER
//   +-----------------------------------------+
//   | 4 bytes: current segment in production  |
//   +-----------------------------------------+
//   | 4 bytes: production rate (bytes x sec)  |
//   +-----------------------------------------+
//

// PACKET HEADER
//   +-----------------------------------------+
//   | 8 bytes: TIMESTAMP                      |
//   +-----------------------------------------+
//   | packet                                  |
//   +-----------------------------------------+

namespace transport {

namespace interface {

RTCProducerSocket::RTCProducerSocket(asio::io_service &io_service)
    : ProducerSocket(io_service),
      currentSeg_(1),
      producedBytes_(0),
      producedPackets_(0),
      bytesProductionRate_(INIT_PACKET_PRODUCTION_RATE * 1400),
      packetsProductionRate_(INIT_PACKET_PRODUCTION_RATE),
      perSecondFactor_(MILLI_IN_A_SEC / STATS_INTERVAL_DURATION),
      active_(false) {
  lastStats_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();
  srand((unsigned int)time(NULL));
  prodLabel_ = ((rand() % 255) << 24UL);
}

RTCProducerSocket::RTCProducerSocket()
    : ProducerSocket(),
      currentSeg_(1),
      producedBytes_(0),
      producedPackets_(0),
      bytesProductionRate_(INIT_PACKET_PRODUCTION_RATE * 1400),
      packetsProductionRate_(INIT_PACKET_PRODUCTION_RATE),
      perSecondFactor_(MILLI_IN_A_SEC / STATS_INTERVAL_DURATION),
      active_(false) {
  lastStats_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();
  srand((unsigned int)time(NULL));
  prodLabel_ = ((rand() % 255) << 24UL);
}

RTCProducerSocket::~RTCProducerSocket() {}

void RTCProducerSocket::registerPrefix(const Prefix &producer_namespace) {
  ProducerSocket::registerPrefix(producer_namespace);

  flowName_ = producer_namespace.getName();
  auto family = flowName_.getAddressFamily();

  switch (family) {
    case AF_INET6:
      headerSize_ = (uint32_t)Packet::getHeaderSizeFromFormat(HF_INET6_TCP);
      break;
    case AF_INET:
      headerSize_ = (uint32_t)Packet::getHeaderSizeFromFormat(HF_INET_TCP);
      break;
    default:
      throw errors::RuntimeException("Unknown name format.");
  }
}

void RTCProducerSocket::updateStats(uint32_t packet_size, uint64_t now) {
  producedBytes_ += packet_size;
  producedPackets_++;
  uint64_t duration = now - lastStats_;
  if (duration >= STATS_INTERVAL_DURATION) {
    lastStats_ = now;
    bytesProductionRate_ = producedBytes_ * perSecondFactor_;
    packetsProductionRate_ = producedPackets_ * perSecondFactor_;
    if (packetsProductionRate_.load() == 0) packetsProductionRate_ = 1;
    producedBytes_ = 0;
    producedPackets_ = 0;
  }
}

void RTCProducerSocket::produce(std::unique_ptr<utils::MemBuf> &&buffer) {
  auto buffer_size = buffer->length();

  if (TRANSPORT_EXPECT_FALSE(buffer_size == 0)) {
    return;
  }

  if (TRANSPORT_EXPECT_FALSE((buffer_size + headerSize_ + TIMESTAMP_LEN) >
                             data_packet_size_)) {
    return;
  }

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  {
    utils::SpinLock::Acquire locked(lock_);
    active_ = true;
    lastProduced_ = now;
  }

  updateStats((uint32_t)(buffer_size + headerSize_ + TIMESTAMP_LEN), now);

  ContentObject content_object(flowName_.setSuffix(currentSeg_));

  auto payload = utils::MemBuf::create(TIMESTAMP_LEN);

  memcpy(payload->writableData(), &now, TIMESTAMP_LEN);
  payload->append(TIMESTAMP_LEN);
  payload->prependChain(std::move(buffer));
  content_object.appendPayload(std::move(payload));

  content_object.setLifetime(500);  // XXX this should be set by the APP

  content_object.setPathLabel(prodLabel_);

  if (on_content_object_output_ != VOID_HANDLER) {
    on_content_object_output_(*this, content_object);
  }

  portal_->sendContentObject(content_object);

  currentSeg_ = (currentSeg_ + 1) % HICN_MAX_DATA_SEQ;
}

void RTCProducerSocket::onInterest(Interest::Ptr &&interest) {
  uint32_t interestSeg = interest->getName().getSuffix();
  uint32_t lifetime = interest->getLifetime();

  if (on_interest_input_ != VOID_HANDLER) {
    on_interest_input_(*this, *interest);
  }

  bool isActive;
  {
    utils::SpinLock::Acquire locked(lock_);
    isActive = active_;
    if (isActive) {
      uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();
      if ((now - lastProduced_) > INACTIVE_TIME) {
        // socket is inactive
        active_ = false;
        isActive = false;
      }
    }
  }

  if (TRANSPORT_EXPECT_FALSE(!isActive)) {
    sendNack(*interest, false);
    return;
  }

  if(interestSeg > HICN_MAX_DATA_SEQ){
    sendNack(*interest, isActive);
    return;
  }

  uint32_t max_gap = (uint32_t)floor(
      (double)((double)((double)lifetime * INTEREST_LIFETIME_REDUCTION_FACTOR /
                        1000.0) *
               (double)packetsProductionRate_.load()));

  if (interestSeg < currentSeg_ || interestSeg > (max_gap + currentSeg_)) {
    sendNack(*interest, true);
  }
  // else drop packet
}

void RTCProducerSocket::sendNack(const Interest &interest, bool isActive) {
  auto nack_payload = utils::MemBuf::create(NACK_HEADER_SIZE);
  nack_payload->append(NACK_HEADER_SIZE);
  ContentObject nack;

  nack.appendPayload(std::move(nack_payload));
  nack.setName(interest.getName());

  uint32_t *payload_ptr = (uint32_t *)nack.getPayload()->data();
  *payload_ptr = currentSeg_;

  if (isActive) {
    *(++payload_ptr) = bytesProductionRate_;
  } else {
    *(++payload_ptr) = 0;
  }

  nack.setLifetime(0);
  nack.setPathLabel(prodLabel_);

  if (on_content_object_output_ != VOID_HANDLER) {
    on_content_object_output_(*this, nack);
  }

  portal_->sendContentObject(nack);
}

}  // namespace interface

}  // end namespace transport
