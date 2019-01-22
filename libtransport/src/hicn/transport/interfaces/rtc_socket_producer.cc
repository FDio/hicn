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

// NACK HEADER
//   +-----------------------------------------+
//   | 4 bytes: current segment in production  |
//   +-----------------------------------------+
//   | 4 bytes: production rate (bytes x sec)  |
//   +-----------------------------------------+
//   may require additional field (Rate for multiple qualities, ...)
//

namespace transport {

namespace interface {

RTCProducerSocket::RTCProducerSocket(asio::io_service &io_service)
    : ProducerSocket(io_service),
      currentSeg_(1),
      nack_(std::make_shared<ContentObject>()),
      producedBytes_(0),
      producedPackets_(0),
      bytesProductionRate_(0),
      packetsProductionRate_(INIT_PACKET_PRODUCTION_RATE),
      perSecondFactor_(1000 / STATS_INTERVAL_DURATION) {
  auto nack_payload = utils::MemBuf::create(NACK_HEADER_SIZE);
  nack_payload->append(NACK_HEADER_SIZE);
  nack_->appendPayload(std::move(nack_payload));
  lastStats_ = std::chrono::steady_clock::now();
  srand(time(NULL));
  prodLabel_ = ((rand() % 255) << 24UL);
}

RTCProducerSocket::~RTCProducerSocket() {}

void RTCProducerSocket::registerName(Prefix &producer_namespace) {
  ProducerSocket::registerPrefix(producer_namespace);

  flowName_ = producer_namespace.getName();

  if (flowName_.getType() == HNT_CONTIGUOUS_V4 ||
      flowName_.getType() == HNT_IOV_V4) {
    headerSize_ = sizeof(hicn_v6_hdr_t::ip);
  } else if (flowName_.getType() == HNT_CONTIGUOUS_V6 ||
             flowName_.getType() == HNT_IOV_V6) {
    headerSize_ = sizeof(hicn_v4_hdr_t::ip);
  } else {
    throw errors::RuntimeException("Unknown name format.");
  }

  headerSize_ += TCP_HEADER_SIZE;
}

void RTCProducerSocket::updateStats(uint32_t packet_size) {
  producedBytes_ += packet_size;
  producedPackets_++;
  std::chrono::steady_clock::duration duration =
      std::chrono::steady_clock::now() - lastStats_;
  if (std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() >=
      STATS_INTERVAL_DURATION) {
    lastStats_ = std::chrono::steady_clock::now();
    bytesProductionRate_ = producedBytes_ * perSecondFactor_;
    packetsProductionRate_ = producedPackets_ * perSecondFactor_;
    producedBytes_ = 0;
    producedPackets_ = 0;
  }
}

void RTCProducerSocket::produce(const uint8_t *buf, size_t buffer_size) {
  if (TRANSPORT_EXPECT_FALSE(buffer_size == 0)) {
    return;
  }

  if (TRANSPORT_EXPECT_FALSE((buffer_size + headerSize_ + TIMESTAMP_LEN) >
                             data_packet_size_)) {
    return;
  }

  updateStats(buffer_size + headerSize_ + TIMESTAMP_LEN);

  ContentObject content_object(flowName_.setSuffix(currentSeg_));

  uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

  auto payload = utils::MemBuf::create(buffer_size + TIMESTAMP_LEN);

  memcpy(payload->writableData(), &timestamp, TIMESTAMP_LEN);
  memcpy(payload->writableData() + TIMESTAMP_LEN, buf, buffer_size);
  payload->append(buffer_size + TIMESTAMP_LEN);
  content_object.appendPayload(std::move(payload));

  content_object.setLifetime(1000);  // XXX this should be set by the APP

  content_object.setPathLabel(prodLabel_);
  portal_->sendContentObject(content_object);

  currentSeg_++;
}

void RTCProducerSocket::onInterest(Interest::Ptr &&interest) {
  uint32_t interestSeg = interest->getName().getSuffix();
  uint32_t lifetime = interest->getLifetime();
  uint32_t max_gap;

  // XXX
  // packetsProductionRate_ is modified by another thread in updateStats
  // this should be safe since I just read here. but, you never know.
  max_gap =
      floor((double)((double)((double)lifetime *
                              INTEREST_LIFETIME_REDUCTION_FACTOR / 1000.0) *
                     (double)packetsProductionRate_));

  if (interestSeg < currentSeg_ || interestSeg > (max_gap + currentSeg_)) {
    sendNack(*interest);
  }
  // else drop packet
}

void RTCProducerSocket::sendNack(const Interest &interest) {
  nack_->setName(interest.getName());
  uint32_t *payload_ptr = (uint32_t *)nack_->getPayload().data();
  *payload_ptr = currentSeg_;
  *(++payload_ptr) = bytesProductionRate_;

  nack_->setLifetime(0);
  nack_->setPathLabel(prodLabel_);
  portal_->sendContentObject(*nack_);
}

}  // namespace interface

}  // end namespace transport
