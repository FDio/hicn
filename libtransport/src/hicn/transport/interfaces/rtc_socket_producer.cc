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

//slow production rate param
#define MIN_PRODUCTION_RATE 10 // in pacekts per sec. this value is computed
                               // through experiments
#define LIFETIME_FRACTION 0.5

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
      timer_on_(false){
  lastStats_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();
  srand((unsigned int)time(NULL));
  prodLabel_ = ((rand() % 255) << 24UL);
  interests_cache_timer_ = std::make_unique<asio::steady_timer>(
                                           this->getIoService());
}

RTCProducerSocket::RTCProducerSocket()
    : ProducerSocket(),
      currentSeg_(1),
      producedBytes_(0),
      producedPackets_(0),
      bytesProductionRate_(INIT_PACKET_PRODUCTION_RATE * 1400),
      packetsProductionRate_(INIT_PACKET_PRODUCTION_RATE),
      perSecondFactor_(MILLI_IN_A_SEC / STATS_INTERVAL_DURATION),
      timer_on_(false){
  lastStats_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count();
  srand((unsigned int)time(NULL));
  prodLabel_ = ((rand() % 255) << 24UL);
  interests_cache_timer_ = std::make_unique<asio::steady_timer>(
                                           this->getIoService());
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

  //remove interests from the interest cache if it exists
  if(!seqs_map_.empty()){

    utils::SpinLock::Acquire locked(interests_cache_lock_);

    auto it_seqs = seqs_map_.find(currentSeg_);
    if(it_seqs != seqs_map_.end()){
      auto range = timers_map_.equal_range(it_seqs->second);
      for(auto it_timers = range.first; it_timers != range.second; it_timers++){
        if(it_timers->second == it_seqs->first){
          timers_map_.erase(it_timers);
          break;
        }
      }
      seqs_map_.erase(it_seqs);
    }
  }

  currentSeg_ = (currentSeg_ + 1) % HICN_MAX_DATA_SEQ;
}

void RTCProducerSocket::onInterest(Interest::Ptr &&interest) {
  uint32_t interestSeg = interest->getName().getSuffix();
  uint32_t lifetime = interest->getLifetime();

  if (on_interest_input_ != VOID_HANDLER) {
    on_interest_input_(*this, *interest);
  }

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();

  if(interestSeg > HICN_MAX_DATA_SEQ){
    sendNack(interestSeg);
    return;
  }

  // if the production rate is less than MIN_PRODUCTION_RATE we put the
  // interest in a queue, otherwise we handle it in the usual way
  if(packetsProductionRate_.load() < MIN_PRODUCTION_RATE && interestSeg >= currentSeg_){

    utils::SpinLock::Acquire locked(interests_cache_lock_);

    uint64_t next_timer = ~0;
    if(!timers_map_.empty()){
      next_timer = timers_map_.begin()->first;
    }

    uint64_t expiration = now + (lifetime * LIFETIME_FRACTION);
    //check if the seq number exists already
    auto it_seqs = seqs_map_.find(interestSeg);
    if(it_seqs != seqs_map_.end()){
      //the seq already exists
      if(expiration < it_seqs->second){
        // we need to update the timer becasue we got a smaller one
        // 1) remove the entry from the multimap
        // 2) update this entry
        auto range = timers_map_.equal_range(it_seqs->second);
        for(auto it_timers = range.first; it_timers != range.second; it_timers++){
          if(it_timers->second == it_seqs->first){
            timers_map_.erase(it_timers);
            break;
          }
        }
        timers_map_.insert(std::pair<uint64_t,uint32_t>(expiration, interestSeg));
        it_seqs->second = expiration;
      }else{
        //nothing to do here
       return;
      }
    }else{
      // add the new seq
      timers_map_.insert(std::pair<uint64_t,uint32_t>(expiration, interestSeg));
      seqs_map_.insert(std::pair<uint32_t,uint64_t>(interestSeg, expiration));
    }

    //here we have at least one interest in the queue, we need to start or
    //update the timer
    if(!timer_on_){
      //set timeout
      timer_on_ = true;
      scheduleTimer(timers_map_.begin()->first - now);
    } else {
      //re-schedule the timer because a new interest will expires sooner
      if(next_timer > timers_map_.begin()->first){
        interests_cache_timer_->cancel();
        scheduleTimer(timers_map_.begin()->first - now);
      }
    }
    return;
  }

  uint32_t max_gap = (uint32_t)floor(
      (double)((double)((double)lifetime * INTEREST_LIFETIME_REDUCTION_FACTOR /
                        1000.0) *
               (double)packetsProductionRate_.load()));

  if (interestSeg < currentSeg_ || interestSeg > (max_gap + currentSeg_)) {
    sendNack(interestSeg);
  }
  // else drop packet
}

void RTCProducerSocket::scheduleTimer(uint64_t wait){
  interests_cache_timer_->expires_from_now(
             std::chrono::milliseconds(wait));
  interests_cache_timer_->async_wait([this](std::error_code ec) {
      if (ec) return;
      interestCacheTimer();
    });
}

void RTCProducerSocket::interestCacheTimer(){
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now().time_since_epoch())
                  .count();

  utils::SpinLock::Acquire locked(interests_cache_lock_);

  for(auto it_timers = timers_map_.begin(); it_timers != timers_map_.end();){
    uint64_t expire = it_timers->first;
    if(expire <= now){
      uint32_t seq = it_timers->second;
      sendNack(seq);
      //remove the interest from the other map
      seqs_map_.erase(seq);
      it_timers = timers_map_.erase(it_timers);
    }else{
      //stop, we are done!
      break;
    }
  }
  if(timers_map_.empty()){
    timer_on_ = false;
  }else{
    timer_on_ = true;
    scheduleTimer(timers_map_.begin()->first - now);
  }
}

void RTCProducerSocket::sendNack(uint32_t sequence) {
  auto nack_payload = utils::MemBuf::create(NACK_HEADER_SIZE);
  nack_payload->append(NACK_HEADER_SIZE);
  ContentObject nack;

  nack.appendPayload(std::move(nack_payload));
  nack.setName(flowName_.setSuffix(sequence));

  uint32_t *payload_ptr = (uint32_t *)nack.getPayload()->data();
  *payload_ptr = currentSeg_;

  *(++payload_ptr) = bytesProductionRate_.load();

  nack.setLifetime(0);
  nack.setPathLabel(prodLabel_);

  if (on_content_object_output_ != VOID_HANDLER) {
    on_content_object_output_(*this, nack);
  }

  portal_->sendContentObject(nack);
}

}  // namespace interface

}  // end namespace transport
