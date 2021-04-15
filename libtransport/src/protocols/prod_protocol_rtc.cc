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

#include <hicn/transport/core/global_object_pool.h>
#include <implementation/socket_producer.h>
#include <protocols/prod_protocol_rtc.h>
#include <protocols/rtc/rtc_consts.h>
#include <stdlib.h>
#include <time.h>

#include <unordered_set>

namespace transport {
namespace protocol {

RTCProductionProtocol::RTCProductionProtocol(
    implementation::ProducerSocket *icn_socket)
    : ProductionProtocol(icn_socket),
      current_seg_(1),
      produced_bytes_(0),
      produced_packets_(0),
      max_packet_production_(1),
      bytes_production_rate_(0),
      packets_production_rate_(0),
      last_round_(std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count()),
      allow_delayed_nacks_(false),
      queue_timer_on_(false),
      consumer_in_sync_(false),
      on_consumer_in_sync_(nullptr) {
  srand((unsigned int)time(NULL));
  prod_label_ = rand() % 256;
  interests_queue_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getIoService());
  round_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  setOutputBufferSize(10000);
  scheduleRoundTimer();
}

RTCProductionProtocol::~RTCProductionProtocol() {}

void RTCProductionProtocol::registerNamespaceWithNetwork(
    const Prefix &producer_namespace) {
  ProductionProtocol::registerNamespaceWithNetwork(producer_namespace);

  flow_name_ = producer_namespace.getName();
  auto family = flow_name_.getAddressFamily();

  switch (family) {
    case AF_INET6:
      header_size_ = (uint32_t)Packet::getHeaderSizeFromFormat(HF_INET6_TCP);
      break;
    case AF_INET:
      header_size_ = (uint32_t)Packet::getHeaderSizeFromFormat(HF_INET_TCP);
      break;
    default:
      throw errors::RuntimeException("Unknown name format.");
  }
}

void RTCProductionProtocol::scheduleRoundTimer() {
  round_timer_->expires_from_now(
      std::chrono::milliseconds(rtc::PRODUCER_STATS_INTERVAL));
  round_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    updateStats();
  });
}

void RTCProductionProtocol::updateStats() {
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  uint64_t duration = now - last_round_;
  if (duration == 0) duration = 1;
  double per_second = rtc::MILLI_IN_A_SEC / duration;

  uint32_t prev_packets_production_rate = packets_production_rate_;

  bytes_production_rate_ = ceil((double)produced_bytes_ * per_second);
  packets_production_rate_ = ceil((double)produced_packets_ * per_second);

  TRANSPORT_LOGD("Updating production rate: produced_bytes_ = %u  bps = %u",
                 produced_bytes_, bytes_production_rate_);

  // update the production rate as soon as it increases by 10% with respect to
  // the last round
  max_packet_production_ =
      produced_packets_ + ceil((double)produced_packets_ * 0.1);
  if (max_packet_production_ < rtc::WIN_MIN)
    max_packet_production_ = rtc::WIN_MIN;

  if (packets_production_rate_ != 0) {
    allow_delayed_nacks_ = false;
  } else if (prev_packets_production_rate == 0) {
    // at least 2 rounds with production rate = 0
    allow_delayed_nacks_ = true;
  }

  // check if the production rate is decreased. if yes send nacks if needed
  if (prev_packets_production_rate < packets_production_rate_) {
    sendNacksForPendingInterests();
  }

  produced_bytes_ = 0;
  produced_packets_ = 0;
  last_round_ = now;
  scheduleRoundTimer();
}

uint32_t RTCProductionProtocol::produceStream(
    const Name &content_name, std::unique_ptr<utils::MemBuf> &&buffer,
    bool is_last, uint32_t start_offset) {
  throw errors::NotImplementedException();
}

uint32_t RTCProductionProtocol::produceStream(const Name &content_name,
                                              const uint8_t *buffer,
                                              size_t buffer_size, bool is_last,
                                              uint32_t start_offset) {
  throw errors::NotImplementedException();
}

void RTCProductionProtocol::produce(ContentObject &content_object) {
  throw errors::NotImplementedException();
}

uint32_t RTCProductionProtocol::produceDatagram(
    const Name &content_name, std::unique_ptr<utils::MemBuf> &&buffer) {
  std::size_t buffer_size = buffer->length();
  if (TRANSPORT_EXPECT_FALSE(buffer_size == 0)) return 0;

  uint32_t data_packet_size;
  socket_->getSocketOption(interface::GeneralTransportOptions::DATA_PACKET_SIZE,
                           data_packet_size);

  if (TRANSPORT_EXPECT_FALSE((buffer_size + header_size_ +
                              rtc::DATA_HEADER_SIZE) > data_packet_size)) {
    return 0;
  }

  auto content_object =
      core::PacketManager<>::getInstance().getPacket<ContentObject>();
  // add rtc header to the payload
  struct rtc::data_packet_t header;
  content_object->appendPayload((const uint8_t *)&header,
                                rtc::DATA_HEADER_SIZE);
  content_object->appendPayload(buffer->data(), buffer->length());

  std::shared_ptr<ContentObject> co = std::move(content_object);

  // schedule actual sending on internal thread
  portal_->getIoService().dispatch(
      [this, content_object{std::move(co)}, content_name]() mutable {
        produceInternal(std::move(content_object), content_name);
      });

  return 1;
}

void RTCProductionProtocol::produceInternal(
    std::shared_ptr<ContentObject> &&content_object, const Name &content_name) {
  // set rtc header
  struct rtc::data_packet_t *data_pkt =
      (struct rtc::data_packet_t *)content_object->getPayload()->data();
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  data_pkt->setTimestamp(now);
  data_pkt->setProductionRate(bytes_production_rate_);

  // set hicn stuff
  Name n(content_name);
  content_object->setName(n.setSuffix(current_seg_));
  content_object->setLifetime(500);  // XXX this should be set by the APP
  content_object->setPathLabel(prod_label_);

  // update stats
  produced_bytes_ +=
      content_object->headerSize() + content_object->payloadSize();
  produced_packets_++;

  if (produced_packets_ >= max_packet_production_) {
    // in this case all the pending interests may be used to accomodate the
    // sudden increase in the production rate. calling the updateStats we will
    // notify all the clients
    round_timer_->cancel();
    updateStats();
  }

  TRANSPORT_LOGD("Sending content object: %s", n.toString().c_str());

  output_buffer_.insert(content_object);

  if (*on_content_object_in_output_buffer_) {
    on_content_object_in_output_buffer_->operator()(*socket_->getInterface(),
                                                    *content_object);
  }

  portal_->sendContentObject(*content_object);

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          *content_object);
  }

  // remove interests from the interest cache if it exists
  removeFromInterestQueue(current_seg_);

  current_seg_ = (current_seg_ + 1) % rtc::MIN_PROBE_SEQ;
}

void RTCProductionProtocol::onInterest(Interest &interest) {
  uint32_t interest_seg = interest.getName().getSuffix();
  uint32_t lifetime = interest.getLifetime();

  if (interest_seg == 0) {
    // first packet from the consumer, reset sync state
    consumer_in_sync_ = false;
  }

  if (*on_interest_input_) {
    on_interest_input_->operator()(*socket_->getInterface(), interest);
  }

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  if (interest_seg > rtc::MIN_PROBE_SEQ) {
    sendNack(interest_seg);
    return;
  }

  TRANSPORT_LOGD("received interest %u", interest_seg);

  const std::shared_ptr<ContentObject> content_object =
      output_buffer_.find(interest);

  if (content_object) {
    if (*on_interest_satisfied_output_buffer_) {
      on_interest_satisfied_output_buffer_->operator()(*socket_->getInterface(),
                                                       interest);
    }

    if (*on_content_object_output_) {
      on_content_object_output_->operator()(*socket_->getInterface(),
                                            *content_object);
    }

    TRANSPORT_LOGD("Send content %u (onInterest)",
                   content_object->getName().getSuffix());
    portal_->sendContentObject(*content_object);
    return;
  } else {
    if (*on_interest_process_) {
      on_interest_process_->operator()(*socket_->getInterface(), interest);
    }
  }

  // if the production rate 0 use delayed nacks
  if (allow_delayed_nacks_ && interest_seg >= current_seg_) {
    uint64_t next_timer = ~0;
    if (!timers_map_.empty()) {
      next_timer = timers_map_.begin()->first;
    }

    uint64_t expiration = now + rtc::SENTINEL_TIMER_INTERVAL;
    addToInterestQueue(interest_seg, expiration);

    // here we have at least one interest in the queue, we need to start or
    // update the timer
    if (!queue_timer_on_) {
      // set timeout
      queue_timer_on_ = true;
      scheduleQueueTimer(timers_map_.begin()->first - now);
    } else {
      // re-schedule the timer because a new interest will expires sooner
      if (next_timer > timers_map_.begin()->first) {
        interests_queue_timer_->cancel();
        scheduleQueueTimer(timers_map_.begin()->first - now);
      }
    }
    return;
  }

  if (queue_timer_on_) {
    // the producer is producing. Send nacks to packets that will expire before
    // the data production and remove the timer
    queue_timer_on_ = false;
    interests_queue_timer_->cancel();
    sendNacksForPendingInterests();
  }

  uint32_t max_gap = (uint32_t)floor(
      (double)((double)((double)lifetime *
                        rtc::INTEREST_LIFETIME_REDUCTION_FACTOR /
                        rtc::MILLI_IN_A_SEC) *
               (double)packets_production_rate_));

  if (interest_seg < current_seg_ || interest_seg > (max_gap + current_seg_)) {
    sendNack(interest_seg);
  } else {
    if (!consumer_in_sync_ && on_consumer_in_sync_) {
      // we consider the remote consumer to be in sync as soon as it covers 70%
      // of the production window with interests
      uint32_t perc = ceil((double)max_gap * 0.7);
      if (interest_seg > (perc + current_seg_)) {
        consumer_in_sync_ = true;
        on_consumer_in_sync_(*socket_->getInterface(), interest);
      }
    }
    uint64_t expiration =
        now + floor((double)lifetime * rtc::INTEREST_LIFETIME_REDUCTION_FACTOR);
    addToInterestQueue(interest_seg, expiration);
  }
}

void RTCProductionProtocol::onError(std::error_code ec) {}

void RTCProductionProtocol::scheduleQueueTimer(uint64_t wait) {
  interests_queue_timer_->expires_from_now(std::chrono::milliseconds(wait));
  interests_queue_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    interestQueueTimer();
  });
}

void RTCProductionProtocol::addToInterestQueue(uint32_t interest_seg,
                                               uint64_t expiration) {
  // check if the seq number exists already
  auto it_seqs = seqs_map_.find(interest_seg);
  if (it_seqs != seqs_map_.end()) {
    // the seq already exists
    if (expiration < it_seqs->second) {
      // we need to update the timer becasue we got a smaller one
      // 1) remove the entry from the multimap
      // 2) update this entry
      auto range = timers_map_.equal_range(it_seqs->second);
      for (auto it_timers = range.first; it_timers != range.second;
           it_timers++) {
        if (it_timers->second == it_seqs->first) {
          timers_map_.erase(it_timers);
          break;
        }
      }
      timers_map_.insert(
          std::pair<uint64_t, uint32_t>(expiration, interest_seg));
      it_seqs->second = expiration;
    } else {
      // nothing to do here
      return;
    }
  } else {
    // add the new seq
    timers_map_.insert(std::pair<uint64_t, uint32_t>(expiration, interest_seg));
    seqs_map_.insert(std::pair<uint32_t, uint64_t>(interest_seg, expiration));
  }
}

void RTCProductionProtocol::sendNacksForPendingInterests() {
  std::unordered_set<uint32_t> to_remove;

  uint32_t packet_gap = 100000;  // set it to a high value (100sec)
  if (packets_production_rate_ != 0)
    packet_gap = ceil(rtc::MILLI_IN_A_SEC / (double)packets_production_rate_);

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  for (auto it = seqs_map_.begin(); it != seqs_map_.end(); it++) {
    if (it->first > current_seg_) {
      uint64_t production_time =
          ((it->first - current_seg_) * packet_gap) + now;
      if (production_time >= it->second) {
        sendNack(it->first);
        to_remove.insert(it->first);
      }
    }
  }

  // delete nacked interests
  for (auto it = to_remove.begin(); it != to_remove.end(); it++) {
    removeFromInterestQueue(*it);
  }
}

void RTCProductionProtocol::removeFromInterestQueue(uint32_t interest_seg) {
  auto seq_it = seqs_map_.find(interest_seg);
  if (seq_it != seqs_map_.end()) {
    auto range = timers_map_.equal_range(seq_it->second);
    for (auto it_timers = range.first; it_timers != range.second; it_timers++) {
      if (it_timers->second == seq_it->first) {
        timers_map_.erase(it_timers);
        break;
      }
    }
    seqs_map_.erase(seq_it);
  }
}

void RTCProductionProtocol::interestQueueTimer() {
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  for (auto it_timers = timers_map_.begin(); it_timers != timers_map_.end();) {
    uint64_t expire = it_timers->first;
    if (expire <= now) {
      uint32_t seq = it_timers->second;
      sendNack(seq);
      // remove the interest from the other map
      seqs_map_.erase(seq);
      it_timers = timers_map_.erase(it_timers);
    } else {
      // stop, we are done!
      break;
    }
  }
  if (timers_map_.empty()) {
    queue_timer_on_ = false;
  } else {
    queue_timer_on_ = true;
    scheduleQueueTimer(timers_map_.begin()->first - now);
  }
}

void RTCProductionProtocol::sendNack(uint32_t sequence) {
  auto nack = core::PacketManager<>::getInstance().getPacket<ContentObject>();
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  uint32_t next_packet = current_seg_;
  uint32_t prod_rate = bytes_production_rate_;

  struct rtc::nack_packet_t header;
  header.setTimestamp(now);
  header.setProductionRate(prod_rate);
  header.setProductionSegement(next_packet);
  nack->appendPayload((const uint8_t *)&header, rtc::NACK_HEADER_SIZE);

  Name n(flow_name_);
  n.setSuffix(sequence);
  nack->setName(n);
  nack->setLifetime(0);
  nack->setPathLabel(prod_label_);

  if (!consumer_in_sync_ && on_consumer_in_sync_ &&
      sequence < rtc::MIN_PROBE_SEQ && sequence > next_packet) {
    consumer_in_sync_ = true;
    auto interest = core::PacketManager<>::getInstance().getPacket<Interest>();
    interest->setName(n);
    on_consumer_in_sync_(*socket_->getInterface(), *interest);
  }

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(), *nack);
  }

  TRANSPORT_LOGD("Send nack %u", sequence);
  portal_->sendContentObject(*nack);
}

}  // namespace protocol

}  // end namespace transport
