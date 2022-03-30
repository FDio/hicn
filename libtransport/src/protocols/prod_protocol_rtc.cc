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
#include <implementation/socket_producer.h>
#include <protocols/prod_protocol_rtc.h>
#include <protocols/rtc/probe_handler.h>
#include <protocols/rtc/rtc_consts.h>
#include <stdlib.h>
#include <time.h>

#include <unordered_set>

namespace transport {
namespace protocol {

using Format = core::Packet::Format;

RTCProductionProtocol::RTCProductionProtocol(
    implementation::ProducerSocket *icn_socket)
    : ProductionProtocol(icn_socket),
      current_seg_(1),
      produced_bytes_(0),
      produced_packets_(0),
      produced_fec_packets_(0),
      max_packet_production_(1),
      bytes_production_rate_(0),
      packets_production_rate_(0),
      fec_packets_production_rate_(0),
      last_produced_data_ts_(0),
      last_round_(utils::SteadyTime::nowMs().count()),
      allow_delayed_nacks_(false),
      queue_timer_on_(false),
      consumer_in_sync_(false),
      on_consumer_in_sync_(nullptr),
      pending_fec_pace_(false),
      max_len_(0),
      queue_len_(0),
      data_aggregation_(true),
      data_aggregation_timer_switch_(false) {
  std::uniform_int_distribution<> dis(0, 255);
  prod_label_ = dis(gen_);
  cache_label_ = (prod_label_ + 1) % 256;
  interests_queue_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  round_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  fec_pacing_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  app_packets_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getThread().getIoService());
  setOutputBufferSize(10000);
}

RTCProductionProtocol::~RTCProductionProtocol() {}

void RTCProductionProtocol::setProducerParam() {
  // Flow name: here we assume there is only one prefix registered in the portal
  flow_name_ = portal_->getServedNamespaces().begin()->getName();

  // Manifest
  uint32_t making_manifest;
  socket_->getSocketOption(interface::GeneralTransportOptions::MAKE_MANIFEST,
                           making_manifest);

  // Signer
  std::shared_ptr<auth::Signer> signer;
  socket_->getSocketOption(interface::GeneralTransportOptions::SIGNER, signer);

  // Default format
  core::Packet::Format default_format;
  socket_->getSocketOption(interface::GeneralTransportOptions::PACKET_FORMAT,
                           default_format);

  // FEC
  using namespace std::placeholders;
  enableFEC(std::bind(&RTCProductionProtocol::onFecPackets, this, _1),
            std::bind(&RTCProductionProtocol::getBuffer, this, _1));

  // Aggregated data
  socket_->getSocketOption(interface::RtcTransportOptions::AGGREGATED_DATA,
                           data_aggregation_);

  size_t signature_size = signer->getSignatureFieldSize();
  data_header_format_ = {
      !making_manifest ? Packet::toAHFormat(default_format) : default_format,
      !making_manifest ? signature_size : 0};
  manifest_header_format_ = {Packet::toAHFormat(default_format),
                             signature_size};
  nack_header_format_ = {Packet::toAHFormat(default_format), signature_size};
  fec_header_format_ = {Packet::toAHFormat(default_format), signature_size};

  // Schedule round timer
  scheduleRoundTimer();
}

void RTCProductionProtocol::scheduleRoundTimer() {
  round_timer_->expires_from_now(
      std::chrono::milliseconds(rtc::PRODUCER_STATS_INTERVAL));
  std::weak_ptr<RTCProductionProtocol> self = shared_from_this();
  round_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) return;

    auto sp = self.lock();
    if (sp && sp->isRunning()) {
      sp->updateStats();
    }
  });
}

void RTCProductionProtocol::updateStats() {
  uint64_t now = utils::SteadyTime::nowMs().count();
  uint64_t duration = now - last_round_;
  if (duration == 0) duration = 1;
  double per_second = rtc::MILLI_IN_A_SEC / duration;

  uint32_t prev_packets_production_rate = packets_production_rate_;

  bytes_production_rate_ = ceil((double)produced_bytes_ * per_second);
  packets_production_rate_ = ceil((double)produced_packets_ * per_second);
  fec_packets_production_rate_ =
      ceil((double)produced_fec_packets_ * per_second);

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Updating production rate: produced_bytes_ = " << produced_bytes_
      << "  bps = " << bytes_production_rate_;

  // update the production rate as soon as it increases by 10% with respect to
  // the last round
  max_packet_production_ =
      produced_packets_ + ceil((double)produced_packets_ * 0.1);
  if (max_packet_production_ < rtc::WIN_MIN)
    max_packet_production_ = rtc::WIN_MIN;

  if (packets_production_rate_ <= rtc::MIN_PRODUCTION_RATE ||
      prev_packets_production_rate <= rtc::MIN_PRODUCTION_RATE) {
    allow_delayed_nacks_ = true;
  } else {
    // at least 2 rounds with enough packets
    allow_delayed_nacks_ = false;
  }

  // check if the production rate is decreased. if yes send nacks if needed
  if (prev_packets_production_rate < packets_production_rate_) {
    sendNacksForPendingInterests();
  }

  produced_bytes_ = 0;
  produced_packets_ = 0;
  produced_fec_packets_ = 0;
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

  if (TRANSPORT_EXPECT_FALSE(
          (Packet::getHeaderSizeFromFormat(data_header_format_.first,
                                           data_header_format_.second) +
           rtc::DATA_HEADER_SIZE + buffer_size) > data_packet_size)) {
    return 0;
  }

  if (!data_aggregation_) {
    // if data aggregation is off emptyQueue will always return doing nothing
    emptyQueue();

    sendManifest(content_name);

    // create content object
    auto content_object =
        core::PacketManager<>::getInstance().getPacket<ContentObject>(
            data_header_format_.first, data_header_format_.second);

    // add rtc header to the payload
    struct rtc::data_packet_t header;
    content_object->appendPayload((const uint8_t *)&header,
                                  rtc::DATA_HEADER_SIZE);
    content_object->appendPayload(buffer->data(), buffer->length());

    // schedule actual sending on internal thread
    portal_->getThread().tryRunHandlerNow(
        [this, content_object{std::move(content_object)},
         content_name]() mutable {
          produceInternal(std::move(content_object), content_name);
        });
  } else {
    // XXX here we assume that all the packets that we push to the queue have
    // the same name
    auto app_pkt = utils::MemBuf::copyBuffer(buffer->data(), buffer->length());
    addPacketToQueue(std::move(app_pkt));
  }

  return 1;
}

void RTCProductionProtocol::addPacketToQueue(
    std::unique_ptr<utils::MemBuf> &&buffer) {
  std::size_t buffer_size = buffer->length();
  if ((queue_len_ + buffer_size) > rtc::MAX_RTC_PAYLOAD_SIZE) {
    emptyQueue();  // this should guaranty that the generated packet will never
                   // be larger than an MTU
  }

  waiting_app_packets_.push(std::move(buffer));
  if (max_len_ < buffer_size) max_len_ = buffer_size;
  queue_len_ += buffer_size;

  if (waiting_app_packets_.size() >= rtc::MAX_AGGREGATED_PACKETS) {
    emptyQueue();
  }

  if (waiting_app_packets_.size() >= 1 && !data_aggregation_timer_switch_) {
    data_aggregation_timer_switch_ = true;
    app_packets_timer_->expires_from_now(
        std::chrono::milliseconds(rtc::AGGREGATED_PACKETS_TIMER));
    std::weak_ptr<RTCProductionProtocol> self = shared_from_this();
    app_packets_timer_->async_wait([self](const std::error_code &ec) {
      if (ec) return;

      auto ptr = self.lock();
      if (ptr && ptr->isRunning()) {
        if (!ptr->data_aggregation_timer_switch_) return;
        ptr->emptyQueue();
      }
    });
  }
}

void RTCProductionProtocol::emptyQueue() {
  if (waiting_app_packets_.size() == 0) return;  // queue is empty

  Name n(flow_name_);

  // cancel timer is scheduled
  if (data_aggregation_timer_switch_) {
    data_aggregation_timer_switch_ = false;
    app_packets_timer_->cancel();
  }

  // send a manifest beforehand if the hash buffer if full
  sendManifest(n);

  // create content object
  auto content_object =
      core::PacketManager<>::getInstance().getPacket<ContentObject>(
          data_header_format_.first, data_header_format_.second);

  // add rtc header to the payload
  struct rtc::data_packet_t header;
  content_object->appendPayload((const uint8_t *)&header,
                                rtc::DATA_HEADER_SIZE);

  // init aggregated header
  rtc::AggrPktHeader hdr(
      (uint8_t *)(content_object->getPayload()->data() + rtc::DATA_HEADER_SIZE),
      max_len_, waiting_app_packets_.size());
  uint32_t header_size = hdr.getHeaderLen();
  content_object->append(header_size);  // leave space for the aggregated header

  uint8_t index = 0;
  while (waiting_app_packets_.size() != 0) {
    std::unique_ptr<utils::MemBuf> pkt =
        std::move(waiting_app_packets_.front());
    waiting_app_packets_.pop();
    // XXX for the moment we have a single name, so this works, otherwise we
    // need to do something else
    hdr.addPacketToHeader(index, pkt->length());
    // append packet
    content_object->appendPayload(pkt->data(), pkt->length());
    index++;
  }

  // reset queue values
  max_len_ = 0;
  queue_len_ = 0;

  // the packet is ready we need to send it
  portal_->getThread().tryRunHandlerNow(
      [this, content_object{std::move(content_object)}, n]() mutable {
        produceInternal(std::move(content_object), n);
      });
}

void RTCProductionProtocol::sendManifest(const Name &name) {
  if (!making_manifest_) {
    return;
  }

  Name manifest_name(name);

  uint32_t data_packet_size;
  socket_->getSocketOption(interface::GeneralTransportOptions::DATA_PACKET_SIZE,
                           data_packet_size);

  // The maximum number of entries a manifest can hold
  uint32_t manifest_capacity = making_manifest_;

  // If there is not enough hashes to fill a manifest, return early
  if (manifest_entries_.size() < manifest_capacity) {
    return;
  }

  // Create a new manifest
  std::shared_ptr<core::ContentObjectManifest> manifest =
      createManifest(manifest_name.setSuffix(current_seg_));

  // Fill the manifest with packet hashes that were previously saved
  uint32_t nb_entries;
  for (nb_entries = 0; nb_entries < manifest_capacity; ++nb_entries) {
    if (manifest_entries_.empty()) {
      break;
    }
    std::pair<uint32_t, auth::CryptoHash> front = manifest_entries_.front();
    manifest->addSuffixHash(front.first, front.second);
    manifest_entries_.pop();
  }

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Sending manifest " << manifest->getName().getSuffix() << " of size "
      << nb_entries;

  // Encode and send the manifest
  manifest->encode();
  portal_->getThread().tryRunHandlerNow(
      [this, content_object{std::move(manifest)}, manifest_name]() mutable {
        produceInternal(std::move(content_object), manifest_name);
      });
}

std::shared_ptr<core::ContentObjectManifest>
RTCProductionProtocol::createManifest(const Name &content_name) const {
  Name name(content_name);

  auth::CryptoHashType hash_algo;
  socket_->getSocketOption(interface::GeneralTransportOptions::HASH_ALGORITHM,
                           hash_algo);

  uint64_t now = utils::SteadyTime::nowMs().count();

  // Create a new manifest
  std::shared_ptr<core::ContentObjectManifest> manifest(
      ContentObjectManifest::createManifest(
          manifest_header_format_.first, name, core::ManifestVersion::VERSION_1,
          core::ManifestType::INLINE_MANIFEST, false, name, hash_algo,
          manifest_header_format_.second));

  // Set connection parameters
  manifest->setParamsRTC(ParamsRTC{
      .timestamp = now,
      .prod_rate = bytes_production_rate_,
      .prod_seg = current_seg_,
      .support_fec = false,
  });

  return manifest;
}

void RTCProductionProtocol::produceInternal(
    std::shared_ptr<ContentObject> &&content_object, const Name &content_name,
    bool fec) {
  uint64_t now = utils::SteadyTime::nowMs().count();

  if (fec && (now - last_produced_data_ts_) < rtc::FEC_PACING_TIME) {
    paced_fec_packets_.push(std::pair<uint64_t, ContentObject::Ptr>(
        now, std::move(content_object)));
    postponeFecPacket();
  } else {
    // need to check if there are FEC packets waiting to be sent
    flushFecPkts(current_seg_);
    producePktInternal(std::move(content_object), content_name, fec);
  }
}

void RTCProductionProtocol::producePktInternal(
    std::shared_ptr<ContentObject> &&content_object, const Name &content_name,
    bool fec) {
  bool is_manifest = content_object->getPayloadType() == PayloadType::MANIFEST;
  uint64_t now = utils::SteadyTime::nowMs().count();

  // set rtc header
  if (!is_manifest) {
    struct rtc::data_packet_t *data_pkt =
        (struct rtc::data_packet_t *)content_object->getPayload()->data();
    data_pkt->setTimestamp(now);
    data_pkt->setProductionRate(bytes_production_rate_);
  }

  // set hicn stuff
  Name n(content_name);
  content_object->setName(n.setSuffix(current_seg_));
  content_object->setLifetime(500);  // XXX this should be set by the APP
  content_object->setPathLabel(prod_label_);

  // update stats
  if (!fec) {
    produced_bytes_ +=
        content_object->headerSize() + content_object->payloadSize();
    produced_packets_++;
  } else {
    produced_fec_packets_++;
  }

  if (!data_aggregation_ && produced_packets_ >= max_packet_production_) {
    // in this case all the pending interests may be used to accomodate the
    // sudden increase in the production rate. calling the updateStats we will
    // notify all the clients
    round_timer_->cancel();
    updateStats();
  }

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Sending content object: " << n << ", is fec: " << fec;

  // pass packet to FEC encoder
  if (fec_encoder_ && !fec) {
    uint32_t offset =
        is_manifest ? content_object->headerSize()
                    : content_object->headerSize() + rtc::DATA_HEADER_SIZE;
    uint32_t metadata = static_cast<uint32_t>(content_object->getPayloadType());

    fec_encoder_->onPacketProduced(*content_object, offset, metadata);
  }

  output_buffer_.insert(content_object);

  if (*on_content_object_in_output_buffer_) {
    on_content_object_in_output_buffer_->operator()(*socket_->getInterface(),
                                                    *content_object);
  }

  auto seq_it = seqs_map_.find(current_seg_);
  if (seq_it != seqs_map_.end()) {
    sendContentObject(content_object, false, fec);
  }

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          *content_object);
  }

  // remove interests from the interest cache if it exists
  removeFromInterestQueue(current_seg_);

  if (!fec) last_produced_data_ts_ = now;

  // Update current segment
  current_seg_ = (current_seg_ + 1) % rtc::MIN_PROBE_SEQ;

  // Publish FEC packets if available
  if (fec_encoder_ && !fec) {
    while (!fec && pending_fec_packets_.size()) {
      auto &co = pending_fec_packets_.front();
      produceInternal(std::move(co), flow_name_, true);
      pending_fec_packets_.pop();
    }
  }
}

void RTCProductionProtocol::flushFecPkts(uint32_t current_seq_num) {
  // Currently we immediately send all the pending fec packets
  // A pacing policy may be helpful, but we do not want to delay too much
  // the packets at this moment.
  while (paced_fec_packets_.size() > 0) {
    producePktInternal(std::move(paced_fec_packets_.front().second), flow_name_,
                       true);
    paced_fec_packets_.pop();
  }
  fec_pacing_timer_->cancel();
  pending_fec_pace_ = false;
  postponeFecPacket();
}

void RTCProductionProtocol::postponeFecPacket() {
  if (paced_fec_packets_.size() == 0) return;
  if (pending_fec_pace_) {
    return;
  }

  uint64_t produced_time = paced_fec_packets_.front().first;
  uint64_t now = utils::SteadyTime::nowMs().count();

  uint64_t wait_time = 0;
  if ((produced_time + rtc::FEC_PACING_TIME) > now)
    wait_time = produced_time + rtc::FEC_PACING_TIME - now;

  fec_pacing_timer_->expires_from_now(std::chrono::milliseconds(wait_time));
  pending_fec_pace_ = true;

  std::weak_ptr<RTCProductionProtocol> self = shared_from_this();
  fec_pacing_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) return;

    auto sp = self.lock();
    if (sp && sp->isRunning()) {
      if (!sp->pending_fec_pace_) return;

      if (sp->paced_fec_packets_.size() > 0) {
        sp->producePktInternal(std::move(sp->paced_fec_packets_.front().second),
                               sp->flow_name_, true);
        sp->paced_fec_packets_.pop();
      }
      sp->pending_fec_pace_ = false;
      sp->postponeFecPacket();
    }
  });
}

void RTCProductionProtocol::onInterest(Interest &interest) {
  if (*on_interest_input_) {
    on_interest_input_->operator()(*socket_->getInterface(), interest);
  }

  auto suffix = interest.firstSuffix();
  // numberOfSuffixes returns only the prefixes in the payalod
  // we add + 1 to count also the seq in the name
  auto n_suffixes = interest.numberOfSuffixes() + 1;
  Name name = interest.getName();
  bool prev_consumer_state = consumer_in_sync_;

  for (uint32_t i = 0; i < n_suffixes; i++) {
    if (i > 0) {
      name.setSuffix(*(suffix + (i - 1)));
    }

    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received interest " << name;

    const std::shared_ptr<ContentObject> content_object =
        output_buffer_.find(name);

    if (content_object) {
      if (*on_interest_satisfied_output_buffer_) {
        on_interest_satisfied_output_buffer_->operator()(
            *socket_->getInterface(), interest);
      }

      if (*on_content_object_output_) {
        on_content_object_output_->operator()(*socket_->getInterface(),
                                              *content_object);
      }

      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Send content %u (onInterest) " << content_object->getName();
      content_object->setPathLabel(cache_label_);
      sendContentObject(content_object);
    } else {
      if (*on_interest_process_) {
        on_interest_process_->operator()(*socket_->getInterface(), interest);
      }
      processInterest(name.getSuffix(), interest.getLifetime());
    }
  }

  if (prev_consumer_state != consumer_in_sync_ && consumer_in_sync_)
    on_consumer_in_sync_(*socket_->getInterface(), interest);
}

void RTCProductionProtocol::processInterest(uint32_t interest_seg,
                                            uint32_t lifetime) {
  if (interest_seg == 0) {
    // first packet from the consumer, reset sync state
    consumer_in_sync_ = false;
  }

  uint64_t now = utils::SteadyTime::nowMs().count();

  switch (rtc::ProbeHandler::getProbeType(interest_seg)) {
    case rtc::ProbeType::INIT:
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received init probe " << interest_seg;
      sendManifestProbe(interest_seg);
      return;
    case rtc::ProbeType::RTT:
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "Received RTT probe " << interest_seg;
      sendNack(interest_seg);
      return;
    default:
      break;
  }

  // if the production rate 0 use delayed nacks
  if (allow_delayed_nacks_ && interest_seg >= current_seg_) {
    uint64_t next_timer = ~0;
    if (!timers_map_.empty()) {
      next_timer = timers_map_.begin()->first;
    }

    uint64_t expiration = now + rtc::NACK_DELAY;
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
    // the producer is producing. Send nacks to packets that will expire
    // before the data production and remove the timer
    queue_timer_on_ = false;
    interests_queue_timer_->cancel();
    sendNacksForPendingInterests();
  }

  uint32_t max_gap = (uint32_t)floor(
      (double)((double)((double)lifetime *
                        rtc::INTEREST_LIFETIME_REDUCTION_FACTOR /
                        rtc::MILLI_IN_A_SEC) *
               (double)(packets_production_rate_ +
                        fec_packets_production_rate_)));

  if (interest_seg < current_seg_ || interest_seg > (max_gap + current_seg_)) {
    sendNack(interest_seg);
  } else {
    if (!consumer_in_sync_ && on_consumer_in_sync_) {
      // we consider the remote consumer to be in sync as soon as it covers
      // 70% of the production window with interests
      uint32_t perc = ceil((double)max_gap * 0.7);
      if (interest_seg > (perc + current_seg_)) {
        consumer_in_sync_ = true;
        // on_consumer_in_sync_(*socket_->getInterface(), interest);
      }
    }
    uint64_t expiration =
        now + floor((double)lifetime * rtc::INTEREST_LIFETIME_REDUCTION_FACTOR);
    addToInterestQueue(interest_seg, expiration);
  }
}

void RTCProductionProtocol::scheduleQueueTimer(uint64_t wait) {
  interests_queue_timer_->expires_from_now(std::chrono::milliseconds(wait));
  std::weak_ptr<RTCProductionProtocol> self = shared_from_this();
  interests_queue_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) {
      return;
    }

    auto sp = self.lock();
    if (sp && sp->isRunning()) {
      sp->interestQueueTimer();
    }
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

  uint64_t now = utils::SteadyTime::nowMs().count();

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
  uint64_t now = utils::SteadyTime::nowMs().count();

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

void RTCProductionProtocol::sendManifestProbe(uint32_t sequence) {
  Name manifest_name(flow_name_);
  manifest_name.setSuffix(sequence);

  std::shared_ptr<core::ContentObjectManifest> manifest_probe =
      createManifest(manifest_name);

  manifest_probe->setLifetime(0);
  manifest_probe->setPathLabel(prod_label_);
  manifest_probe->encode();

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          *manifest_probe);
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send init probe " << sequence;
  sendContentObject(manifest_probe, true, false);
}

void RTCProductionProtocol::sendNack(uint32_t sequence) {
  auto nack = core::PacketManager<>::getInstance().getPacket<ContentObject>(
      nack_header_format_.first, nack_header_format_.second);
  uint64_t now = utils::SteadyTime::nowMs().count();
  uint32_t next_packet = current_seg_;
  uint32_t prod_rate = bytes_production_rate_;

  struct rtc::nack_packet_t header;
  header.setTimestamp(now);
  header.setProductionRate(prod_rate);
  header.setProductionSegment(next_packet);
  nack->appendPayload((const uint8_t *)&header, rtc::NACK_HEADER_SIZE);

  Name n(flow_name_);
  n.setSuffix(sequence);
  nack->setName(n);
  nack->setLifetime(0);
  nack->setPathLabel(prod_label_);

  if (!consumer_in_sync_ && on_consumer_in_sync_ &&
      rtc::ProbeHandler::getProbeType(sequence) == rtc::ProbeType::NOT_PROBE &&
      sequence > next_packet) {
    consumer_in_sync_ = true;
    Packet::Format format;
    socket_->getSocketOption(interface::GeneralTransportOptions::PACKET_FORMAT,
                             format);

    auto interest =
        core::PacketManager<>::getInstance().getPacket<Interest>(format);
    interest->setName(n);
    on_consumer_in_sync_(*socket_->getInterface(), *interest);
  }

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(), *nack);
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send nack " << sequence;
  sendContentObject(nack, true, false);
}

void RTCProductionProtocol::sendContentObject(
    std::shared_ptr<ContentObject> content_object, bool nack, bool fec) {
  bool is_ah = _is_ah(content_object->getFormat());

  // Compute signature
  if (is_ah) {
    signer_->signPacket(content_object.get());
  }

  portal_->sendContentObject(*content_object);

  // Compute and save data packet digest
  if (making_manifest_ && !is_ah) {
    auth::CryptoHashType hash_algo;
    socket_->getSocketOption(interface::GeneralTransportOptions::HASH_ALGORITHM,
                             hash_algo);
    manifest_entries_.push({content_object->getName().getSuffix(),
                            content_object->computeDigest(hash_algo)});
  }
}

void RTCProductionProtocol::onFecPackets(fec::BufferArray &packets) {
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Produced " << packets.size() << " FEC packets";

  for (auto &packet : packets) {
    auto content_object =
        std::static_pointer_cast<ContentObject>(packet.getBuffer());
    content_object->prepend(content_object->headerSize() +
                            rtc::DATA_HEADER_SIZE);
    pending_fec_packets_.push(std::move(content_object));
  }
}

fec::buffer RTCProductionProtocol::getBuffer(std::size_t size) {
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Asked buffer for FEC symbol of size " << size;

  auto ret = core::PacketManager<>::getInstance().getPacket<ContentObject>(
      fec_header_format_.first, fec_header_format_.second);

  ret->updateLength(rtc::DATA_HEADER_SIZE + size);
  ret->append(rtc::DATA_HEADER_SIZE + size);
  ret->trimStart(ret->headerSize() + rtc::DATA_HEADER_SIZE);

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Responding with buffer of length " << ret->length();
  DCHECK(ret->length() >= size);

  return ret;
}

}  // namespace protocol

}  // namespace transport
