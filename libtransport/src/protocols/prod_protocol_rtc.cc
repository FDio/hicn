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

extern "C" {
#include <hicn/util/bitmap.h>
}

namespace transport {
namespace protocol {

using Format = core::Packet::Format;

RTCProductionProtocol::RTCProductionProtocol(
    implementation::ProducerSocket *icn_socket)
    : ProductionProtocol(icn_socket),
      current_seg_(1),
      prev_produced_bytes_(0),
      prev_produced_packets_(0),
      produced_bytes_(0),
      produced_packets_(0),
      max_packet_production_(UINT32_MAX),
      bytes_production_rate_(UINT32_MAX),
      packets_production_rate_(0),
      last_produced_data_ts_(0),
      last_round_(utils::SteadyTime::nowMs().count()),
      allow_delayed_nacks_(false),
      pending_fec_pace_(false),
      max_len_(0),
      queue_len_(0),
      data_aggregation_(true),
      data_aggregation_timer_switch_(false) {
  std::uniform_int_distribution<> dis(0, 255);
  prod_label_ = dis(gen_);
  cache_label_ = (prod_label_ + 1) % 256;
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
  flow_name_ = portal_->getServedNamespaces().begin()->makeName();

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

  size_t signature_size = signer_->getSignatureFieldSize();
  data_header_format_ = {!manifest_max_capacity_
                             ? Packet::toAHFormat(default_format)
                             : default_format,
                         !manifest_max_capacity_ ? signature_size : 0};
  manifest_header_format_ = {Packet::toAHFormat(default_format),
                             signature_size};
  nack_header_format_ = {Packet::toAHFormat(default_format), signature_size};
  fec_header_format_ = {Packet::toAHFormat(default_format), signature_size};

  // Initialize verifier for aggregated interests
  std::shared_ptr<auth::Verifier> verifier;
  socket_->getSocketOption(implementation::GeneralTransportOptions::VERIFIER,
                           verifier);
  verifier_ = std::make_shared<rtc::RTCVerifier>(verifier, 0, 0);

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
      sp->updateStats(true);
    }
  });
}

void RTCProductionProtocol::updateStats(bool new_round) {
  uint64_t now = utils::SteadyTime::nowMs().count();
  uint64_t duration = now - last_round_;
  if (!new_round) {
    duration += rtc::PRODUCER_STATS_INTERVAL;
  } else {
    prev_produced_bytes_ = 0;
    prev_produced_packets_ = 0;
  }

  double per_second = rtc::MILLI_IN_A_SEC / duration;

  uint32_t prev_packets_production_rate = packets_production_rate_;

  // bytes_production_rate_ does not take into account FEC!!! this is because
  // each client requests a differen amount of FEC packet so the client itself
  // increase the production rate in the right way
  bytes_production_rate_ =
      ceil((double)(produced_bytes_ + prev_produced_bytes_) * per_second);
  packets_production_rate_ =
      ceil((double)(produced_packets_ + prev_produced_packets_) * per_second);

  if (fec_encoder_ && fec_type_ != fec::FECType::UNKNOWN) {
    // add fec packets looking at the fec code. we don't use directly the number
    // of fec packets produced in 1 round because it may happen that different
    // numbers of blocks are generated during the rounds and this creates
    // inconsistencies in the estimation of the production rate
    uint32_t k = fec::FECUtils::getSourceSymbols(fec_type_);
    uint32_t n = fec::FECUtils::getBlockSymbols(fec_type_);

    packets_production_rate_ +=
        ceil((double)packets_production_rate_ / (double)k) * (n - k);
  }

  // update the production rate as soon as it increases by 10% with respect to
  // the last round
  max_packet_production_ =
      produced_packets_ + ceil((double)produced_packets_ * 0.10);
  if (max_packet_production_ < rtc::WIN_MIN)
    max_packet_production_ = rtc::WIN_MIN;

  if (packets_production_rate_ <= rtc::MIN_PRODUCTION_RATE ||
      prev_packets_production_rate <= rtc::MIN_PRODUCTION_RATE) {
    allow_delayed_nacks_ = true;
  } else {
    // at least 2 rounds with enough packets
    allow_delayed_nacks_ = false;
  }

  if (new_round) {
    prev_produced_bytes_ = produced_bytes_;
    prev_produced_packets_ = produced_packets_;
    produced_bytes_ = 0;
    produced_packets_ = 0;
    last_round_ = now;
    scheduleRoundTimer();
  }
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
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Maybe Sending content object: " << content_name;

  if (TRANSPORT_EXPECT_FALSE(buffer_size == 0)) return 0;

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending content object: " << content_name;

  uint32_t data_packet_size;
  socket_->getSocketOption(interface::GeneralTransportOptions::DATA_PACKET_SIZE,
                           data_packet_size);
  // this is a source packet but we check the fec header size of FEC packet in
  // order to leave room for the header when FEC packets will be generated
  uint32_t fec_header = 0;
  if (fec_encoder_) fec_encoder_->getFecHeaderSize(true);
  uint32_t headers_size =
      (uint32_t)Packet::getHeaderSizeFromFormat(data_header_format_.first,
                                                data_header_format_.second) +
      rtc::DATA_HEADER_SIZE + fec_header;
  if (TRANSPORT_EXPECT_FALSE((headers_size + buffer_size) > data_packet_size)) {
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
  if (!manifest_max_capacity_) {
    return;
  }

  Name manifest_name = name;

  // If there is not enough hashes to fill a manifest, return early
  if (manifest_entries_.size() < manifest_max_capacity_) {
    return;
  }

  // Create a new manifest
  std::shared_ptr<core::ContentObjectManifest> manifest =
      createManifest(manifest_name.setSuffix(current_seg_));
  auto manifest_co =
      std::dynamic_pointer_cast<ContentObject>(manifest->getPacket());

  // Fill the manifest with packet hashes that were previously saved
  uint32_t nb_entries;
  for (nb_entries = 0; nb_entries < manifest_max_capacity_; ++nb_entries) {
    if (manifest_entries_.empty()) {
      break;
    }
    std::pair<uint32_t, auth::CryptoHash> front = manifest_entries_.front();
    manifest->addEntry(front.first, front.second);
    manifest_entries_.pop();
  }

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Sending manifest " << manifest_co->getName().getSuffix()
      << " of size " << nb_entries;

  // Encode and send the manifest
  manifest->encode();
  portal_->getThread().tryRunHandlerNow(
      [this, content_object{std::move(manifest_co)}, manifest_name]() mutable {
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
  std::shared_ptr<core::ContentObjectManifest> manifest =
      ContentObjectManifest::createContentManifest(
          manifest_header_format_.first, name, manifest_header_format_.second);
  manifest->setHeaders(core::ManifestType::INLINE_MANIFEST,
                       manifest_max_capacity_, hash_algo, false /* is_last */,
                       name);

  // Set connection parameters
  manifest->setParamsRTC(ParamsRTC{
      .timestamp = now,
      .prod_rate = bytes_production_rate_,
      .prod_seg = current_seg_,
      .fec_type = fec_type_,
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

  uint32_t expiry_time = 0;
  socket_->getSocketOption(
      interface::GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
      expiry_time);
  if (expiry_time == interface::default_values::content_object_expiry_time)
    expiry_time = 500;  // the data expiration time should be set by the App. if
                        // the App does not specify it the default is 500ms
  content_object->setLifetime(expiry_time);
  content_object->setPathLabel(prod_label_);

  // update stats
  if (!fec) {
    produced_bytes_ +=
        content_object->headerSize() + content_object->payloadSize();
    produced_packets_++;
  }

  if (!data_aggregation_ && produced_packets_ >= max_packet_production_) {
    // in this case all the pending interests may be used to accomodate the
    // sudden increase in the production rate. calling the updateStats we will
    // notify all the clients
    updateStats(false);
  }

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Sending content object: " << n << ", is fec: " << fec;

  // pass packet to FEC encoder
  if (fec_encoder_ && !fec) {
    uint32_t offset = is_manifest ? (uint32_t)content_object->headerSize()
                                  : (uint32_t)content_object->headerSize() +
                                        rtc::DATA_HEADER_SIZE;
    uint32_t metadata = static_cast<uint32_t>(content_object->getPayloadType());

    fec_encoder_->onPacketProduced(*content_object, offset, metadata);
  }

  output_buffer_.insert(content_object);

  if (*on_content_object_in_output_buffer_) {
    on_content_object_in_output_buffer_->operator()(*socket_->getInterface(),
                                                    *content_object);
  }

  // TODO we may want to send FEC only if an interest is pending in the pit in
  sendContentObject(content_object, false, fec);

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          *content_object);
  }

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

  if (!interest.isValid()) throw std::runtime_error("Bad interest format");
  if (interest.hasManifest() &&
      verifier_->verify(interest) != auth::VerificationPolicy::ACCEPT)
    throw std::runtime_error("Interset manifest verification failed");

  uint32_t *suffix = interest.firstSuffix();
  uint32_t n_suffixes_in_manifest = interest.numberOfSuffixes();
  hicn_uword *request_bitmap = interest.getRequestBitmap();

  Name name = interest.getName();
  uint32_t pos = 0;  // Position of current suffix in manifest

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Received interest " << name << " (" << n_suffixes_in_manifest
      << " suffixes in manifest)";

  // Process the suffix in the interest header
  // (first loop iteration), then suffixes in the manifest
  do {
    if (!interest.hasManifest() ||
        bitmap_is_set_no_check(request_bitmap, pos)) {
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

    // Retrieve next suffix in the manifest
    if (interest.hasManifest()) {
      uint32_t seq = *suffix;
      suffix++;

      name.setSuffix(seq);
      interest.setName(name);
    }
  } while (pos++ < n_suffixes_in_manifest);
}

void RTCProductionProtocol::processInterest(uint32_t interest_seg,
                                            uint32_t lifetime) {
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

  if (interest_seg < current_seg_) sendNack(interest_seg);
}

void RTCProductionProtocol::sendManifestProbe(uint32_t sequence) {
  Name manifest_name(flow_name_);
  manifest_name.setSuffix(sequence);

  std::shared_ptr<core::ContentObjectManifest> manifest_probe =
      createManifest(manifest_name);
  auto manifest_probe_co =
      std::dynamic_pointer_cast<ContentObject>(manifest_probe->getPacket());

  manifest_probe_co->setLifetime(0);
  manifest_probe_co->setPathLabel(prod_label_);
  manifest_probe->encode();

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          *manifest_probe_co);
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send init probe " << sequence;
  sendContentObject(manifest_probe_co, true, false);
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
  if (manifest_max_capacity_ && !is_ah) {
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
