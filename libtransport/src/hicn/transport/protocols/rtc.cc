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

#include <math.h>

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/rtc.h>

/*
 * TODO
 * 2) start/constructor/rest variable implementation
 * 3) interest retransmission: now I always recover, we should recover only if
 * we have enough time 4) returnContentToUser: rememeber to remove the first
 * 32bits from the payload
 */

namespace transport {

namespace protocol {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(BaseSocket *icnet_socket)
    : TransportProtocol(icnet_socket),
      inflightInterests_(1 << default_values::log_2_default_buffer_size),
      modMask_((1 << default_values::log_2_default_buffer_size) - 1) {
  icnet_socket->getSocketOption(PORTAL, portal_);
  reset();
}

RTCTransportProtocol::~RTCTransportProtocol() {
  if (is_running_) {
    stop();
  }
}

void RTCTransportProtocol::start(
    utils::SharableVector<uint8_t> &content_buffer) {
  if (is_running_) return;

  is_running_ = true;
  content_buffer_ = content_buffer.shared_from_this();

  reset();
  scheduleNextInterest();

  portal_->runEventsLoop();
  is_running_ = false;
}

void RTCTransportProtocol::stop() {
  if (!is_running_) return;

  is_running_ = false;
  portal_->stopEventsLoop();
}

void RTCTransportProtocol::resume() {
  if (is_running_) return;

  is_running_ = true;

  lastRoundBegin_ = std::chrono::steady_clock::now();
  inflightInterestsCount_ = 0;
  if (content_buffer_) content_buffer_->clear();

  scheduleNextInterest();

  portal_->runEventsLoop();

  is_running_ = false;
}

void RTCTransportProtocol::onRTCPPacket(uint8_t *packet, size_t len) {
  //#define MASK_RTCP_VERSION 192
  //#define MASK_TYPE_CODE 31
  size_t read = 0;
  uint8_t *offset = packet;
  while (read < len) {
    if ((((*offset) & HICN_MASK_RTCP_VERSION) >> 6) != HICN_RTCP_VERSION) {
      TRANSPORT_LOGE("error while parsing RTCP packet, version unkwown");
      return;
    }
    processRtcpHeader(offset);
    uint16_t RTCPlen = (ntohs(*(((uint16_t *)offset) + 1)) + 1) * 4;
    offset += RTCPlen;
    read += RTCPlen;
  }
}

// private
void RTCTransportProtocol::reset() {
  portal_->setConsumerCallback(this);
  // controller var
  lastRoundBegin_ = std::chrono::steady_clock::now();
  currentState_ = HICN_RTC_SYNC_STATE;

  // cwin var
  currentCWin_ = HICN_INITIAL_CWIN;
  maxCWin_ = HICN_INITIAL_CWIN_MAX;

  // names/packets var
  actualSegment_ = 0;
  inflightInterestsCount_ = 0;
  while (interestRetransmissions_.size() != 0) interestRetransmissions_.pop();
  nackedByProducer_.clear();
  nackedByProducerMaxSize_ = 512;
  if (content_buffer_) content_buffer_->clear();

  // stats
  receivedBytes_ = 0;
  sentInterest_ = 0;
  receivedData_ = 0;
  packetLost_ = 0;
  avgPacketSize_ = HICN_INIT_PACKET_SIZE;
  gotNack_ = false;
  gotFutureNack_ = 0;
  roundsWithoutNacks_ = 0;
  pathTable_.clear();
  // roundCounter_ = 0;
  // minRTTwin_.clear();
  // for (int i = 0; i < MIN_RTT_WIN; i++)
  //    minRTTwin_.push_back(UINT_MAX);
  minRtt_ = UINT_MAX;

  // CC var
  estimatedBw_ = 0.0;
  lossRate_ = 0.0;
  queuingDelay_ = 0.0;
  protocolState_ = HICN_RTC_NORMAL_STATE;

  producerPathLabel_ = 0;
  socket_->setSocketOption(
      GeneralTransportOptions::INTEREST_LIFETIME,
      (uint32_t)
          HICN_RTC_INTEREST_LIFETIME);
                  // XXX this should bedone by the application
}

uint32_t max(uint32_t a, uint32_t b) {
  if (a > b)
    return a;
  else
    return b;
}

uint32_t min(uint32_t a, uint32_t b) {
  if (a < b)
    return a;
  else
    return b;
}

void RTCTransportProtocol::checkRound() {
  uint32_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - lastRoundBegin_)
                          .count();
  if (duration >= HICN_ROUND_LEN) {
    lastRoundBegin_ = std::chrono::steady_clock::now();
    updateStats(duration);  // update stats and window
  }
}

void RTCTransportProtocol::updateDelayStats(
    const ContentObject &content_object) {
  uint32_t segmentNumber = content_object.getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;

  if (inflightInterests_[pkt].transmissionTime ==
      0)  // this is always the case if we have a retransmitted packet (timeout
          // or RTCP)
    return;

  uint32_t pathLabel = content_object.getPathLabel();

  if (pathTable_.find(pathLabel) == pathTable_.end()) {
    // found a new path
    std::shared_ptr<RTCDataPath> newPath = std::make_shared<RTCDataPath>();
    pathTable_[pathLabel] = newPath;
  }

  // RTT measurements are useful both from NACKs and data packets
  uint64_t RTT = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count() -
                 inflightInterests_[pkt].transmissionTime;

  pathTable_[pathLabel]->insertRttSample(RTT);

  // we collect OWD only for datapackets
  if (content_object.getPayload().length() != HICN_NACK_HEADER_SIZE) {
    uint64_t *senderTimeStamp = (uint64_t *)content_object.getPayload().data();

    int64_t OWD = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count() -
                  *senderTimeStamp;

    pathTable_[pathLabel]->insertOwdSample(OWD);
  }
}

void RTCTransportProtocol::updateStats(uint32_t round_duration) {
  if (receivedBytes_ != 0) {
    double bytesPerSec = (double)(receivedBytes_ *
                          ((double) HICN_MILLI_IN_A_SEC /
                          (double)round_duration));
    estimatedBw_ = (estimatedBw_ * HICN_ESTIMATED_BW_ALPHA) +
                   ((1 - HICN_ESTIMATED_BW_ALPHA) * bytesPerSec);
  }

  auto it = pathTable_.find(producerPathLabel_);
  if (it == pathTable_.end()) return;

  // double maxAvgRTT = it->second->getAverageRtt();
  // double minRTT = it->second->getMinRtt();
  minRtt_ = it->second->getMinRtt();
  queuingDelay_ = it->second->getQueuingDealy();

  if (minRtt_ == 0) minRtt_ = 1;

  for (auto it = pathTable_.begin(); it != pathTable_.end(); it++) {
    it->second->roundEnd();
  }

  // this is inefficient but the window is supposed to be small, so it
  // probably makes sense to leave it like this
  // if(minRTT == 0)
  //    minRTT = 1;

  // minRTTwin_[roundCounter_ % MIN_RTT_WIN] = minRTT;
  // minRtt_ = minRTT;
  // for (int i = 0; i < MIN_RTT_WIN; i++)
  //    if(minRtt_ > minRTTwin_[i])
  //        minRtt_ = minRTTwin_[i];

  // roundCounter_++;

  // std::cout << "min RTT " << minRtt_ << " queuing " << queuingDelay_ <<
  // std::endl;

  if (sentInterest_ != 0 && currentState_ == HICN_RTC_NORMAL_STATE) {
    double lossRate = (double)((double)packetLost_ / (double)sentInterest_);
    lossRate_ = lossRate_ * HICN_ESTIMATED_LOSSES_ALPHA +
                (lossRate * (1 - HICN_ESTIMATED_LOSSES_ALPHA));
  }

  if (avgPacketSize_ == 0) avgPacketSize_ = HICN_INIT_PACKET_SIZE;

  uint32_t BDP =
      ceil((estimatedBw_ * (double)((double)minRtt_ /
                (double)HICN_MILLI_IN_A_SEC) *
                HICN_BANDWIDTH_SLACK_FACTOR) /
           avgPacketSize_);
  uint32_t BW = ceil(estimatedBw_);
  computeMaxWindow(BW, BDP);

  // bound also by interest lifitime* production rate
  if (!gotNack_) {
    roundsWithoutNacks_++;
    if (currentState_ == HICN_RTC_SYNC_STATE &&
        roundsWithoutNacks_ >= HICN_ROUNDS_IN_SYNC_BEFORE_SWITCH) {
      currentState_ = HICN_RTC_NORMAL_STATE;
    }
  } else {
    roundsWithoutNacks_ = 0;
  }

  updateCCState();
  updateWindow();

  // in any case we reset all the counters

  gotNack_ = false;
  gotFutureNack_ = 0;
  receivedBytes_ = 0;
  sentInterest_ = 0;
  receivedData_ = 0;
  packetLost_ = 0;
}

void RTCTransportProtocol::updateCCState() {
  // TODO
}

void RTCTransportProtocol::computeMaxWindow(uint32_t productionRate,
                                            uint32_t BDPWin) {
  if (productionRate ==
      0)  // we have no info about the producer, keep the previous maxCWin
    return;

  uint32_t interestLifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           interestLifetime);
  uint32_t maxWaintingInterest = ceil(
      (productionRate / avgPacketSize_) *
      (double)((double)(interestLifetime *
                HICN_INTEREST_LIFETIME_REDUCTION_FACTOR) /
                (double) HICN_MILLI_IN_A_SEC));

  if (currentState_ == HICN_RTC_SYNC_STATE) {
    // in this case we do not limit the window with the BDP, beacuse most likly
    // it is wrong
    maxCWin_ = maxWaintingInterest;
    return;
  }

  // currentState = RTC_NORMAL_STATE
  if (BDPWin != 0) {
    maxCWin_ = ceil((double)BDPWin + ((double)BDPWin / 10.0));  // BDP + 10%
  } else {
    maxCWin_ = min(maxWaintingInterest, maxCWin_);
  }
}

void RTCTransportProtocol::updateWindow() {
  if (currentState_ == HICN_RTC_SYNC_STATE) return;

  if (currentCWin_ < maxCWin_ * 0.7) {
    currentCWin_ = min(maxCWin_, currentCWin_ * HICN_WIN_INCREASE_FACTOR);
  } else if (currentCWin_ > maxCWin_) {
    currentCWin_ = max(currentCWin_ * HICN_WIN_DECREASE_FACTOR, HICN_MIN_CWIN);
  }
}

void RTCTransportProtocol::decreaseWindow() {
  // this is used only in SYNC mode
  if (currentState_ == HICN_RTC_NORMAL_STATE) return;

  if (gotFutureNack_ == 1)
    currentCWin_ =
        min((currentCWin_ - 1), ceil((double)maxCWin_ * 0.66));  // 2/3
  else
    currentCWin_--;

  currentCWin_ = max(currentCWin_, HICN_MIN_CWIN);
}

void RTCTransportProtocol::increaseWindow() {
  // this is used only in SYNC mode
  if (currentState_ == HICN_RTC_NORMAL_STATE) return;

  // we need to be carefull to do not increase the window to much
  if (currentCWin_ < ((double)maxCWin_ * 0.5)) {
    currentCWin_ = currentCWin_ + 1;  // exponential
  } else {
    currentCWin_ = min(
        maxCWin_, ceil(currentCWin_ + (1.0 / (double)currentCWin_)));  // linear
  }
}

void RTCTransportProtocol::sendInterest() {
  Name interest_name;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           interest_name);
  bool isRTX = false;
  // uint32_t sentInt = 0;

  if (interestRetransmissions_.size() > 0) {
    // handle retransmission
    // here we have two possibile retransmissions: retransmissions due to
    // timeouts and retransmissions due to RTCP NACKs. we will send the interest
    // anyway, even if it is pending (this is possible only in the second case)
    uint32_t rtxSeg = interestRetransmissions_.front();
    interestRetransmissions_.pop();

    // a packet recovery means that there was a loss
    packetLost_++;

    uint32_t pkt = rtxSeg & modMask_;
    interest_name.setSuffix(rtxSeg);

    // if the interest is not pending anymore we encrease the retrasnmission
    // counter in order to avoid to handle a recovered packt as a normal one
    if (!portal_->interestIsPending(interest_name)) {
      inflightInterests_[pkt].retransmissions++;
    }

    inflightInterests_[pkt].transmissionTime = 0;
    isRTX = true;
  } else {
    // in this case we send the packet only if it is not pending yet
    interest_name.setSuffix(actualSegment_);
    if (portal_->interestIsPending(interest_name)) {
      actualSegment_++;
      return;
    }

    // sentInt = actualSegment_;
    uint32_t pkt = actualSegment_ & modMask_;
    inflightInterests_[pkt].transmissionTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    inflightInterests_[pkt].retransmissions = 0;
    actualSegment_++;
  }

  auto interest = getInterest();
  interest->setName(interest_name);

  uint32_t interestLifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           interestLifetime);
  interest->setLifetime(uint32_t(interestLifetime));

  ConsumerInterestCallback on_interest_output = VOID_HANDLER;

  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_OUTPUT,
                           on_interest_output);

  if (on_interest_output != VOID_HANDLER) {
    on_interest_output(*dynamic_cast<ConsumerSocket *>(socket_), *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  using namespace std::placeholders;
  portal_->sendInterest(std::move(interest));

  sentInterest_++;

  if (!isRTX) {
    inflightInterestsCount_++;
  }
}

void RTCTransportProtocol::scheduleNextInterest() {
  checkRound();
  if (!is_running_) return;

  while (interestRetransmissions_.size() > 0) {
    sendInterest();
    checkRound();
  }

  while (inflightInterestsCount_ < currentCWin_) {
    sendInterest();
    checkRound();
  }
}

void RTCTransportProtocol::scheduleAppNackRtx(std::vector<uint32_t> &nacks) {
  for (uint32_t i = 0; i < nacks.size(); i++) {
    if (nackedByProducer_.find(nacks[i]) != nackedByProducer_.end()) {
      continue;
    }
    // packetLost_++;
    // XXX here I need to avoid the retrasmission for packet that were nacked by
    // the network
    interestRetransmissions_.push(nacks[i]);
  }

  scheduleNextInterest();
}
void RTCTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  // packetLost_++;

  uint32_t segmentNumber = interest->getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;

  if (inflightInterests_[pkt].retransmissions == 0) {
    inflightInterestsCount_--;
  }

  if (inflightInterests_[pkt].retransmissions < HICN_MAX_RTX) {
    interestRetransmissions_.push(segmentNumber);
  }

  scheduleNextInterest();
}

void RTCTransportProtocol::onNack(const ContentObject &content_object) {
  uint32_t *payload = (uint32_t *)content_object.getPayload().data();
  uint32_t productionSeg = *payload;
  uint32_t productionRate = *(++payload);
  uint32_t nackSegment = content_object.getName().getSuffix();

  // we synch the estimated production rate with the actual one
  estimatedBw_ = (double)productionRate;

  // if(inflightInterests_[segmentNumber %
  // default_values::default_buffer_size].retransmissions != 0){ ignore nacks
  // for retransmissions
  //    return;
  //}

  gotNack_ = true;

  if (productionSeg > nackSegment) {
    // we are asking for stuff produced in the past
    actualSegment_ = max(productionSeg + 1, actualSegment_);
    if (currentState_ == HICN_RTC_NORMAL_STATE) {
      currentState_ = HICN_RTC_SYNC_STATE;
    }

    computeMaxWindow(productionRate, 0);
    increaseWindow();

    if (nackedByProducer_.size() >= nackedByProducerMaxSize_)
      nackedByProducer_.erase(nackedByProducer_.begin());
    nackedByProducer_.insert(nackSegment);

  } else if (productionSeg < nackSegment) {
    gotFutureNack_++;
    // we are asking stuff in the future
    // example
    // 10    12    13    14    15    16    17
    //       ^                  ^           ^
    //       in prod            nack        actual
    // in this example we sent up to segment 17 and we get a nack for segment 15
    // this means that we will get nack also for 16 17
    // and valid data for 13 14
    // so the next segment to ask is 15, because 13 and 14 will can back anyway
    // we go back only in the case that the actual segment is really bigger than
    // nack segment, other we do nothing

    actualSegment_ = min(actualSegment_, nackSegment);

    computeMaxWindow(productionRate, 0);
    decreaseWindow();

    if (currentState_ == HICN_RTC_SYNC_STATE) {
      currentState_ = HICN_RTC_NORMAL_STATE;
    }
  }  // equal should not happen
}

void RTCTransportProtocol::onContentObject(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  uint32_t payload_size = content_object->getPayload().length();
  uint32_t segmentNumber = content_object->getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;

  if (payload_size == HICN_NACK_HEADER_SIZE) {
    // Nacks always come form the producer, so we set the producerePathLabel_;
    producerPathLabel_ = content_object->getPathLabel();
    if (inflightInterests_[pkt].retransmissions == 0) {
      inflightInterestsCount_--;
      onNack(*content_object);
      updateDelayStats(*content_object);
    }

  } else {
    receivedData_++;

    avgPacketSize_ =
        (HICN_ESTIMATED_PACKET_SIZE * avgPacketSize_) +
        ((1 - HICN_ESTIMATED_PACKET_SIZE) *
        content_object->getPayload().length());

    if (inflightInterests_[pkt].retransmissions == 0) {
      inflightInterestsCount_--;
      // we count only non retransmitted data in order to take into accunt only
      // the transmition rate of the producer
      receivedBytes_ +=
          content_object->headerSize() + content_object->payloadSize();
      updateDelayStats(*content_object);
    }

    returnContentToUser(*content_object);
    increaseWindow();
  }

  scheduleNextInterest();
}

void RTCTransportProtocol::returnContentToUser(
    const ContentObject &content_object) {
  // return content to the user
  Array a = content_object.getPayload();

  uint8_t *start = ((uint8_t *)a.data()) + HICN_TIMESTAMP_SIZE;
  unsigned size = a.length() - HICN_TIMESTAMP_SIZE;

  // set offset between hICN and RTP packets
  uint16_t rtp_seq = ntohs(*(((uint16_t *)start) + 1));
  RTPhICN_offset_ = content_object.getName().getSuffix() - rtp_seq;

  content_buffer_->insert(content_buffer_->end(), start, start + size);

  ConsumerContentCallback on_payload = VOID_HANDLER;
  socket_->getSocketOption(CONTENT_RETRIEVED, on_payload);
  if (on_payload != VOID_HANDLER) {
    on_payload(*dynamic_cast<ConsumerSocket *>(socket_), size,
               std::make_error_code(std::errc(0)));
  }
}

uint32_t RTCTransportProtocol::hICN2RTP(uint32_t hicn_seq) {
  return RTPhICN_offset_ - hicn_seq;
}

uint32_t RTCTransportProtocol::RTP2hICN(uint32_t rtp_seq) {
  return RTPhICN_offset_ + rtp_seq;
}

void RTCTransportProtocol::processRtcpHeader(uint8_t *offset) {
  uint8_t pkt_type = (*(offset + 1));
  switch (pkt_type) {
    case HICN_RTCP_RR:  // Receiver report
      //TRANSPORT_LOGI("got RR packet\n");
      break;
    case HICN_RTCP_SR:  // Sender report
      //TRANSPORT_LOGI("got SR packet\n");
      break;
    case HICN_RTCP_SDES:  // Description
      processSDES(offset);
      break;
    case HICN_RTCP_RTPFB:  // Transport layer FB message
      processGenericNack(offset);
      break;
    case HICN_RTCP_PSFB:
      processPli(offset);
      break;
    default:
      errorParsingRtcpHeader(offset);
  }
}

void RTCTransportProtocol::errorParsingRtcpHeader(uint8_t *offset) {
  uint8_t pt = (*(offset + 1));
  uint8_t code = ((*offset) & HICN_MASK_TYPE_CODE);
  TRANSPORT_LOGE("Received unknwnon RTCP packet. Payload type = %u, code = %u",
                 pt, code);
}

void RTCTransportProtocol::processSDES(uint8_t *offset) {
  uint8_t code = ((*offset) & HICN_MASK_TYPE_CODE);
  switch (code) {
    case HICN_RTCP_SDES_CNAME:
      TRANSPORT_LOGI("got SDES packet: CNAME\n");
      break;
    default:
      errorParsingRtcpHeader(offset);
  }
}

void RTCTransportProtocol::processPli(uint8_t *offset) {
  if (((*offset) & HICN_MASK_TYPE_CODE) != HICN_RTCP_PSFB_PLI) {
    errorParsingRtcpHeader(offset);
    return;
  }

  TRANSPORT_LOGI("got PLI packet\n");
}

void RTCTransportProtocol::processGenericNack(uint8_t *offset) {
  if (((*offset) & HICN_MASK_TYPE_CODE) != HICN_RTCP_RTPFB_GENERIC_NACK) {
    errorParsingRtcpHeader(offset);
    return;
  }

  std::vector<uint32_t> nacks;

  uint16_t header_lines =
      ntohs(*(((uint16_t *)offset) + 1)) -
      2;  // 2 is the number of header 32-bits words - 1 (RFC 4885)
  uint8_t *payload = offset + HICN_RTPC_NACK_HEADER;  // 12 bytes
  for (uint16_t l = header_lines; l > 0; l--) {
    nacks.push_back(RTP2hICN(ntohs(*((uint16_t *)payload))));

    uint16_t BLP = ntohs(*(((uint16_t *)payload) + 1));

    for (int bit = 0; bit < 15; bit++) {  // 16 bits word to scan
      if ((BLP >> bit) & 1) {
        nacks.push_back(RTP2hICN((ntohs(*((uint16_t *)payload)) + bit + 1) %
                                 HICN_MAX_RTCP_SEQ_NUMBER));
      }
    }

    payload += 4;  // go to the next line
  }

  portal_->getIoService().post(std::bind(
      &RTCTransportProtocol::scheduleAppNackRtx, this, std::move(nacks)));
}

}  // end namespace protocol

}  // end namespace transport
