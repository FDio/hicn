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

namespace transport {

namespace protocol {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(
    interface::ConsumerSocket *icnet_socket)
    : TransportProtocol(icnet_socket),
      inflightInterests_(1 << default_values::log_2_default_buffer_size),
      modMask_((1 << default_values::log_2_default_buffer_size) - 1) {
  icnet_socket->getSocketOption(PORTAL, portal_);
  nack_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  rtx_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  nack_timer_used_ = false;
  reset();
}

RTCTransportProtocol::~RTCTransportProtocol() {
  if (is_running_) {
    stop();
  }
}

int RTCTransportProtocol::start() {
  checkRtx();
  return TransportProtocol::start();
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

  scheduleNextInterests();
  checkRtx();

  portal_->runEventsLoop();

  is_running_ = false;
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
  interestRetransmissions_.clear();
  lastSegNacked_ = 0;
  lastReceived_ = 0;
  nackedByProducer_.clear();
  nackedByProducerMaxSize_ = 512;

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
  minRtt_ = UINT_MAX;

  // CC var
  estimatedBw_ = 0.0;
  lossRate_ = 0.0;
  queuingDelay_ = 0.0;
  protocolState_ = HICN_RTC_NORMAL_STATE;

  producerPathLabel_ = 0;
  socket_->setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           (uint32_t)HICN_RTC_INTEREST_LIFETIME);
  // XXX this should be done by the application
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
  uint32_t duration =
      (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
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

  if (inflightInterests_[pkt].state != sent_) return;

  if (interestRetransmissions_.find(segmentNumber) !=
      interestRetransmissions_.end())
    // this packet was rtx at least once
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
  auto payload = content_object.getPayload();

  // we collect OWD only for datapackets
  if (payload->length() != HICN_NACK_HEADER_SIZE) {
    uint64_t *senderTimeStamp = (uint64_t *)payload->data();

    int64_t OWD = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count() -
                  *senderTimeStamp;

    pathTable_[pathLabel]->insertOwdSample(OWD);
  }
}

void RTCTransportProtocol::updateStats(uint32_t round_duration) {
  if (receivedBytes_ != 0) {
    double bytesPerSec =
        (double)(receivedBytes_ *
                 ((double)HICN_MILLI_IN_A_SEC / (double)round_duration));
    estimatedBw_ = (estimatedBw_ * HICN_ESTIMATED_BW_ALPHA) +
                   ((1 - HICN_ESTIMATED_BW_ALPHA) * bytesPerSec);
  }

  auto it = pathTable_.find(producerPathLabel_);
  if (it == pathTable_.end()) return;

  minRtt_ = it->second->getMinRtt();
  queuingDelay_ = it->second->getQueuingDealy();

  if (minRtt_ == 0) minRtt_ = 1;

  for (auto it = pathTable_.begin(); it != pathTable_.end(); it++) {
    it->second->roundEnd();
  }

  if (sentInterest_ != 0 && currentState_ == HICN_RTC_NORMAL_STATE) {
    double lossRate = (double)((double)packetLost_ / (double)sentInterest_);
    lossRate_ = lossRate_ * HICN_ESTIMATED_LOSSES_ALPHA +
                (lossRate * (1 - HICN_ESTIMATED_LOSSES_ALPHA));
  }

  if (avgPacketSize_ == 0) avgPacketSize_ = HICN_INIT_PACKET_SIZE;

  uint32_t BDP = (uint32_t)ceil(
      (estimatedBw_ * (double)((double)minRtt_ / (double)HICN_MILLI_IN_A_SEC) *
       HICN_BANDWIDTH_SLACK_FACTOR) /
      avgPacketSize_);
  uint32_t BW = (uint32_t)ceil(estimatedBw_);
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
  uint32_t maxWaintingInterest = (uint32_t)ceil(
      (productionRate / avgPacketSize_) *
      (double)((double)(interestLifetime *
                        HICN_INTEREST_LIFETIME_REDUCTION_FACTOR) /
               (double)HICN_MILLI_IN_A_SEC));

  if (currentState_ == HICN_RTC_SYNC_STATE) {
    // in this case we do not limit the window with the BDP, beacuse most
    // likely it is wrong
    maxCWin_ = maxWaintingInterest;
    return;
  }

  // currentState = RTC_NORMAL_STATE
  if (BDPWin != 0) {
    maxCWin_ =
        (uint32_t)ceil((double)BDPWin + ((double)BDPWin / 10.0));  // BDP + 10%
  } else {
    maxCWin_ = min(maxWaintingInterest, maxCWin_);
  }
}

void RTCTransportProtocol::updateWindow() {
  if (currentState_ == HICN_RTC_SYNC_STATE) return;

  if (currentCWin_ < maxCWin_ * 0.7) {
    currentCWin_ =
        min(maxCWin_, (uint32_t)(currentCWin_ * HICN_WIN_INCREASE_FACTOR));
  } else if (currentCWin_ > maxCWin_) {
    currentCWin_ =
        max((uint32_t)(currentCWin_ * HICN_WIN_DECREASE_FACTOR), HICN_MIN_CWIN);
  }
}

void RTCTransportProtocol::decreaseWindow() {
  // this is used only in SYNC mode
  if (currentState_ == HICN_RTC_NORMAL_STATE) return;

  if (gotFutureNack_ == 1)
    currentCWin_ = min((currentCWin_ - 1),
                       (uint32_t)ceil((double)maxCWin_ * 0.66));  // 2/3
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
        maxCWin_,
        (uint32_t)ceil(currentCWin_ + (1.0 / (double)currentCWin_)));  // linear
  }
}

void RTCTransportProtocol::sendInterest(Name *interest_name, bool rtx) {
  auto interest = getPacket();
  interest->setName(*interest_name);

  uint32_t interestLifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           interestLifetime);
  interest->setLifetime(uint32_t(interestLifetime));

  ConsumerInterestCallback *on_interest_output = nullptr;

  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_OUTPUT,
                           &on_interest_output);

  if (*on_interest_output != VOID_HANDLER) {
    (*on_interest_output)(*socket_, *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  portal_->sendInterest(std::move(interest));

  sentInterest_++;

  if (!rtx) {
    inflightInterestsCount_++;
  }
}

void RTCTransportProtocol::scheduleNextInterests() {
  checkRound();
  if (!is_running_) return;

  while (inflightInterestsCount_ < currentCWin_) {
    Name *interest_name = nullptr;
    socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                             &interest_name);

    // we send the packet only if it is not pending yet
    interest_name->setSuffix(actualSegment_);
    if (portal_->interestIsPending(*interest_name)) {
      actualSegment_++;
      continue;
    }

    uint32_t pkt = actualSegment_ & modMask_;
    // if we already reacevied the content we don't ask it again
    if (inflightInterests_[pkt].state == received_ &&
        inflightInterests_[pkt].sequence == actualSegment_) {
      actualSegment_++;
      continue;
    }

    inflightInterests_[pkt].transmissionTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    inflightInterests_[pkt].state = sent_;
    inflightInterests_[pkt].sequence = actualSegment_;
    actualSegment_++;

    sendInterest(interest_name, false);
    checkRound();
  }
}

void RTCTransportProtocol::scheduleAppNackRtx(std::vector<uint32_t> &nacks) {
#if 0
  for (uint32_t i = 0; i < nacks.size(); i++) {
    if (nackedByProducer_.find(nacks[i]) != nackedByProducer_.end()) {
      continue;
    }
    // packetLost_++;
    // XXX here I need to avoid the retrasmission for packet that were
    // nacked by the network
    interestRetransmissions_.push(nacks[i]);
  }

  scheduleNextInterests();
#endif
}

void RTCTransportProtocol::addRetransmissions(uint32_t val) {
  // add only val in the rtx list
  addRetransmissions(val, val + 1);
}

void RTCTransportProtocol::addRetransmissions(uint32_t start, uint32_t stop) {
  for (uint32_t i = start; i < stop; i++) {
    auto it = interestRetransmissions_.find(i);
    if (it == interestRetransmissions_.end()) {
      if (lastSegNacked_ <= i) {
        // i must be larger than the last past nack received
        interestRetransmissions_[i] = 0;
      }
    }  // if the retransmission is already there the rtx timer will
       // take care of it
  }
  retransmit(true);
}

void RTCTransportProtocol::retransmit(bool first_rtx) {
  auto it = interestRetransmissions_.begin();

  // cut len to max HICN_MAX_RTX_SIZE
  // since we use a map, the smaller (and so the older) sequence number are at
  // the beginnin of the map
  while (interestRetransmissions_.size() > HICN_MAX_RTX_SIZE) {
    it = interestRetransmissions_.erase(it);
  }

  it = interestRetransmissions_.begin();

  while (it != interestRetransmissions_.end()) {
    uint32_t pkt = it->first & modMask_;

    if (inflightInterests_[pkt].sequence != it->first) {
      // this packet is not anymore in the inflight buffer, erase it
      it = interestRetransmissions_.erase(it);
      continue;
    }

    // we retransmitted the packet too many times
    if (it->second >= HICN_MAX_RTX) {
      it = interestRetransmissions_.erase(it);
      continue;
    }

    // this packet is too old
    if ((lastReceived_ > it->first) &&
        (lastReceived_ - it->first) > HICN_MAX_RTX_MAX_AGE) {
      it = interestRetransmissions_.erase(it);
      continue;
    }

    if (first_rtx) {
      // TODO (optimization)
      // the rtx that we never sent (it->second  == 0) are all at the
      // end, so we can go directly there
      if (it->second == 0) {
        inflightInterests_[pkt].transmissionTime =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count();
        it->second++;

        Name *interest_name = nullptr;
        socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                                 &interest_name);
        interest_name->setSuffix(it->first);
        sendInterest(interest_name, true);
      }
      ++it;
    } else {
      // base on time
      uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();
      if ((now - inflightInterests_[pkt].transmissionTime) > 20) {
        // XXX replace 20 with rtt
        inflightInterests_[pkt].transmissionTime =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count();
        it->second++;

        Name *interest_name = nullptr;
        socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                                 &interest_name);
        interest_name->setSuffix(it->first);
        sendInterest(interest_name, true);
      }
      ++it;
    }
  }
}

void RTCTransportProtocol::checkRtx() {
  retransmit(false);
  rtx_timer_->expires_from_now(std::chrono::milliseconds(20));
  rtx_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    checkRtx();
  });
}

void RTCTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  // packetLost_++;

  uint32_t segmentNumber = interest->getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;

  if (inflightInterests_[pkt].state == sent_) {
    inflightInterestsCount_--;
  }

  // check how many times we sent this packet
  auto it = interestRetransmissions_.find(segmentNumber);
  if (it != interestRetransmissions_.end() && it->second >= HICN_MAX_RTX) {
    inflightInterests_[pkt].state = lost_;
  }

  if (inflightInterests_[pkt].state == sent_) {
    inflightInterests_[pkt].state = timeout1_;
  } else if (inflightInterests_[pkt].state == timeout1_) {
    inflightInterests_[pkt].state = timeout2_;
  } else if (inflightInterests_[pkt].state == timeout2_) {
    inflightInterests_[pkt].state = lost_;
  }

  if (inflightInterests_[pkt].state == lost_) {
    interestRetransmissions_.erase(segmentNumber);
  } else {
    addRetransmissions(segmentNumber);
  }

  scheduleNextInterests();
}

bool RTCTransportProtocol::checkIfProducerIsActive(
    const ContentObject &content_object) {
  uint32_t *payload = (uint32_t *)content_object.getPayload()->data();
  uint32_t productionSeg = *payload;
  uint32_t productionRate = *(++payload);

  if (productionRate == 0) {
    // the producer socket is not active
    // in this case we consider only the first nack
    if (nack_timer_used_) {
      return false;
    }

    nack_timer_used_ = true;
    // actualSegment_ should be the one in the nack, which will be the next in
    // production
    actualSegment_ = productionSeg;
    // all the rest (win size should not change)
    // we wait a bit before pull the socket again
    nack_timer_->expires_from_now(std::chrono::milliseconds(500));
    nack_timer_->async_wait([this](std::error_code ec) {
      if (ec) return;
      nack_timer_used_ = false;
      scheduleNextInterests();
    });
    return false;
  }
  return true;
}

void RTCTransportProtocol::onNack(const ContentObject &content_object) {
  uint32_t *payload = (uint32_t *)content_object.getPayload()->data();
  uint32_t productionSeg = *payload;
  uint32_t productionRate = *(++payload);
  uint32_t nackSegment = content_object.getName().getSuffix();

  gotNack_ = true;
  // we synch the estimated production rate with the actual one
  estimatedBw_ = (double)productionRate;

  if (productionSeg > nackSegment) {
    // we are asking for stuff produced in the past
    actualSegment_ = max(productionSeg + 1, actualSegment_);
    if (currentState_ == HICN_RTC_NORMAL_STATE) {
      currentState_ = HICN_RTC_SYNC_STATE;
    }

    computeMaxWindow(productionRate, 0);
    increaseWindow();

    interestRetransmissions_.clear();
    lastSegNacked_ = productionSeg;

    if (nackedByProducer_.size() >= nackedByProducerMaxSize_)
      nackedByProducer_.erase(nackedByProducer_.begin());
    nackedByProducer_.insert(nackSegment);

  } else if (productionSeg < nackSegment) {
    // we are asking stuff in the future
    gotFutureNack_++;

    actualSegment_ = productionSeg + 1;

    computeMaxWindow(productionRate, 0);
    decreaseWindow();

    if (currentState_ == HICN_RTC_SYNC_STATE) {
      currentState_ = HICN_RTC_NORMAL_STATE;
    }
  }  // equal should not happen
}

void RTCTransportProtocol::onNackForRtx(const ContentObject &content_object) {
  uint32_t *payload = (uint32_t *)content_object.getPayload()->data();
  uint32_t productionSeg = *payload;
  uint32_t nackSegment = content_object.getName().getSuffix();

  if (productionSeg > nackSegment) {
    // we are asking for stuff produced in the past
    actualSegment_ = max(productionSeg + 1, actualSegment_);

    interestRetransmissions_.clear();
    lastSegNacked_ = productionSeg;

  } else if (productionSeg < nackSegment) {
    actualSegment_ = productionSeg + 1;
  }  // equal should not happen
}

void RTCTransportProtocol::onContentObject(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  auto payload = content_object->getPayload();
  uint32_t payload_size = (uint32_t)payload->length();
  uint32_t segmentNumber = content_object->getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;
  bool schedule_next_interest = true;

  ConsumerContentObjectCallback *callback_content_object = nullptr;
  socket_->getSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
                           &callback_content_object);
  if (*callback_content_object != VOID_HANDLER) {
    (*callback_content_object)(*socket_, *content_object);
  }

  if (payload_size == HICN_NACK_HEADER_SIZE) {
    // Nacks always come form the producer, so we set the producerPathLabel_;
    producerPathLabel_ = content_object->getPathLabel();
    schedule_next_interest = checkIfProducerIsActive(*content_object);
    if (inflightInterests_[pkt].state == sent_) {
      inflightInterestsCount_--;
      // if checkIfProducerIsActive returns false, we did all we need to do
      // inside that function, no need to call onNack
      if (schedule_next_interest) onNack(*content_object);
      updateDelayStats(*content_object);
    } else {
      if (schedule_next_interest) onNackForRtx(*content_object);
    }

  } else {
    avgPacketSize_ = (HICN_ESTIMATED_PACKET_SIZE * avgPacketSize_) +
                     ((1 - HICN_ESTIMATED_PACKET_SIZE) * payload->length());

    if (inflightInterests_[pkt].state == sent_) {
      inflightInterestsCount_--;  // packet sent without timeouts
    }

    if (inflightInterests_[pkt].state == sent_ &&
        interestRetransmissions_.find(segmentNumber) ==
            interestRetransmissions_.end()) {
      // we count only non retransmitted data in order to take into accunt only
      // the transmition rate of the producer
      receivedBytes_ += (uint32_t)(content_object->headerSize() +
                                   content_object->payloadSize());
      updateDelayStats(*content_object);

      addRetransmissions(lastReceived_ + 1, segmentNumber);
      // lastReceived_ is updated only for data packets received without RTX
      lastReceived_ = segmentNumber;
    }

    receivedData_++;
    inflightInterests_[pkt].state = received_;

    reassemble(std::move(content_object));
    increaseWindow();
  }

  // in any case we remove the packet from the rtx list
  interestRetransmissions_.erase(segmentNumber);

  if (schedule_next_interest) {
    scheduleNextInterests();
  }
}

void RTCTransportProtocol::returnContentToApplication(
    const ContentObject &content_object) {
  // return content to the user
  auto read_buffer = content_object.getPayload();

  read_buffer->trimStart(HICN_TIMESTAMP_SIZE);

  // set offset between hICN and RTP packets
  uint16_t rtp_seq = ntohs(*(((uint16_t *)read_buffer->writableData()) + 1));
  RTPhICN_offset_ = content_object.getName().getSuffix() - rtp_seq;

  interface::ConsumerSocket::ReadCallback *read_callback = nullptr;
  socket_->getSocketOption(READ_CALLBACK, &read_callback);

  if (read_callback == nullptr) {
    throw errors::RuntimeException(
        "The read callback must be installed in the transport before starting "
        "the content retrieval.");
  }

  if (read_callback->isBufferMovable()) {
    read_callback->readBufferAvailable(
        utils::MemBuf::copyBuffer(read_buffer->data(), read_buffer->length()));
  } else {
    // The buffer will be copied into the application-provided buffer
    uint8_t *buffer;
    std::size_t length;
    std::size_t total_length = read_buffer->length();

    while (read_buffer->length()) {
      buffer = nullptr;
      length = 0;
      read_callback->getReadBuffer(&buffer, &length);

      if (!buffer || !length) {
        throw errors::RuntimeException(
            "Invalid buffer provided by the application.");
      }

      auto to_copy = std::min(read_buffer->length(), length);

      std::memcpy(buffer, read_buffer->data(), to_copy);
      read_buffer->trimStart(to_copy);
    }

    read_callback->readDataAvailable(total_length);
    read_buffer->clear();
  }

  if (read_callback->isBufferMovable()) {
    read_callback->readBufferAvailable(
        utils::MemBuf::copyBuffer(read_buffer->data(), read_buffer->length()));
  } else {
    // The buffer will be copied into the application-provided buffer
    uint8_t *buffer;
    std::size_t length;
    std::size_t total_length = read_buffer->length();

    while (read_buffer->length()) {
      buffer = nullptr;
      length = 0;
      read_callback->getReadBuffer(&buffer, &length);

      if (!buffer || !length) {
        throw errors::RuntimeException(
            "Invalid buffer provided by the application.");
      }

      auto to_copy = std::min(read_buffer->length(), length);

      std::memcpy(buffer, read_buffer->data(), to_copy);
      read_buffer->trimStart(to_copy);
    }

    read_callback->readDataAvailable(total_length);
    read_buffer->clear();
  }
}

}  // end namespace protocol

}  // end namespace transport
