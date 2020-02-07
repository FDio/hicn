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

#include <hicn/transport/protocols/rtc.h>

#include <hicn/transport/interfaces/socket_consumer.h>

#include <math.h>
#include <random>

namespace transport {

namespace protocol {

using namespace interface;

RTCTransportProtocol::RTCTransportProtocol(
    interface::ConsumerSocket *icn_socket)
    : TransportProtocol(icn_socket, nullptr),
      DatagramReassembly(icn_socket, this),
      inflightInterests_(1 << default_values::log_2_default_buffer_size),
      modMask_((1 << default_values::log_2_default_buffer_size) - 1) {
  icn_socket->getSocketOption(PORTAL, portal_);
  rtx_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  probe_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  sentinel_timer_ =
      std::make_unique<asio::steady_timer>(portal_->getIoService());
  round_timer_ = std::make_unique<asio::steady_timer>(portal_->getIoService());
  reset();
}

RTCTransportProtocol::~RTCTransportProtocol() {
  if (is_running_) {
    stop();
  }
}

int RTCTransportProtocol::start() {
  probeRtt();
  sentinelTimer();
  newRound();
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

  inflightInterestsCount_ = 0;

  probeRtt();
  sentinelTimer();
  newRound();
  scheduleNextInterests();

  portal_->runEventsLoop();

  is_running_ = false;
}

// private
void RTCTransportProtocol::reset() {
  portal_->setConsumerCallback(this);
  // controller var
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
  lastReceivedTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
  lastEvent_ = lastReceivedTime_;
  highestReceived_ = 0;
  firstSequenceInRound_ = 0;

  rtx_timer_used_ = false;
  for (int i = 0; i < (1 << default_values::log_2_default_buffer_size); i++) {
    inflightInterests_[i] = {0};
  }

  // stats
  firstPckReceived_ = false;
  receivedBytes_ = 0;
  sentInterest_ = 0;
  receivedData_ = 0;
  packetLost_ = 0;
  lossRecovered_ = 0;
  avgPacketSize_ = HICN_INIT_PACKET_SIZE;
  gotNack_ = false;
  gotFutureNack_ = 0;
  rounds_ = 0;
  roundsWithoutNacks_ = 0;
  pathTable_.clear();

  // CC var
  estimatedBw_ = 0.0;
  lossRate_ = 0.0;
  queuingDelay_ = 0.0;
  protocolState_ = HICN_RTC_NORMAL_STATE;

  producerPathLabels_[0] = 0;
  producerPathLabels_[1] = 0;
  initied = false;

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

void RTCTransportProtocol::newRound() {
  round_timer_->expires_from_now(std::chrono::milliseconds(HICN_ROUND_LEN));
  round_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    updateStats(HICN_ROUND_LEN);
    newRound();
  });
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
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count() -
                  *senderTimeStamp;

    pathTable_[pathLabel]->insertOwdSample(OWD);
    pathTable_[pathLabel]->computeInterArrivalGap(segmentNumber);
  } else {
    pathTable_[pathLabel]->receivedNack();
  }
}

void RTCTransportProtocol::updateStats(uint32_t round_duration) {
  if (pathTable_.empty()) return;

  if (receivedBytes_ != 0) {
    double bytesPerSec =
        (double)(receivedBytes_ *
                 ((double)HICN_MILLI_IN_A_SEC / (double)round_duration));
    estimatedBw_ = (estimatedBw_ * HICN_ESTIMATED_BW_ALPHA) +
                   ((1 - HICN_ESTIMATED_BW_ALPHA) * bytesPerSec);
  }

  uint64_t minRtt = UINT_MAX;
  uint64_t maxRtt = 0;

  for (auto it = pathTable_.begin(); it != pathTable_.end(); it++) {
    it->second->roundEnd();
    if (it->second->isActive()) {
      if (it->second->getMinRtt() < minRtt) {
        minRtt = it->second->getMinRtt();
        producerPathLabels_[0] = it->first;
      }
      if (it->second->getMinRtt() > maxRtt) {
        maxRtt = it->second->getMinRtt();
        producerPathLabels_[1] = it->first;
      }
    }
  }

  if (pathTable_.find(producerPathLabels_[0]) == pathTable_.end() ||
      pathTable_.find(producerPathLabels_[1]) == pathTable_.end())
    return;  // this should not happen

  // as a queuing delay we keep the lowest one among the two paths
  // if one path is congested the forwarder should decide to do not
  // use it so it does not make sense  to inform the application
  // that maybe we have a problem
  if (pathTable_[producerPathLabels_[0]]->getQueuingDealy() <
      pathTable_[producerPathLabels_[1]]->getQueuingDealy())
    queuingDelay_ = pathTable_[producerPathLabels_[0]]->getQueuingDealy();
  else
    queuingDelay_ = pathTable_[producerPathLabels_[1]]->getQueuingDealy();

  if (sentInterest_ != 0 && currentState_ == HICN_RTC_NORMAL_STATE) {
    uint32_t numberTheoricallyReceivedPackets_ =
        highestReceived_ - firstSequenceInRound_;
    double lossRate = 0;
    if (numberTheoricallyReceivedPackets_ != 0)
      lossRate = (double)((double)(packetLost_ - lossRecovered_) /
                          (double)numberTheoricallyReceivedPackets_);

    if (lossRate < 0) lossRate = 0;

    if (initied) {
      lossRate_ = lossRate_ * HICN_ESTIMATED_LOSSES_ALPHA +
                  (lossRate * (1 - HICN_ESTIMATED_LOSSES_ALPHA));
    } else {
      lossRate_ = lossRate;
      initied = true;
    }
  }

  if (avgPacketSize_ == 0) avgPacketSize_ = HICN_INIT_PACKET_SIZE;

  // for the BDP we use the max rtt, so that we calibrate the window on the
  // RTT of the slowest path. In this way we are sure that the window will
  // never be too small
  uint32_t BDP = (uint32_t)ceil(
      (estimatedBw_ *
       (double)((double)pathTable_[producerPathLabels_[1]]->getMinRtt() /
                (double)HICN_MILLI_IN_A_SEC) *
       HICN_BANDWIDTH_SLACK_FACTOR) /
      avgPacketSize_);
  uint32_t BW = (uint32_t)ceil(estimatedBw_);
  computeMaxWindow(BW, BDP);

  ConsumerTimerCallback *stats_callback = nullptr;
  socket_->getSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                           &stats_callback);
  if (*stats_callback) {
    // Send the stats to the app
    stats_->updateQueuingDelay(queuingDelay_);
    stats_->updateLossRatio(lossRate_);
    stats_->updateAverageRtt(pathTable_[producerPathLabels_[1]]->getMinRtt());
    (*stats_callback)(*socket_, *stats_);
  }

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

  if (queuingDelay_ > 25.0) {
    // this indicates that the client will go soon out of synch,
    // switch to synch mode
    if (currentState_ == HICN_RTC_NORMAL_STATE) {
      currentState_ = HICN_RTC_SYNC_STATE;
    }
    computeMaxWindow(BW, 0);
    increaseWindow();
  }

  // in any case we reset all the counters

  gotNack_ = false;
  gotFutureNack_ = 0;
  receivedBytes_ = 0;
  sentInterest_ = 0;
  receivedData_ = 0;
  packetLost_ = 0;
  lossRecovered_ = 0;
  rounds_++;
  firstSequenceInRound_ = highestReceived_;
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
    maxCWin_ = (uint32_t)ceil((double)BDPWin +
                              (((double)BDPWin * 30.0) / 100.0));  // BDP + 30%
  } else {
    maxCWin_ = min(maxWaintingInterest, maxCWin_);
  }

  if (maxCWin_ < HICN_MIN_CWIN) maxCWin_ = HICN_MIN_CWIN;
}

void RTCTransportProtocol::updateWindow() {
  if (currentState_ == HICN_RTC_SYNC_STATE) return;

  if (currentCWin_ < maxCWin_ * 0.9) {
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
  if (currentCWin_ < ((double)maxCWin_ * 0.7)) {
    currentCWin_ = currentCWin_ + 1;  // exponential
  } else {
    currentCWin_ = min(
        maxCWin_,
        (uint32_t)ceil(currentCWin_ + (1.0 / (double)currentCWin_)));  // linear
  }
}

void RTCTransportProtocol::probeRtt() {
  time_sent_probe_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();

  Name *interest_name = nullptr;
  socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                           &interest_name);
  // get a random numbe in the probe seq range
  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint32_t> idis(HICN_MIN_PROBE_SEQ,
                                               HICN_MAX_PROBE_SEQ);
  probe_seq_number_ = idis(eng);
  interest_name->setSuffix(probe_seq_number_);

  // we considere the probe as a rtx so that we do not incresea inFlightInt
  received_probe_ = false;
  sendInterest(interest_name, true);

  probe_timer_->expires_from_now(std::chrono::milliseconds(1000));
  probe_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    probeRtt();
  });
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

  if (*on_interest_output) {
    (*on_interest_output)(*socket_, *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_ && !is_first_)) {
    return;
  }

  portal_->sendInterest(std::move(interest));

  sentInterest_++;

  if (!rtx) {
    packets_in_window_[interest_name->getSuffix()] = 0;
    inflightInterestsCount_++;
  }
}

void RTCTransportProtocol::scheduleNextInterests() {
  if (!is_running_ && !is_first_) return;

  while (inflightInterestsCount_ < currentCWin_) {
    Name *interest_name = nullptr;
    socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                             &interest_name);

    interest_name->setSuffix(actualSegment_);

    // if the producer socket is not stated (does not reply even with nacks)
    // we keep asking for something without marking anything as lost (see
    // timeout). In this way when the producer socket will start the
    // consumer socket will not miss any packet
    if (TRANSPORT_EXPECT_FALSE(!firstPckReceived_)) {
      uint32_t pkt = actualSegment_ & modMask_;
      inflightInterests_[pkt].state = sent_;
      inflightInterests_[pkt].sequence = actualSegment_;
      actualSegment_ = (actualSegment_ + 1) % HICN_MIN_PROBE_SEQ;
      sendInterest(interest_name, false);
      return;
    }

    // we send the packet only if it is not pending yet
    // notice that this is not true for rtx packets
    if (portal_->interestIsPending(*interest_name)) {
      actualSegment_ = (actualSegment_ + 1) % HICN_MIN_PROBE_SEQ;
      continue;
    }

    uint32_t pkt = actualSegment_ & modMask_;
    // if we already reacevied the content we don't ask it again
    if (inflightInterests_[pkt].state == received_ &&
        inflightInterests_[pkt].sequence == actualSegment_) {
      actualSegment_ = (actualSegment_ + 1) % HICN_MIN_PROBE_SEQ;
      continue;
    }

    // same if the packet is lost
    if (inflightInterests_[pkt].state == lost_ &&
        inflightInterests_[pkt].sequence == actualSegment_) {
      actualSegment_ = (actualSegment_ + 1) % HICN_MIN_PROBE_SEQ;
      continue;
    }

    inflightInterests_[pkt].transmissionTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();

    // here the packet can be in any state except for lost or recevied
    inflightInterests_[pkt].state = sent_;
    inflightInterests_[pkt].sequence = actualSegment_;
    actualSegment_ = (actualSegment_ + 1) % HICN_MIN_PROBE_SEQ;

    sendInterest(interest_name, false);
  }
}

void RTCTransportProtocol::sentinelTimer() {
  uint32_t wait = 50;

  if (pathTable_.find(producerPathLabels_[0]) != pathTable_.end() &&
      pathTable_.find(producerPathLabels_[1]) != pathTable_.end()) {
    // we have all the info to set the timers
    wait = round(pathTable_[producerPathLabels_[0]]->getInterArrivalGap());
    if (wait == 0) wait = 1;
  }

  sentinel_timer_->expires_from_now(std::chrono::milliseconds(wait));
  sentinel_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();

    if (pathTable_.find(producerPathLabels_[0]) == pathTable_.end() ||
        pathTable_.find(producerPathLabels_[1]) == pathTable_.end()) {
      // we have no info, so we send again

      for (auto it = packets_in_window_.begin(); it != packets_in_window_.end();
           it++) {
        uint32_t pkt = it->first & modMask_;
        if (inflightInterests_[pkt].sequence == it->first) {
          inflightInterests_[pkt].transmissionTime = now;
          Name *interest_name = nullptr;
          socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                                   &interest_name);
          interest_name->setSuffix(it->first);
          it->second++;
          sendInterest(interest_name, true);
        }
      }
    } else {
      uint64_t max_waiting_time =  // wait at least 50ms
          (pathTable_[producerPathLabels_[1]]->getMinRtt() -
           pathTable_[producerPathLabels_[0]]->getMinRtt()) +
          (ceil(pathTable_[producerPathLabels_[0]]->getInterArrivalGap()) * 50);

      if ((currentState_ == HICN_RTC_NORMAL_STATE) &&
          (inflightInterestsCount_ >= currentCWin_) &&
          ((now - lastEvent_) > max_waiting_time) && (lossRate_ >= 0.05)) {
        uint64_t RTT = pathTable_[producerPathLabels_[1]]->getMinRtt();

        for (auto it = packets_in_window_.begin();
             it != packets_in_window_.end(); it++) {
          uint32_t pkt = it->first & modMask_;
          if (inflightInterests_[pkt].sequence == it->first &&
              ((now - inflightInterests_[pkt].transmissionTime) >= RTT)) {
            inflightInterests_[pkt].transmissionTime = now;
            Name *interest_name = nullptr;
            socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                                     &interest_name);
            interest_name->setSuffix(it->first);
            it->second++;
            sendInterest(interest_name, true);
          }
        }
      }
    }

    sentinelTimer();
  });
}
void RTCTransportProtocol::addRetransmissions(uint32_t val) {
  // add only val in the rtx list
  addRetransmissions(val, val + 1);
}

void RTCTransportProtocol::addRetransmissions(uint32_t start, uint32_t stop) {
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  bool new_rtx = false;
  for (uint32_t i = start; i < stop; i++) {
    auto it = interestRetransmissions_.find(i);
    if (it == interestRetransmissions_.end()) {
      uint32_t pkt = i & modMask_;
      if (lastSegNacked_ <= i && inflightInterests_[pkt].state != received_) {
        // it must be larger than the last past nack received
        packetLost_++;
        interestRetransmissions_[i] = 0;
        uint32_t pkt = i & modMask_;
        // we reset the transmission time setting to now, so that rtx will
        // happne in one RTT on waint one inter arrival gap
        inflightInterests_[pkt].transmissionTime = now;
        new_rtx = true;
      }
    }  // if the retransmission is already there the rtx timer will
       // take care of it
  }

  // in case a new rtx is added to the map we need to run checkRtx()
  if (new_rtx) {
    if (rtx_timer_used_) {
      // if a timer is pending we need to delete it
      rtx_timer_->cancel();
      rtx_timer_used_ = false;
    }
    checkRtx();
  }
}

uint64_t RTCTransportProtocol::retransmit() {
  auto it = interestRetransmissions_.begin();

  // cut len to max HICN_MAX_RTX_SIZE
  // since we use a map, the smaller (and so the older) sequence number are at
  // the beginnin of the map
  while (interestRetransmissions_.size() > HICN_MAX_RTX_SIZE) {
    it = interestRetransmissions_.erase(it);
  }

  it = interestRetransmissions_.begin();
  uint64_t smallest_timeout = ULONG_MAX;
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

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

    uint64_t rtx_time = now;

    if (it->second == 0) {
      // first rtx
      if (producerPathLabels_[0] != producerPathLabels_[1]) {
        // multipath
        if (pathTable_.find(producerPathLabels_[0]) != pathTable_.end() &&
            pathTable_.find(producerPathLabels_[1]) != pathTable_.end() &&
            (pathTable_[producerPathLabels_[0]]->getInterArrivalGap() <
             HICN_MIN_INTER_ARRIVAL_GAP)) {
          rtx_time = lastReceivedTime_ +
                     (pathTable_[producerPathLabels_[1]]->getMinRtt() -
                      pathTable_[producerPathLabels_[0]]->getMinRtt()) +
                     pathTable_[producerPathLabels_[0]]->getInterArrivalGap();
        }  // else low rate producer, send it immediatly
      } else {
        // single path
        if (pathTable_.find(producerPathLabels_[0]) != pathTable_.end() &&
            (pathTable_[producerPathLabels_[0]]->getInterArrivalGap() <
             HICN_MIN_INTER_ARRIVAL_GAP)) {
          rtx_time = lastReceivedTime_ +
                     pathTable_[producerPathLabels_[0]]->getInterArrivalGap();
        }  // else low rate producer send immediatly
      }
    } else {
      // second or plus rtx, wait for the min rtt
      if (pathTable_.find(producerPathLabels_[0]) != pathTable_.end()) {
        uint64_t sent_time = inflightInterests_[pkt].transmissionTime;
        rtx_time = sent_time + pathTable_[producerPathLabels_[0]]->getMinRtt();
      }  // if we don't have info we send it immediatly
    }

    if (now >= rtx_time) {
      inflightInterests_[pkt].transmissionTime = now;
      it->second++;

      Name *interest_name = nullptr;
      socket_->getSocketOption(GeneralTransportOptions::NETWORK_NAME,
                               &interest_name);
      interest_name->setSuffix(it->first);
      sendInterest(interest_name, true);
    } else if (rtx_time < smallest_timeout) {
      smallest_timeout = rtx_time;
    }

    ++it;
  }
  return smallest_timeout;
}

void RTCTransportProtocol::checkRtx() {
  if (interestRetransmissions_.empty()) {
    rtx_timer_used_ = false;
    return;
  }

  uint64_t next_timeout = retransmit();
  uint64_t wait = 1;
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  if (next_timeout != ULONG_MAX && now < next_timeout) {
    wait = next_timeout - now;
  }
  rtx_timer_used_ = true;
  rtx_timer_->expires_from_now(std::chrono::milliseconds(wait));
  rtx_timer_->async_wait([this](std::error_code ec) {
    if (ec) return;
    rtx_timer_used_ = false;
    checkRtx();
  });
}

void RTCTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  uint32_t segmentNumber = interest->getName().getSuffix();

  if (segmentNumber >= HICN_MIN_PROBE_SEQ) {
    // this is a timeout on a probe, do nothing
    return;
  }

  uint32_t pkt = segmentNumber & modMask_;

  if (TRANSPORT_EXPECT_FALSE(!firstPckReceived_)) {
    // we do nothing, and we keep asking the same stuff over
    // and over until we get at least a packet
    inflightInterestsCount_--;
    lastEvent_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
    packets_in_window_.erase(segmentNumber);
    scheduleNextInterests();
    return;
  }

  if (inflightInterests_[pkt].state == sent_) {
    lastEvent_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
    packets_in_window_.erase(segmentNumber);
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

bool RTCTransportProtocol::onNack(const ContentObject &content_object,
                                  bool rtx) {
  uint32_t *payload = (uint32_t *)content_object.getPayload()->data();
  uint32_t productionSeg = *payload;
  uint32_t productionRate = *(++payload);
  uint32_t nackSegment = content_object.getName().getSuffix();

  bool old_nack = false;

  // if we did not received anything between lastReceived_ + 1 and productionSeg
  // most likelly some packets got lost
  if (lastReceived_ != 0) {
    addRetransmissions(lastReceived_ + 1, productionSeg);
  }

  if (!rtx) {
    gotNack_ = true;
    // we synch the estimated production rate with the actual one
    estimatedBw_ = (double)productionRate;
  }

  if (productionSeg > nackSegment) {
    // we are asking for stuff produced in the past
    actualSegment_ = max(productionSeg, actualSegment_) % HICN_MIN_PROBE_SEQ;

    if (!rtx) {
      if (currentState_ == HICN_RTC_NORMAL_STATE) {
        currentState_ = HICN_RTC_SYNC_STATE;
      }

      computeMaxWindow(productionRate, 0);
      increaseWindow();
    }

    lastSegNacked_ = productionSeg;
    old_nack = true;

  } else if (productionSeg < nackSegment) {
    actualSegment_ = productionSeg % HICN_MIN_PROBE_SEQ;

    if (!rtx) {
      // we are asking stuff in the future
      gotFutureNack_++;
      computeMaxWindow(productionRate, 0);
      decreaseWindow();

      if (currentState_ == HICN_RTC_SYNC_STATE) {
        currentState_ = HICN_RTC_NORMAL_STATE;
      }
    }
  } else {
    // we are asking the right thing, but the producer is slow
    // keep doing the same until the packet is produced
    actualSegment_ = productionSeg % HICN_MIN_PROBE_SEQ;
  }

  return old_nack;
}

void RTCTransportProtocol::onContentObject(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  // as soon as we get a packet firstPckReceived_ will never be false
  firstPckReceived_ = true;

  auto payload = content_object->getPayload();
  uint32_t payload_size = (uint32_t)payload->length();
  uint32_t segmentNumber = content_object->getName().getSuffix();
  uint32_t pkt = segmentNumber & modMask_;

  ConsumerContentObjectCallback *callback_content_object = nullptr;
  socket_->getSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
                           &callback_content_object);
  if (*callback_content_object) {
    (*callback_content_object)(*socket_, *content_object);
  }

  if (segmentNumber >= HICN_MIN_PROBE_SEQ) {
    if (segmentNumber == probe_seq_number_ && !received_probe_) {
      received_probe_ = true;

      uint32_t pathLabel = content_object->getPathLabel();
      if (pathTable_.find(pathLabel) == pathTable_.end()) {
        std::shared_ptr<RTCDataPath> newPath = std::make_shared<RTCDataPath>();
        pathTable_[pathLabel] = newPath;
      }

      // this is the expected probe, update the RTT and drop the packet
      uint64_t RTT = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count() -
                     time_sent_probe_;

      pathTable_[pathLabel]->insertRttSample(RTT);
      pathTable_[pathLabel]->receivedNack();
    }
    return;
  }

  // check if the packet is a rtx
  bool is_rtx = false;
  if (interestRetransmissions_.find(segmentNumber) !=
      interestRetransmissions_.end()) {
    is_rtx = true;
  } else {
    auto it_win = packets_in_window_.find(segmentNumber);
    if (it_win != packets_in_window_.end() && it_win->second != 0)
      is_rtx = true;
  }

  if (payload_size == HICN_NACK_HEADER_SIZE) {
    if (inflightInterests_[pkt].state == sent_) {
      lastEvent_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();
      packets_in_window_.erase(segmentNumber);
      inflightInterestsCount_--;
    }

    bool old_nack = false;

    if (!is_rtx) {
      // this is not a retransmitted packet
      old_nack = onNack(*content_object, false);
      updateDelayStats(*content_object);
    } else {
      old_nack = onNack(*content_object, true);
    }

    // the nacked_ state is used only to avoid to decrease
    // inflightInterestsCount_ multiple times. In fact, every time that we
    // receive an event related to an interest (timeout, nacked, content) we
    // cange the state. In this way we are sure that we do not decrease twice
    // the counter
    if (old_nack) {
      inflightInterests_[pkt].state = lost_;
      interestRetransmissions_.erase(segmentNumber);
    } else {
      inflightInterests_[pkt].state = nacked_;
    }

  } else {
    avgPacketSize_ = (HICN_ESTIMATED_PACKET_SIZE * avgPacketSize_) +
                     ((1 - HICN_ESTIMATED_PACKET_SIZE) * payload->length());

    receivedBytes_ += (uint32_t)(content_object->headerSize() +
                                 content_object->payloadSize());

    if (inflightInterests_[pkt].state == sent_) {
      lastEvent_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();
      packets_in_window_.erase(segmentNumber);
      inflightInterestsCount_--;  // packet sent without timeouts
    }

    if (inflightInterests_[pkt].state == sent_ && !is_rtx) {
      // delay stats are computed only for non retransmitted data
      updateDelayStats(*content_object);
    }

    addRetransmissions(lastReceived_ + 1, segmentNumber);
    if (segmentNumber > highestReceived_) {
      highestReceived_ = segmentNumber;
    }
    if (segmentNumber > lastReceived_) {
      lastReceived_ = segmentNumber;
      lastReceivedTime_ =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count();
    }
    receivedData_++;
    inflightInterests_[pkt].state = received_;

    auto it = interestRetransmissions_.find(segmentNumber);
    if (it != interestRetransmissions_.end()) lossRecovered_++;

    interestRetransmissions_.erase(segmentNumber);

    reassemble(std::move(content_object));
    increaseWindow();
  }

  scheduleNextInterests();
}

}  // end namespace protocol

}  // end namespace transport
