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

#include <hicn/transport/utils/chrono_typedefs.h>
#include <protocols/rtc/probe_handler.h>
#include <protocols/rtc/rtc_consts.h>

namespace transport {

namespace protocol {

namespace rtc {

ProbeHandler::ProbeHandler(SendProbeCallback &&send_callback,
                           asio::io_service &io_service)
    : probe_interval_(0),
      max_probes_(0),
      sent_probes_(0),
      recv_probes_(0),
      probe_timer_(std::make_unique<asio::steady_timer>(io_service)),
      rand_eng_((std::random_device())()),
      distr_(MIN_RTT_PROBE_SEQ, MAX_RTT_PROBE_SEQ),
      send_probe_callback_(std::move(send_callback)) {}

ProbeHandler::~ProbeHandler() {}

uint64_t ProbeHandler::getRtt(uint32_t seq, bool is_valid) {
  auto it = pending_probes_.find(seq);

  if (it == pending_probes_.end()) return 0;

  if (!is_valid) {
    // delete the probe anyway
    pending_probes_.erase(it);
    valid_batch_ = false;
    return 0;
  }

  uint64_t now = utils::SteadyTime::nowMs().count();
  uint64_t rtt = now - it->second;
  if (rtt < 1) rtt = 1;

  pending_probes_.erase(it);
  recv_probes_++;

  return rtt;
}

double ProbeHandler::getProbeLossRate() {
  if (!valid_batch_) return 1.0;
  return 1.0 - ((double)recv_probes_ / (double)sent_probes_);
}

void ProbeHandler::setSuffixRange(uint32_t min, uint32_t max) {
  assert(min <= max && min >= MIN_PROBE_SEQ);
  distr_ = std::uniform_int_distribution<uint32_t>(min, max);
}

void ProbeHandler::setProbes(uint32_t probe_interval, uint32_t max_probes) {
  stopProbes();
  probe_interval_ = probe_interval;
  max_probes_ = max_probes;
}

void ProbeHandler::stopProbes() {
  probe_interval_ = 0;
  max_probes_ = 0;
  sent_probes_ = 0;
  recv_probes_ = 0;
  valid_batch_ = true;
  probe_timer_->cancel();
}

void ProbeHandler::sendProbes() {
  if (probe_interval_ == 0) return;

  std::weak_ptr<ProbeHandler> self(shared_from_this());
  probe_timer_->expires_from_now(std::chrono::microseconds(probe_interval_));
  probe_timer_->async_wait([self](const std::error_code &ec) {
    if (ec) return;
    auto s = self.lock();
    if (s) {
      s->generateProbe();
    }
  });
}

void ProbeHandler::generateProbe() {
  if (probe_interval_ == 0) return;
  if (max_probes_ != 0 && sent_probes_ >= max_probes_) return;

  uint64_t now = utils::SteadyTime::nowMs().count();

  uint32_t seq = distr_(rand_eng_);
  pending_probes_.insert(std::pair<uint32_t, uint64_t>(seq, now));
  send_probe_callback_(seq);
  sent_probes_++;

  // clean up
  // a probe may get lost. if the pending_probes_ size becomes bigger than
  // MAX_PENDING_PROBES remove all the probes older than a seconds
  if (pending_probes_.size() > MAX_PENDING_PROBES) {
    for (auto it = pending_probes_.begin(); it != pending_probes_.end();) {
      if ((now - it->second) > 1000)
        it = pending_probes_.erase(it);
      else
        it++;
    }
  }

  sendProbes();
}

ProbeType ProbeHandler::getProbeType(uint32_t seq) {
  if (MIN_INIT_PROBE_SEQ <= seq && seq <= MAX_INIT_PROBE_SEQ) {
    return ProbeType::INIT;
  }
  if (MIN_RTT_PROBE_SEQ <= seq && seq <= MAX_RTT_PROBE_SEQ) {
    return ProbeType::RTT;
  }
  return ProbeType::NOT_PROBE;
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
