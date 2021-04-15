/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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

#include <protocols/rtc/probe_handler.h>
#include <protocols/rtc/rtc_consts.h>

namespace transport {

namespace protocol {

namespace rtc {

ProbeHandler::ProbeHandler(uint32_t min_prob_seq, uint32_t max_prob_seq,
                           uint32_t probe_interval,
                           SendProbeCallback &&send_callback,
                           asio::io_service &io_service)
    : probe_interval_(probe_interval),
      probe_timer_(std::make_unique<asio::steady_timer>(io_service)),
      rand_eng_((std::random_device())()),
      distr_(min_prob_seq, max_prob_seq),
      send_probe_callback_(std::move(send_callback)) {}

ProbeHandler::~ProbeHandler() {}

uint64_t ProbeHandler::getRtt(uint32_t seq) {
  auto it = pending_probes_.find(seq);

  if (it == pending_probes_.end()) return 0;

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
  uint64_t rtt = now - it->second;

  pending_probes_.erase(it);

  return rtt;
}

void ProbeHandler::sendProbesNow(uint32_t probe_interval) {
  probe_timer_->cancel();
  probe_interval_ = probe_interval;
  sendProbes();
}

void ProbeHandler::stopProbes() {
  probe_interval_ = 0;
  probe_timer_->cancel();
}

void ProbeHandler::sendProbes() {
  if (probe_interval_ == 0) return;

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  uint32_t seq = distr_(rand_eng_);
  pending_probes_.insert(std::pair<uint32_t, uint64_t>(seq, now));
  send_probe_callback_(seq);

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

  if (probe_interval_ == 0) return;

  std::weak_ptr<ProbeHandler> self(shared_from_this());
  probe_timer_->expires_from_now(std::chrono::milliseconds(probe_interval_));
  probe_timer_->async_wait([self](std::error_code ec) {
    if (ec) return;
    if (auto s = self.lock()) {
      s->sendProbes();
    }
  });
}

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
