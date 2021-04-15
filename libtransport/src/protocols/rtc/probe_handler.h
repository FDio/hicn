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
#pragma once
#include <hicn/transport/config.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <functional>
#include <random>
#include <unordered_map>

namespace transport {

namespace protocol {

namespace rtc {

class ProbeHandler : public std::enable_shared_from_this<ProbeHandler> {
 public:
  using SendProbeCallback = std::function<void(uint32_t)>;

 public:
  ProbeHandler(SendProbeCallback &&send_callback,
               asio::io_service &io_service);

  ~ProbeHandler();

  // if the function returns 0 the probe is not valaid
  uint64_t getRtt(uint32_t seq);

  // reset the probes parameters. it stop the current probing.
  // to restar call sendProbes.
  // probe_interval = 0 means that no event will be scheduled
  // max_probe = 0 means no limit to the number of probe to send
  void setProbes(uint32_t probe_interval, uint32_t max_probes);

  // stop to schedule probes
  void stopProbes();

  void sendProbes();

 private:
  uint32_t probe_interval_;  // us
  uint32_t max_probes_; // packets
  uint32_t sent_probes_; // packets

  std::unique_ptr<asio::steady_timer> probe_timer_;

  // map from seqnumber to timestamp
  std::unordered_map<uint32_t, uint64_t> pending_probes_;

  // random generator
  std::default_random_engine rand_eng_;
  std::uniform_int_distribution<uint32_t> distr_;

  SendProbeCallback send_probe_callback_;
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
