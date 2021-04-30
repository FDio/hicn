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

#pragma once

#include <hicn/transport/core/content_object.h>

#include <functional>

namespace transport {
namespace protocol {

/**
 * Interface classes to integrate FEC inside any producer transport protocol
 */
class ProducerFECBase {
 public:
  /**
   * Callback, to be called by implementations as soon as a repair packet is
   * ready.
   */
  using RepairPacketsReady =
      std::function<void(std::vector<core::ContentObject::Ptr> &)>;

  /**
   * Producers will call this function upon production of a new packet.
   */
  virtual void onPacketProduced(const core::ContentObject &content_object) = 0;

  /**
   * Set callback to signal production protocol the repair packet is ready.
   */
  void setFECCallback(const RepairPacketsReady &on_repair_packet) {
    rep_packet_ready_callback_ = on_repair_packet;
  }

 protected:
  RepairPacketsReady rep_packet_ready_callback_;
};

/**
 * Interface classes to integrate FEC inside any consumer transport protocol
 */
class ConsumerFECBase {
 public:
  /**
   * Callback, to be called by implemrntations as soon as a packet is recovered.
   */
  using OnPacketsRecovered =
      std::function<void(std::vector<core::ContentObject::Ptr> &)>;

  /**
   * Consumers will call this function when they receive a FEC packet.
   */
  virtual void onFECPacket(const core::ContentObject &content_object) = 0;

  /**
   * Consumers will call this function when they receive a data packet
   */
  virtual void onDataPacket(const core::ContentObject &content_object) = 0;

  /**
   * Set callback to signal consumer protocol the repair packet is ready.
   */
  void setFECCallback(const OnPacketsRecovered &on_repair_packet) {
    packet_recovered_callback_ = on_repair_packet;
  }

 protected:
  OnPacketsRecovered packet_recovered_callback_;
};

}  // namespace protocol
}  // namespace transport