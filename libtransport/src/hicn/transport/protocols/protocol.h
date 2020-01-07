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

#pragma once

#include <atomic>

#include <hicn/transport/interfaces/socket.h>
#include <hicn/transport/protocols/packet_manager.h>
#include <hicn/transport/protocols/statistics.h>
#include <hicn/transport/utils/object_pool.h>

namespace transport {

namespace protocol {

using namespace core;

class TransportProtocolCallback {
  virtual void onContentObject(const core::Interest &interest,
                               const core::ContentObject &content_object) = 0;
  virtual void onTimeout(const core::Interest &interest) = 0;
};

class TransportProtocol : public interface::BasePortal::ConsumerCallback,
                          public PacketManager<Interest> {
  static constexpr std::size_t interest_pool_size = 4096;

 public:
  TransportProtocol(interface::ConsumerSocket *icn_socket);

  virtual ~TransportProtocol() = default;

  TRANSPORT_ALWAYS_INLINE bool isRunning() { return is_running_; }

  virtual int start();

  virtual void stop();

  virtual void resume();

  virtual bool verifyKeyPackets() = 0;

  virtual void scheduleNextInterests() = 0;

 protected:
  // Consumer Callback
  virtual void reset() = 0;
  virtual void onContentObject(Interest::Ptr &&i, ContentObject::Ptr &&c) = 0;
  virtual void onTimeout(Interest::Ptr &&i) = 0;

 protected:
  interface::ConsumerSocket *socket_;
  std::shared_ptr<interface::BasePortal> portal_;
  std::atomic<bool> is_running_;
  // True if it si the first time we schedule an interest
  std::atomic<bool> is_first_;
  TransportStatistics stats_;
};

}  // end namespace protocol

}  // end namespace transport
