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

#include <hicn/transport/interfaces/socket.h>
#include <hicn/transport/utils/object_pool.h>
#include <hicn/transport/utils/sharable_vector.h>

namespace transport {

namespace protocol {

using namespace core;

class TransportProtocolCallback {
  virtual void onContentObject(const core::Interest &interest,
                               const core::ContentObject &content_object) = 0;
  virtual void onTimeout(const core::Interest &interest) = 0;
};

class TransportProtocol : public interface::BasePortal::ConsumerCallback {
  static constexpr std::size_t interest_pool_size = 4096;

 public:
  TransportProtocol(interface::BaseSocket *icn_socket);

  virtual ~TransportProtocol();

  void updatePortal();

  bool isRunning();

  virtual void start(utils::SharableVector<uint8_t> &content_buffer) = 0;

  virtual void stop() = 0;

  virtual void resume() = 0;

 protected:
  virtual void increasePoolSize(std::size_t size = interest_pool_size);

  TRANSPORT_ALWAYS_INLINE Interest::Ptr getInterest() {
    auto result = interest_pool_.get();

    while (TRANSPORT_EXPECT_FALSE(!result.first)) {
      // Add packets to the pool
      increasePoolSize();
      result = interest_pool_.get();
    }

    return std::move(result.second);
  }
  // Consumer Callback
  virtual void onContentObject(Interest::Ptr &&i, ContentObject::Ptr &&c) = 0;
  virtual void onTimeout(Interest::Ptr &&i) = 0;

 protected:
  interface::ConsumerSocket *socket_;
  std::shared_ptr<interface::BasePortal> portal_;
  volatile bool is_running_;
  utils::ObjectPool<Interest> interest_pool_;
};

}  // end namespace protocol

}  // end namespace transport
