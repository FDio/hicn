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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/deadline_timer.h>

#include <asio/steady_timer.hpp>

namespace transport {

namespace core {

class HicnForwarderInterface;
class VPPForwarderInterface;
class RawSocketInterface;

template <typename ForwarderInt>
class Portal;

typedef std::function<void(Interest::Ptr &&, ContentObject::Ptr &&)>
    OnContentObjectCallback;
typedef std::function<void(Interest::Ptr &&)> OnInterestTimeoutCallback;
typedef std::function<void(const std::error_code &)> TimerCallback;

class PendingInterest {
  friend class Portal<HicnForwarderInterface>;
  friend class Portal<VPPForwarderInterface>;
  friend class Portal<RawSocketInterface>;

 public:
  PendingInterest();

  PendingInterest(Interest::Ptr &&interest,
                  std::unique_ptr<asio::steady_timer> &&timer);

  PendingInterest(Interest::Ptr &&interest,
                  const OnContentObjectCallback &&on_content_object,
                  const OnInterestTimeoutCallback &&on_interest_timeout,
                  std::unique_ptr<asio::steady_timer> &&timer);

  ~PendingInterest();

  template <typename Handler>
  TRANSPORT_ALWAYS_INLINE void startCountdown(Handler &&cb) {
    timer_->expires_from_now(
        std::chrono::milliseconds(interest_->getLifetime()));
    timer_->async_wait(cb);
  }

  void cancelTimer();

  void setReceived();

  bool isReceived() const;

  Interest::Ptr &&getInterest();

  const OnContentObjectCallback &getOnDataCallback() const;

  void setOnDataCallback(const OnContentObjectCallback &on_content_object);

  const OnInterestTimeoutCallback &getOnTimeoutCallback() const;

  void setOnTimeoutCallback(
      const OnInterestTimeoutCallback &on_interest_timeout);

 private:
  Interest::Ptr interest_;
  std::unique_ptr<asio::steady_timer> timer_;
  OnContentObjectCallback on_content_object_callback_;
  OnInterestTimeoutCallback on_interest_timeout_callback_;
  bool received_;
};

}  // end namespace core

}  // end namespace transport
