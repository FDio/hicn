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

#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/interfaces/portal.h>
#include <hicn/transport/portability/portability.h>

#include <utils/deadline_timer.h>

#include <asio/steady_timer.hpp>

namespace transport {

namespace core {

class HicnForwarderInterface;
class VPPForwarderInterface;
class RawSocketInterface;

template <typename ForwarderInt>
class Portal;

using OnContentObjectCallback = interface::Portal::OnContentObjectCallback;
using OnInterestTimeoutCallback = interface::Portal::OnInterestTimeoutCallback;

class PendingInterest {
  friend class Portal<HicnForwarderInterface>;
  friend class Portal<VPPForwarderInterface>;
  friend class Portal<RawSocketInterface>;

 public:
  using Ptr = utils::ObjectPool<PendingInterest>::Ptr;
  PendingInterest()
      : interest_(nullptr, nullptr),
        timer_(),
        on_content_object_callback_(),
        on_interest_timeout_callback_() {}

  PendingInterest(Interest::Ptr &&interest,
                  std::unique_ptr<asio::steady_timer> &&timer)
      : interest_(std::move(interest)),
        timer_(std::move(timer)),
        on_content_object_callback_(),
        on_interest_timeout_callback_() {}

  PendingInterest(Interest::Ptr &&interest,
                  OnContentObjectCallback &&on_content_object,
                  OnInterestTimeoutCallback &&on_interest_timeout,
                  std::unique_ptr<asio::steady_timer> &&timer)
      : interest_(std::move(interest)),
        timer_(std::move(timer)),
        on_content_object_callback_(std::move(on_content_object)),
        on_interest_timeout_callback_(std::move(on_interest_timeout)) {}

  ~PendingInterest() = default;

  template <typename Handler>
  TRANSPORT_ALWAYS_INLINE void startCountdown(Handler &&cb) {
    timer_->expires_from_now(
        std::chrono::milliseconds(interest_->getLifetime()));
    timer_->async_wait(std::forward<Handler &&>(cb));
  }

  TRANSPORT_ALWAYS_INLINE void cancelTimer() { timer_->cancel(); }

  TRANSPORT_ALWAYS_INLINE Interest::Ptr &&getInterest() {
    return std::move(interest_);
  }

  TRANSPORT_ALWAYS_INLINE void setInterest(Interest::Ptr &&interest) {
    interest_ = std::move(interest);
  }

  TRANSPORT_ALWAYS_INLINE const OnContentObjectCallback &getOnDataCallback()
      const {
    return on_content_object_callback_;
  }

  TRANSPORT_ALWAYS_INLINE void setOnContentObjectCallback(
      OnContentObjectCallback &&on_content_object) {
    PendingInterest::on_content_object_callback_ = on_content_object;
  }

  TRANSPORT_ALWAYS_INLINE const OnInterestTimeoutCallback &
  getOnTimeoutCallback() const {
    return on_interest_timeout_callback_;
  }

  TRANSPORT_ALWAYS_INLINE void setOnTimeoutCallback(
      OnInterestTimeoutCallback &&on_interest_timeout) {
    PendingInterest::on_interest_timeout_callback_ = on_interest_timeout;
  }

 private:
  Interest::Ptr interest_;
  std::unique_ptr<asio::steady_timer> timer_;
  OnContentObjectCallback on_content_object_callback_;
  OnInterestTimeoutCallback on_interest_timeout_callback_;
};

}  // end namespace core

}  // end namespace transport
