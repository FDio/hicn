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

#include <hicn/transport/config.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/interfaces/portal.h>
#include <hicn/transport/portability/portability.h>
#include <utils/deadline_timer.h>

namespace transport {

namespace core {

class HicnForwarderInterface;
class VPPForwarderInterface;
class RawSocketInterface;

class Portal;

using OnContentObjectCallback = interface::Portal::OnContentObjectCallback;
using OnInterestTimeoutCallback = interface::Portal::OnInterestTimeoutCallback;

class PendingInterest {
  friend class Portal;

 public:
  using Ptr = utils::ObjectPool<PendingInterest>::Ptr;

  PendingInterest(asio::io_service &io_service, const Interest::Ptr &interest)
      : interest_(interest), timer_(io_service) {}

  PendingInterest(asio::io_service &io_service, const Interest::Ptr &interest,
                  OnContentObjectCallback &&on_content_object,
                  OnInterestTimeoutCallback &&on_interest_timeout)
      : interest_(interest),
        timer_(io_service),
        on_content_object_callback_(std::move(on_content_object)),
        on_interest_timeout_callback_(std::move(on_interest_timeout)) {}

  ~PendingInterest() = default;

  template <typename Handler>
  void startCountdown(uint32_t lifetime, Handler &&cb) {
    timer_.expires_from_now(std::chrono::milliseconds(lifetime));
    timer_.async_wait(std::forward<Handler>(cb));
  }

  void cancelTimer() {
    try {
      timer_.cancel();
    } catch (asio::system_error &e) {
      // do nothing
    }
  }

  Interest::Ptr &&getInterest() { return std::move(interest_); }

  const Interest::Ptr &getInterestReference() const { return interest_; }

  void setInterest(const Interest::Ptr &interest) { interest_ = interest; }

  const OnContentObjectCallback &getOnDataCallback() const {
    return on_content_object_callback_;
  }

  void setOnContentObjectCallback(OnContentObjectCallback &&on_content_object) {
    PendingInterest::on_content_object_callback_ = std::move(on_content_object);
  }

  const OnInterestTimeoutCallback &getOnTimeoutCallback() const {
    return on_interest_timeout_callback_;
  }

  void setOnTimeoutCallback(OnInterestTimeoutCallback &&on_interest_timeout) {
    PendingInterest::on_interest_timeout_callback_ =
        std::move(on_interest_timeout);
  }

 private:
  Interest::Ptr interest_;
  asio::steady_timer timer_;
  OnContentObjectCallback on_content_object_callback_;
  OnInterestTimeoutCallback on_interest_timeout_callback_;
};

}  // end namespace core

}  // end namespace transport
