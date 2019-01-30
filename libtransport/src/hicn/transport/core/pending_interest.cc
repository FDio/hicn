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

#include <hicn/transport/core/pending_interest.h>

namespace transport {

namespace core {

PendingInterest::PendingInterest()
    : interest_(nullptr, nullptr),
      timer_(),
      on_content_object_callback_(),
      on_interest_timeout_callback_(),
      received_(false) {}

PendingInterest::PendingInterest(Interest::Ptr &&interest,
                                 std::unique_ptr<asio::steady_timer> &&timer)
    : interest_(std::move(interest)),
      timer_(std::move(timer)),
      on_content_object_callback_(),
      on_interest_timeout_callback_(),
      received_(false) {}

PendingInterest::PendingInterest(
    Interest::Ptr &&interest, const OnContentObjectCallback &&on_content_object,
    const OnInterestTimeoutCallback &&on_interest_timeout,
    std::unique_ptr<asio::steady_timer> &&timer)
    : interest_(std::move(interest)),
      timer_(std::move(timer)),
      on_content_object_callback_(std::move(on_content_object)),
      on_interest_timeout_callback_(std::move(on_interest_timeout)),
      received_(false) {}

PendingInterest::~PendingInterest() {
  // timer_.reset();
}

void PendingInterest::cancelTimer() { timer_->cancel(); }

void PendingInterest::setReceived() { received_ = true; }

bool PendingInterest::isReceived() const { return received_; }

Interest::Ptr &&PendingInterest::getInterest() { return std::move(interest_); }

const OnContentObjectCallback &PendingInterest::getOnDataCallback() const {
  return on_content_object_callback_;
}

void PendingInterest::setOnDataCallback(
    const OnContentObjectCallback &on_content_object) {
  PendingInterest::on_content_object_callback_ = on_content_object;
}

const OnInterestTimeoutCallback &PendingInterest::getOnTimeoutCallback() const {
  return on_interest_timeout_callback_;
}

void PendingInterest::setOnTimeoutCallback(
    const OnInterestTimeoutCallback &on_interest_timeout) {
  PendingInterest::on_interest_timeout_callback_ = on_interest_timeout;
}

}  // end namespace core

}  // end namespace transport
