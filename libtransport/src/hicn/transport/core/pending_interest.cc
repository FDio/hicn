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
    : interest_(nullptr, nullptr), timer_(), received_(false) {}

PendingInterest::PendingInterest(Interest::Ptr &&interest,
                                 std::unique_ptr<asio::steady_timer> &&timer)
    : interest_(std::move(interest)),
      timer_(std::move(timer)),
      received_(false) {}

PendingInterest::~PendingInterest() {
  // timer_.reset();
}

void PendingInterest::cancelTimer() { timer_->cancel(); }

bool PendingInterest::isReceived() const { return received_; }

void PendingInterest::setReceived() { received_ = true; }

Interest::Ptr &&PendingInterest::getInterest() { return std::move(interest_); }

void PendingInterest::setReceived(bool received) {
  PendingInterest::received_ = received;
}

}  // end namespace core

}  // end namespace transport