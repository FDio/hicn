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

#include <core/portal.h>
#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/utils/noncopyable.h>

#include <random>

namespace transport {

namespace protocol {

class Protocol : public core::Portal::TransportCallback, utils::NonCopyable {
 public:
  virtual void stop() {
    portal_->getThread().addAndWaitForExecution([this]() {
      unSetRunning();
      portal_->unregisterTransportCallback();
      portal_->clear();
    });
  }

  virtual void onInterest(core::Interest &i) {
    throw errors::RuntimeException("Not implemented");
  }

  virtual void onContentObject(core::Interest &i, core::ContentObject &c) {
    throw errors::RuntimeException("Not implemented");
  }

  virtual void onTimeout(core::Interest::Ptr &i, const core::Name &n) {
    throw errors::RuntimeException("Not implemented");
  }

  virtual void onError(const std::error_code &ec) {
    throw errors::RuntimeException("Not implemented");
  }

  bool isRunning() { return is_running_; }
  void setRunning() { is_running_ = true; }
  void unSetRunning() { is_running_ = false; }

 protected:
  Protocol() : portal_(nullptr), is_running_(false), gen_(rd_()) {}
  virtual ~Protocol() {}

 protected:
  std::shared_ptr<core::Portal> portal_;
  std::atomic_bool is_running_;

  // Random engine
  std::random_device rd_;
  std::mt19937 gen_;
};

}  // namespace protocol

}  // namespace transport