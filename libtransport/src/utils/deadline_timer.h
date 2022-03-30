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

#include <utils/event_reactor.h>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <utility>

namespace utils {

template <typename Implementation>
class DeadlineTimer {
 public:
  virtual ~DeadlineTimer() = default;

  template <typename WaitHandler>
  void asyncWait(WaitHandler &&callback) {
    static_cast<Implementation *>(this)->asyncWaitImpl(
        std::forward<WaitHandler>(callback));
  }

  void wait() { static_cast<Implementation *>(this)->waitImpl(); }

  template <typename T, typename R>
  void expiresFromNow(std::chrono::duration<T, R> &&duration) {
    static_cast<Implementation *>(this)->expiresFromNowImpl(
        std::forward<std::chrono::duration<T, R>>(duration));
  }

  template <typename TimePoint,
            typename = typename std::enable_if<
                std::is_same<std::remove_reference_t<TimePoint>,
                             std::chrono::steady_clock::time_point>::value,
                TimePoint>::type>
  void expiresAt(TimePoint &&time_point) {
    static_cast<Implementation *>(this)->expiresAtImpl(
        std::forward<TimePoint>(time_point));
  }

  void cancel() { static_cast<Implementation *>(this)->cancelImpl(); }
};

}  // namespace utils
