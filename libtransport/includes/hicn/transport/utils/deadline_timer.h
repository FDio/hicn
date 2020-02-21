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

#include <utils/event_reactor.h>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <utility>

namespace std {
namespace chrono {
namespace detail {

template <typename From, typename To>
struct posix_duration_cast;

// chrono -> timespec caster
template <typename Rep, typename Period>
struct posix_duration_cast<std::chrono::duration<Rep, Period>,
                           struct timespec> {
  static struct timespec cast(std::chrono::duration<Rep, Period> const &d) {
    struct timespec tv;

    std::chrono::seconds const sec =
        std::chrono::duration_cast<std::chrono::seconds>(d);

    tv.tv_sec = sec.count();
    tv.tv_nsec =
        std::chrono::duration_cast<std::chrono::nanoseconds>(d - sec).count();

    return tv;
  }
};

// timespec -> chrono caster
template <typename Rep, typename Period>
struct posix_duration_cast<struct timespec,
                           std::chrono::duration<Rep, Period>> {
  static std::chrono::duration<Rep, Period> cast(struct timespec const &tv) {
    return std::chrono::duration_cast<std::chrono::duration<Rep, Period>>(
        std::chrono::seconds(tv.tv_sec) + std::chrono::nanoseconds(tv.tv_nsec));
  }
};

}  // namespace detail

// chrono -> timespec
template <typename T, typename Rep, typename Period>
auto duration_cast(std::chrono::duration<Rep, Period> const &d) ->
    typename std::enable_if<std::is_same<T, struct timespec>::value,
                            struct timespec>::type {
  return detail::posix_duration_cast<std::chrono::duration<Rep, Period>,
                                     timespec>::cast(d);
}

// timespec -> chrono
template <typename Duration>
Duration duration_cast(struct timespec const &tv) {
  return detail::posix_duration_cast<struct timespec, Duration>::cast(tv);
}

}  // namespace chrono
}  // namespace std

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
