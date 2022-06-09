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

#include <chrono>

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

template <typename T>
class Time {
 public:
  using Clock = T;
  using TimePoint = typename Clock::time_point;
  using Rep = uint64_t;
  using Seconds = std::chrono::duration<Rep>;
  using Milliseconds = std::chrono::duration<Rep, std::milli>;
  using Microseconds = std::chrono::duration<Rep, std::micro>;

  static auto now() { return Clock::now(); }

  // From epochs
  static auto nowMs() {
    return std::chrono::duration_cast<Milliseconds>(now().time_since_epoch());
  }

  // From epoch
  static auto nowUs() {
    return std::chrono::duration_cast<Microseconds>(now().time_since_epoch());
  }

  template <typename D>
  static auto getDuration(const TimePoint &start, const TimePoint &end) {
    return std::chrono::duration_cast<D>(end - start);
  }

  static auto getDurationS(const TimePoint &start, const TimePoint &end) {
    return getDuration<Seconds>(start, end);
  }
  static auto getDurationMs(const TimePoint &start, const TimePoint &end) {
    return getDuration<Milliseconds>(start, end);
  }
  static auto getDurationUs(const TimePoint &start, const TimePoint &end) {
    return getDuration<Microseconds>(start, end);
  }
};

using SteadyTime = Time<std::chrono::steady_clock>;
using SystemTime = Time<std::chrono::system_clock>;

}  // namespace utils
