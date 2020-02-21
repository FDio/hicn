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

#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/utils/log.h>

#include <utils/deadline_timer.h>
#include <utils/epoll_event_reactor.h>

#include <chrono>
#include <cstddef>

#include <sys/timerfd.h>
#include <unistd.h>

namespace utils {

class FdDeadlineTimer : public DeadlineTimer<FdDeadlineTimer> {
 public:
  explicit FdDeadlineTimer(EpollEventReactor &reactor)
      : reactor_(reactor),
        timer_fd_(timerfd_create(CLOCK_MONOTONIC, 0)),
        flags_(0) {
    if (timer_fd_ == -1) {
      throw errors::RuntimeException("Impossible to create the timer!");
    }
  }

  ~FdDeadlineTimer() { close(timer_fd_); }

  template <typename WaitHandler>
  void asyncWaitImpl(WaitHandler &&callback) {
    // ASIO_WAIT_HANDLER_CHECK(WaitHandler, callback) type_check;

    if (timerfd_settime(timer_fd_, flags_, &new_value_, NULL) == -1) {
      throw errors::RuntimeException("Impossible to set the timer!");
    }

    uint32_t events = EPOLLIN;

    reactor_.addFileDescriptor(
        timer_fd_, events,
        [callback = std::forward<WaitHandler &&>(callback)](
            const Event &event) -> int {
          uint64_t s = 0;
          std::error_code ec;

          if (read(event.data.fd, &s, sizeof(s)) == -1) {
            TRANSPORT_LOGE("Read error!!");
          }

          if (!(event.events & EPOLLIN)) {
            ec = std::make_error_code(std::errc::operation_canceled);
          }

          callback(ec);

          return 0;
        });
  }

  void waitImpl() {
    if (timerfd_settime(timer_fd_, flags_, &new_value_, NULL) == -1) {
      throw errors::RuntimeException("Impossible to set the timer!");
    }

    uint64_t ret;

    if (read(timer_fd_, &ret, sizeof(ret)) == -1) {
      throw errors::RuntimeException(
          "Error while waiting for the timer expiration.");
    }
  }

  template <typename T, typename R>
  void expiresFromNowImpl(std::chrono::duration<T, R> &&duration) {
    std::memset(&new_value_, 0, sizeof(new_value_));
    new_value_.it_value = std::chrono::duration_cast<struct timespec>(
        std::forward<std::chrono::duration<T, R>>(duration));
  }

  template <typename TimePoint,
            typename = std::enable_if_t<
                std::is_same<std::remove_reference_t<TimePoint>,
                             std::chrono::steady_clock::time_point>::value,
                TimePoint>>
  void expiresAtImpl(TimePoint &&time_point) {
    std::memset(&new_value_, 0, sizeof(new_value_));

    new_value_.it_value = std::chrono::duration_cast<struct timespec>(
        time_point.time_since_epoch());
    flags_ |= TFD_TIMER_ABSTIME;
  }

  void cancelImpl() {
    std::memset(&new_value_, 0, sizeof(new_value_));

    if (timerfd_settime(timer_fd_, 0, &new_value_, NULL) == -1) {
      throw errors::RuntimeException("Impossible to cancel the timer!");
    }

    // reactor_.delFileDescriptor(timer_fd_);
  }

  EventReactor &getEventReactor() { return reactor_; }

 private:
  EpollEventReactor &reactor_;
  int timer_fd_;
  EventCallback callback_;
  struct itimerspec new_value_;
  int flags_;
};

}  // namespace utils
