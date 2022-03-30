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

#include <glog/logging.h>
#include <hicn/transport/utils/spinlock.h>
#include <sys/epoll.h>
#include <utils/event_reactor.h>

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <unordered_map>

#define FD_NUMBER 20000

namespace utils {

typedef struct epoll_event Event;
typedef std::function<int(const Event &)> EventCallback;
typedef std::unordered_map<int, EventCallback> EventCallbackMap;

class EpollEventReactor : public EventReactor {
 public:
  explicit EpollEventReactor()
      : epoll_fd_(epoll_create(20000)), run_event_loop_(true) {}

  ~EpollEventReactor() { close(epoll_fd_); }

  template <typename EventHandler>
  int addFileDescriptor(int fd, uint32_t events, EventHandler &&callback) {
    auto it = event_callback_map_.find(fd);
    int ret = 0;

    if (it == event_callback_map_.end()) {
      {
        utils::SpinLock::Acquire locked(event_callback_map_lock_);
        event_callback_map_[fd] = std::forward<EventHandler &&>(callback);
      }

      ret = addFileDescriptor(fd, events);
    }

    return ret;
  }

  int delFileDescriptor(int fd) {
    if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
      LOG(ERROR) << "invalid fd " << fd;
      return -1;
    }

    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));

    if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &evt) <
                               0)) {
      return -1;
    }

    utils::SpinLock::Acquire locked(event_callback_map_lock_);
    event_callback_map_.erase(fd);

    return 0;
  }

  int modFileDescriptor(int fd, uint32_t events) {
    if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
      LOG(ERROR) << "invalid fd " << fd;
      return -1;
    }

    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;

    if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &evt) <
                               0)) {
      LOG(ERROR) << "epoll_ctl: " << strerror(errno) << " fd " << fd;
      return -1;
    }

    return 0;
  }

  void runEventLoop(int timeout = -1) override {
    Event evt[128];
    int en = 0;
    EventCallbackMap::iterator it;
    EventCallback callback;

    // evt.events = EPOLLIN | EPOLLOUT;
    sigset_t sigset;
    sigemptyset(&sigset);

    while (run_event_loop_) {
      memset(&evt, 0, sizeof(evt));
      en = epoll_pwait(epoll_fd_, evt, 128, timeout, &sigset);

      if (TRANSPORT_EXPECT_FALSE(en < 0)) {
        LOG(ERROR) << "epoll_pwait: " << strerror(errno);
        if (errno == EINTR) {
          continue;
        } else {
          return;
        }
      }

      for (int i = 0; i < en; i++) {
        if (evt[i].data.fd > 0) {
          {
            utils::SpinLock::Acquire locked(event_callback_map_lock_);
            it = event_callback_map_.find(evt[i].data.fd);
          }

          if (TRANSPORT_EXPECT_FALSE(it == event_callback_map_.end())) {
            LOG(ERROR) << "unexpected event. fd " << evt[i].data.fd;
          } else {
            {
              utils::SpinLock::Acquire locked(event_callback_map_lock_);
              callback = event_callback_map_[evt[i].data.fd];
            }

            callback(evt[i]);

            // In the callback the epoll event reactor could have been stopped,
            // then we need to check whether the event loop is still running.
            if (TRANSPORT_EXPECT_FALSE(!run_event_loop_)) {
              return;
            }
          }
        } else {
          LOG(ERROR) << "unexpected event. fd " << evt[i].data.fd;
        }
      }
    }
  }

  void runOneEvent() override {
    Event evt;
    int en = 0;
    EventCallbackMap::iterator it;
    EventCallback callback;

    //  evt.events = EPOLLIN | EPOLLOUT;
    sigset_t sigset;
    sigemptyset(&sigset);

    memset(&evt, 0, sizeof(evt));

    en = epoll_pwait(epoll_fd_, &evt, 1, -1, &sigset);

    if (TRANSPORT_EXPECT_FALSE(en < 0)) {
      LOG(ERROR) << "epoll_pwait: " << strerror(errno);
      return;
    }

    if (TRANSPORT_EXPECT_TRUE(evt.data.fd > 0)) {
      {
        utils::SpinLock::Acquire locked(event_callback_map_lock_);
        it = event_callback_map_.find(evt.data.fd);
      }

      if (TRANSPORT_EXPECT_FALSE(it == event_callback_map_.end())) {
        LOG(ERROR) << "unexpected event. fd " << evt.data.fd;
      } else {
        {
          utils::SpinLock::Acquire locked(event_callback_map_lock_);
          callback = event_callback_map_[evt.data.fd];
        }

        callback(evt);
      }
    } else {
      LOG(ERROR) << "unexpected event. fd " << evt.data.fd;
    }
  }

  void stop() override { run_event_loop_ = false; }

  std::size_t mapSize() { return event_callback_map_.size(); }

 private:
  int addFileDescriptor(int fd, uint32_t events) {
    if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
      LOG(ERROR) << "invalid fd " << fd;
      return -1;
    }

    struct epoll_event evt;
    std::memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;

    if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &evt) <
                               0)) {
      LOG(ERROR) << "epoll_ctl: " << strerror(errno) << " fd " << fd;
      return -1;
    }

    return 0;
  }

  int epoll_fd_;
  std::atomic_bool run_event_loop_;
  EventCallbackMap event_callback_map_;
  utils::SpinLock event_callback_map_lock_;
};

}  // namespace utils
