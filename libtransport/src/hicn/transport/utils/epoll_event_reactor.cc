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

#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/epoll_event_reactor.h>
#include <hicn/transport/utils/fd_deadline_timer.h>

#include <signal.h>
#include <unistd.h>
#include <iostream>

namespace utils {

EpollEventReactor::EpollEventReactor()
    : epoll_fd_(epoll_create(20000)), run_event_loop_(true) {}

EpollEventReactor::~EpollEventReactor() { close(epoll_fd_); }

int EpollEventReactor::addFileDescriptor(int fd, uint32_t events) {
  if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
    TRANSPORT_LOGE("invalid fd %d", fd);
    return -1;
  }

  struct epoll_event evt;
  std::memset(&evt, 0, sizeof(evt));
  evt.events = events;
  evt.data.fd = fd;

  if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &evt) <
                             0)) {
    TRANSPORT_LOGE("epoll_ctl: %s fd %d", strerror(errno), fd);
    return -1;
  }

  return 0;
}

int EpollEventReactor::addFileDescriptor(int fd, uint32_t events,
                                         EventCallback &callback) {
  auto it = event_callback_map_.find(fd);
  event_callback_map_[fd] = callback;
  if (it != event_callback_map_.end()) {
    event_callback_map_[fd] = callback;
  } else {
    return addFileDescriptor(fd, events);
  }

  return 0;
}

int EpollEventReactor::addFileDescriptor(int fd, uint32_t events,
                                         EventCallback &&callback) {
  auto it = event_callback_map_.find(fd);
  event_callback_map_[fd] = callback;
  if (it != event_callback_map_.end()) {
    event_callback_map_[fd] = callback;
  } else {
    return addFileDescriptor(fd, events);
  }

  return 0;
}

int EpollEventReactor::modFileDescriptor(int fd, uint32_t events) {
  if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
    TRANSPORT_LOGE("invalid fd %d", fd);
    return -1;
  }

  struct epoll_event evt;
  memset(&evt, 0, sizeof(evt));
  evt.events = events;
  evt.data.fd = fd;

  if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &evt) <
                             0)) {
    TRANSPORT_LOGE("epoll_ctl: %s fd %d", strerror(errno), fd);
    return -1;
  }

  return 0;
}

std::size_t EpollEventReactor::mapSize() { return event_callback_map_.size(); }

int EpollEventReactor::delFileDescriptor(int fd) {
  if (TRANSPORT_EXPECT_FALSE(fd < 0)) {
    TRANSPORT_LOGE("invalid fd %d", fd);
    return -1;
  }

  struct epoll_event evt;
  memset(&evt, 0, sizeof(evt));

  if (TRANSPORT_EXPECT_FALSE(epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &evt) <
                             0)) {
    TRANSPORT_LOGE("epoll_ctl: %s fd %d", strerror(errno), fd);
    return -1;
  }

  event_callback_map_.erase(fd);

  return 0;
}

void EpollEventReactor::runEventLoop(int timeout) {
  Event evt[128];
  int en = 0;

  // evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset(&sigset);

  while (run_event_loop_) {
    memset(&evt, 0, sizeof(evt));

    en = epoll_pwait(epoll_fd_, evt, 128, timeout, &sigset);

    if (TRANSPORT_EXPECT_FALSE(en < 0)) {
      TRANSPORT_LOGE("epoll_pwait: %s", strerror(errno));
      return;
    }

    for (int i = 0; i < en; i++) {
      if (evt[i].data.fd > 0) {
        auto it = event_callback_map_.find(evt[i].data.fd);
        if (TRANSPORT_EXPECT_FALSE(it == event_callback_map_.end())) {
          TRANSPORT_LOGE("unexpected event. fd %d", evt[i].data.fd);
        } else {
          event_callback_map_[evt[i].data.fd](evt[i]);
        }
      } else {
        TRANSPORT_LOGE("unexpected event. fd %d", evt[i].data.fd);
      }
    }
  }
}

void EpollEventReactor::runOneEvent() {
  Event evt;
  int en = 0;

  //  evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset(&sigset);

  memset(&evt, 0, sizeof(evt));

  en = epoll_pwait(epoll_fd_, &evt, 1, -1, &sigset);

  if (TRANSPORT_EXPECT_FALSE(en < 0)) {
    TRANSPORT_LOGE("epoll_pwait: %s", strerror(errno));
    return;
  }

  if (TRANSPORT_EXPECT_TRUE(evt.data.fd > 0)) {
    auto it = event_callback_map_.find(evt.data.fd);
    if (TRANSPORT_EXPECT_FALSE(it == event_callback_map_.end())) {
      TRANSPORT_LOGE("unexpected event. fd %d", evt.data.fd);
    } else {
      event_callback_map_[evt.data.fd](evt);
    }
  } else {
    TRANSPORT_LOGE("unexpected event. fd %d", evt.data.fd);
  }
}

void EpollEventReactor::stop() { run_event_loop_ = false; }

}  // namespace utils