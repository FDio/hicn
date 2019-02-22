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

#include <hicn/transport/utils/event_reactor.h>

#include <sys/epoll.h>
#include <cstddef>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <atomic>

#define FD_NUMBER 20000

namespace utils {

typedef struct epoll_event Event;
typedef std::function<int(const Event &)> EventCallback;
typedef std::unordered_map<int, EventCallback> EventCallbackMap;

class EpollEventReactor : public EventReactor {
 public:
  explicit EpollEventReactor();

  ~EpollEventReactor();

  int addFileDescriptor(int fd, uint32_t events, EventCallback &callback);

  int addFileDescriptor(int fd, uint32_t events, EventCallback &&callback);

  int delFileDescriptor(int fd);

  int modFileDescriptor(int fd, uint32_t events);

  void runEventLoop(int timeout = -1) override;

  void runOneEvent() override;

  void stop() override;

  std::size_t mapSize();

 private:
  int addFileDescriptor(int fd, uint32_t events);

  int epoll_fd_;
  std::atomic_bool run_event_loop_;
  EventCallbackMap event_callback_map_;
  std::mutex event_callback_map_mutex_;
};

}  // namespace utils
