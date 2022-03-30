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

#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/noncopyable.h>

#include <thread>
#include <vector>

namespace utils {

class ThreadPool : public NonCopyable {
 public:
  explicit ThreadPool(
      std::size_t n_threads = std::thread::hardware_concurrency())
      : workers_(n_threads > 0 ? n_threads : 1) {}

  std::size_t getNThreads() const { return workers_.size(); }
  EventThread &getWorker(std::size_t i) { return workers_.at(i); }

 private:
  std::vector<EventThread> workers_;
};

}  // namespace utils