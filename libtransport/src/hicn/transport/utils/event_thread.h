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
#include <memory>

#include <asio.hpp>

namespace utils {

class EventThread {
 private:
  // No copies
  EventThread(const EventThread&) = delete;  // non construction-copyable
  EventThread& operator=(const EventThread&) = delete;  // non copyable

 public:
  explicit EventThread(asio::io_service& io_service)
      : internal_io_service_(nullptr),
        io_service_(io_service),
        work_(io_service_),
        thread_(nullptr) {
    run();
  }

  explicit EventThread()
      : internal_io_service_(std::make_unique<asio::io_service>()),
        io_service_(*internal_io_service_),
        work_(io_service_),
        thread_(nullptr) {
    run();
  }

  ~EventThread() { stop(); }

  void run() {
    if (stopped()) {
      io_service_.reset();
    }

    thread_ = std::make_unique<std::thread>([this]() { io_service_.run(); });
  }

  std::thread::id getThreadId() const {
    if (thread_) {
      return thread_->get_id();
    } else {
      throw errors::RuntimeException("Event thread is not running.");
    }
  }

  template <typename Func>
  void add(Func&& f) {
    // If the function f
    // TODO USe post in mac os, asio->post in xenial
    io_service_.post(std::forward<Func&&>(f));
  }

  template <typename Func>
  void tryRunHandlerNow(Func&& f) {
    io_service_.dispatch(std::forward<Func&&>(f));
  }

  void stop() {
    io_service_.stop();

    if (thread_ && thread_->joinable()) {
      thread_->join();
    }

    thread_.reset();
  }

  bool stopped() { return io_service_.stopped(); }

  asio::io_service& getIoService() { return io_service_; }

 private:
  std::unique_ptr<asio::io_service> internal_io_service_;
  asio::io_service& io_service_;
  asio::io_service::work work_;
  std::unique_ptr<std::thread> thread_;
};

}  // namespace utils