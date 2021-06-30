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

#include <hicn/transport/config.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/errors/runtime_exception.h>

#include <memory>
#include <thread>

namespace utils {

class EventThread {
 public:
  EventThread(asio::io_service& io_service, bool detached = false)
      : internal_io_service_(nullptr),
        io_service_(std::ref(io_service)),
        work_(std::make_unique<asio::io_service::work>(io_service_)),
        thread_(nullptr),
        detached_(detached) {
    run();
  }

  EventThread(bool detached = false)
      : internal_io_service_(std::make_unique<asio::io_service>()),
        io_service_(std::ref(*internal_io_service_)),
        work_(std::make_unique<asio::io_service::work>(io_service_)),
        thread_(nullptr),
        detached_(detached) {
    run();
  }

  EventThread(const EventThread&) = delete;
  EventThread& operator=(const EventThread&) = delete;

  EventThread(EventThread&& other)
      : internal_io_service_(std::move(other.internal_io_service_)),
        io_service_(std::move(other.io_service_)),
        work_(std::move(other.work_)),
        thread_(std::move(other.thread_)),
        detached_(std::move(other.detached_)) {}

  EventThread& operator=(EventThread&& other) {
    internal_io_service_ = std::move(other.internal_io_service_);
    io_service_ = std::move(other.io_service_);
    work_ = std::move(other.work_);
    thread_ = std::move(other.thread_);
    detached_ = other.detached_;

    return *this;
  }

  ~EventThread() { stop(); }

  void run() {
    if (stopped()) {
      io_service_.get().stopped();
    }

    thread_ =
        std::make_unique<std::thread>([this]() { io_service_.get().run(); });

    if (detached_) {
      thread_->detach();
    }
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
    io_service_.get().post(std::forward<Func&&>(f));
  }

  template <typename Func>
  void tryRunHandlerNow(Func&& f) {
    io_service_.get().dispatch(std::forward<Func&&>(f));
  }

  void stop() {
    work_.reset();

    if (thread_ && thread_->joinable()) {
      thread_->join();
    }

    thread_.reset();
  }

  bool stopped() { return io_service_.get().stopped(); }

  asio::io_service& getIoService() { return io_service_; }

 private:
  std::unique_ptr<asio::io_service> internal_io_service_;
  std::reference_wrapper<asio::io_service> io_service_;
  std::unique_ptr<asio::io_service::work> work_;
  std::unique_ptr<std::thread> thread_;
  bool detached_;
};

}  // namespace utils