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
        work_guard_(asio::make_work_guard(io_service_.get())),
        thread_(nullptr),
        detached_(detached) {
    run();
  }

  explicit EventThread(bool detached = false)
      : internal_io_service_(std::make_unique<asio::io_service>()),
        io_service_(std::ref(*internal_io_service_)),
        work_guard_(asio::make_work_guard(io_service_.get())),
        thread_(nullptr),
        detached_(detached) {
    run();
  }

  EventThread(const EventThread&) = delete;
  EventThread& operator=(const EventThread&) = delete;

  EventThread(EventThread&& other) noexcept
      : internal_io_service_(std::move(other.internal_io_service_)),
        io_service_(std::move(other.io_service_)),
        work_guard_(std::move(other.work_guard_)),
        thread_(std::move(other.thread_)),
        detached_(other.detached_) {}

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
    io_service_.get().post(std::forward<Func>(f));
  }

  template <typename Func>
  void tryRunHandlerNow(Func&& f) {
    io_service_.get().dispatch(std::forward<Func>(f));
  }

  template <typename Func>
  void addAndWaitForExecution(Func&& f) const {
    auto promise = std::promise<void>();
    auto future = promise.get_future();

    asio::dispatch(io_service_.get(), [&promise, f = std::forward<Func>(f)]() {
      f();
      promise.set_value();
    });

    future.wait();
  }

  void stop() {
    add([this]() { work_guard_.reset(); });

    if (thread_ && thread_->joinable()) {
      thread_->join();
    }

    thread_.reset();
  }

  bool stopped() const { return io_service_.get().stopped(); }

  asio::io_service& getIoService() { return io_service_; }

 private:
  std::unique_ptr<asio::io_service> internal_io_service_;
  std::reference_wrapper<asio::io_service> io_service_;
  asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
  std::unique_ptr<std::thread> thread_;
  bool detached_;
};

}  // namespace utils