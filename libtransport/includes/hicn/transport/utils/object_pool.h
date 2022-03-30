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

#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/noncopyable.h>
#include <hicn/transport/utils/spinlock.h>

#include <deque>
#include <memory>
#include <mutex>

namespace utils {

template <typename T>
class ObjectPool : private utils::NonCopyable {
  class ObjectDeleter {
   public:
    ObjectDeleter(ObjectPool<T> *pool = nullptr) : pool_(pool) {}

    void operator()(T *t) {
      if (pool_) {
        pool_->add(t);
      } else {
        delete t;
      }
    }

   private:
    ObjectPool<T> *pool_;
  };

 public:
  using Ptr = std::shared_ptr<T>;

  ObjectPool() : destructor_(false) {}

  ObjectPool(ObjectPool &&other)
      : object_pool_lock_(std::move(other.object_pool_lock_)),
        object_pool_(std::move(other.object_pool_)),
        destructor_(other.destructor_) {}

  ObjectPool &operator=(ObjectPool &&other) {
    if (this != &other) {
      object_pool_lock_ = std::move(other.object_pool_lock_);
      object_pool_ = std::move(other.object_pool_);
      destructor_ = other.destructor_;
    }

    return *this;
  }

  ~ObjectPool() {
    destructor_ = true;
    for (auto &ptr : object_pool_) {
      ptr.reset();
    }
  }

  bool empty() {
    utils::SpinLock::Acquire locked(object_pool_lock_);
    return object_pool_.empty();
  }

  std::pair<bool, Ptr> get() {
    utils::SpinLock::Acquire locked(object_pool_lock_);
    if (object_pool_.empty()) {
      return std::make_pair<bool, Ptr>(false, nullptr);
    }

    auto ret = std::move(object_pool_.front());
    object_pool_.pop_front();
    return std::make_pair<bool, Ptr>(true, std::move(ret));
  }

  void add(T *object) {
    utils::SpinLock::Acquire locked(object_pool_lock_);

    if (TRANSPORT_EXPECT_TRUE(!destructor_)) {
      object_pool_.emplace_front(makePtr(object));
    } else {
      delete object;
    }
  }

  Ptr makePtr(T *object) { return Ptr(object, ObjectDeleter(this)); }

 private:
  utils::SpinLock object_pool_lock_;
  std::deque<Ptr> object_pool_;
  std::atomic<bool> destructor_;
};

}  // namespace utils
