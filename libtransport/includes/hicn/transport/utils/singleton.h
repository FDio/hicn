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

#include <hicn/transport/utils/noncopyable.h>

namespace utils {

template <typename T>
class Singleton : NonCopyable {
 public:
  static T& getInstance() {
    static T instance;
    return instance;
  }

 protected:
  Singleton() {}
  ~Singleton() {}
};

template <typename T>
class ThreadLocalSingleton : NonCopyable {
 public:
  static T& getInstance() {
    static thread_local T instance;
    return instance;
  }

 protected:
  ThreadLocalSingleton() {}
  ~ThreadLocalSingleton() {}
};

}  // namespace utils