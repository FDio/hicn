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

#include <hicn/transport/core/name.h>

namespace transport {

namespace interface {

class PublicationOptions {
 public:
  template <typename T>
  PublicationOptions(T&& name, uint32_t lifetime)
      : name_(std::forward<T&&>(name)),
        content_lifetime_milliseconds_(lifetime) {}

  TRANSPORT_ALWAYS_INLINE const core::Name& getName() const { return name_; }
  TRANSPORT_ALWAYS_INLINE uint32_t getLifetime() const {
    return content_lifetime_milliseconds_;
  }

 private:
  core::Name name_;
  uint32_t content_lifetime_milliseconds_;
  // TODO Signature
};
}  // namespace interface

}  // namespace transport