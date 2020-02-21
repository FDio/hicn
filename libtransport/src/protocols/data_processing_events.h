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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>

namespace transport {
namespace protocol {

class ContentObjectProcessingEventCallback {
 public:
  virtual ~ContentObjectProcessingEventCallback() = default;
  virtual void onPacketDropped(core::Interest::Ptr &&i,
                               core::ContentObject::Ptr &&c) = 0;
  virtual void onReassemblyFailed(std::uint32_t missing_segment) = 0;
};

}  // namespace protocol
}  // namespace transport
