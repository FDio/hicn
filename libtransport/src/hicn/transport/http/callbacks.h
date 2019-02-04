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

#include <hicn/transport/http/server_publisher.h>

#include <functional>
#include <memory>

namespace transport {

namespace http {

enum class RC : uint8_t {
  SUCCESS,
  CONTENT_PUBLISHED,
  ERR_UNDEFINED,
};

using OnHttpRequest =
    std::function<void(std::shared_ptr<HTTPServerPublisher>&, const uint8_t*,
                       std::size_t, int request_id)>;
using DeadlineTimerCallback = std::function<void(const std::error_code& e)>;
using ReceiveCallback = std::function<void(const std::vector<uint8_t>&)>;
using OnPayloadCallback =
    std::function<RC(const std::error_code& ec, const core::Name& name,
                     const ContentBuffer& payload)>;
using ContentSentCallback =
    std::function<void(const std::error_code&, const core::Name&)>;

}  // namespace http

}  // namespace transport