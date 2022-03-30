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

#include <core/errors.h>

namespace transport {
namespace core {

const std::error_category& core_category() {
  static core_category_impl instance;

  return instance;
}

const char* core_category_impl::name() const throw() {
  return "transport::protocol::error";
}

std::string core_category_impl::message(int ev) const {
  switch (static_cast<core_error>(ev)) {
    case core_error::success: {
      return "Success";
    }
    case core_error::configuration_parse_failed: {
      return "Error parsing configuration.";
    }
    case core_error::configuration_not_applied: {
      return "Configuration was not applied due to wrong parameters.";
    }
    case core_error::send_failed: {
      return "Error sending data to socket.";
    }
    case core_error::send_buffer_allocation_failed: {
      return "Error allocating buffers to send data.";
    }
    case core_error::receive_failed: {
      return "Error receiving data from socket.";
    }
    default: {
      return "Unknown core error";
    }
  }
}

}  // namespace core
}  // namespace transport