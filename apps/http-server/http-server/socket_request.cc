/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "socket_request.h"

namespace icn_httpserver {

void SocketRequest::read_remote_endpoint_data(socket_type &socket) {
  try {
    remote_endpoint_address_ =
        socket.lowest_layer().remote_endpoint().address().to_string();
    remote_endpoint_port_ = socket.lowest_layer().remote_endpoint().port();
  } catch (const std::exception &) {
  }
}

}  // end namespace icn_httpserver
