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

#pragma once

#include "response.h"

namespace icn_httpserver {

class SocketResponse : public Response {
 public:
  SocketResponse(std::shared_ptr<socket_type> socket);

  ~SocketResponse();

  void send(const SendCallback &callback = nullptr);

  const std::shared_ptr<socket_type> &getSocket() const;

  void setSocket(const std::shared_ptr<socket_type> &socket);

 private:
  std::shared_ptr<socket_type> socket_;
};

}  // end namespace icn_httpserver
