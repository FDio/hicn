/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <core/facade.h>
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/config.h>
#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/socket_options_keys.h>

#define SOCKET_OPTION_GET 0
#define SOCKET_OPTION_NOT_GET 1
#define SOCKET_OPTION_SET 2
#define SOCKET_OPTION_NOT_SET 3
#define SOCKET_OPTION_DEFAULT 12345

namespace transport {
namespace implementation {

// Forward Declarations
class Socket;

class Socket {
 public:
  virtual void connect() = 0;
  virtual bool isRunning() = 0;

  virtual asio::io_service &getIoService() {
    return portal_->getThread().getIoService();
  }

  int setSocketOption(int socket_option_key,
                      hicn_packet_format_t packet_format);
  int getSocketOption(int socket_option_key,
                      hicn_packet_format_t &packet_format);

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<core::Portal> &socket_option_value) {
    switch (socket_option_key) {
      case interface::GeneralTransportOptions::PORTAL:
        socket_option_value = portal_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
        ;
    }

    return SOCKET_OPTION_GET;
  }

 protected:
  Socket(std::shared_ptr<core::Portal> &&portal);

  virtual ~Socket(){};

 protected:
  std::shared_ptr<core::Portal> portal_;
  bool is_async_;
  hicn_packet_format_t packet_format_;
  std::shared_ptr<auth::Signer> signer_;
  std::shared_ptr<auth::Verifier> verifier_;
};

}  // namespace implementation

}  // namespace transport
