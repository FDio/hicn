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

#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/interfaces/verification_policy.h>
#include <hicn/transport/protocols/errors.h>

namespace transport {

namespace interface {
class ConsumerSocket;
}

namespace protocol {

using Packet = core::Packet;
using interface::ConsumerSocket;
using interface::VerificationPolicy;

class VerificationManager {
 public:
  virtual ~VerificationManager() = default;
  virtual VerificationPolicy onPacketToVerify(const Packet& packet) = 0;
};

class SignatureVerificationManager : public VerificationManager {
 public:
  SignatureVerificationManager(ConsumerSocket* icn_socket)
      : icn_socket_(icn_socket) {}

  interface::VerificationPolicy onPacketToVerify(const Packet& packet) override;

 private:
  ConsumerSocket* icn_socket_;
};

}  // end namespace protocol

}  // end namespace transport
