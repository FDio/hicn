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

#include <hicn/transport/interfaces/socket_consumer.h>

#include <deque>

namespace transport {

namespace protocol {

class VerificationManager {
 public:
  virtual ~VerificationManager() = default;
  virtual bool onPacketToVerify(const Packet& packet) = 0;
};

class SignatureVerificationManager : public VerificationManager {
 public:
  SignatureVerificationManager(interface::ConsumerSocket* icn_socket)
      : icn_socket_(icn_socket) {}

  TRANSPORT_ALWAYS_INLINE bool onPacketToVerify(const Packet& packet) override {
    using namespace interface;

    bool verify_signature, ret = false;
    icn_socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE,
                                 verify_signature);

    if (!verify_signature) {
      return true;
    }

    std::shared_ptr<utils::Verifier> verifier;
    icn_socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);

    if (TRANSPORT_EXPECT_FALSE(!verifier)) {
      throw errors::RuntimeException(
          "No certificate provided by the application.");
    }

    ret = verifier->verify(packet);

    if (!ret) {
      throw errors::RuntimeException(
          "Verification failure policy has to be implemented.");
    }

    return ret;
  }

 private:
  interface::ConsumerSocket* icn_socket_;
};

}  // end namespace protocol

}  // end namespace transport
