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
  virtual bool onKeyToVerify() { return false; }
};

class SignatureVerificationManager : public VerificationManager {
 public:
  using ContentObjectPtr = std::shared_ptr<ContentObject>;

  SignatureVerificationManager(interface::ConsumerSocket* icn_socket)
      : icn_socket_(icn_socket), key_packets_() {}

  TRANSPORT_ALWAYS_INLINE bool onPacketToVerify(const Packet& packet) override {
    using namespace interface;

    bool verify_signature = false, key_content = false, ret = false;

    icn_socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE,
                                 verify_signature);
    icn_socket_->getSocketOption(GeneralTransportOptions::KEY_CONTENT,
                                 key_content);

    if (!verify_signature) return true;

    if (key_content) {
      key_packets_.push(copyPacket(packet));
      return true;
    } else if (!key_packets_.empty()) {
      std::queue<ContentObjectPtr>().swap(key_packets_);
    }

    std::shared_ptr<utils::Verifier> verifier;
    icn_socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);

    if (TRANSPORT_EXPECT_FALSE(!verifier)) {
      throw errors::RuntimeException(
          "No verifier provided by the application.");
    }

    ret = verifier->verify(packet);

    if (!ret) {
      throw errors::RuntimeException(
          "Verification failure policy has to be implemented.");
    }

    return ret;
  }

  TRANSPORT_ALWAYS_INLINE bool onKeyToVerify() override {
    using namespace interface;

    if (TRANSPORT_EXPECT_FALSE(key_packets_.empty())) {
      throw errors::RuntimeException("No key to verify.");
    }

    while (!key_packets_.empty()) {
      ContentObjectPtr packet_to_verify = key_packets_.front();
      key_packets_.pop();
      if (!onPacketToVerify(*packet_to_verify)) return false;
    }

    return true;
  }

 private:
  interface::ConsumerSocket* icn_socket_;
  std::queue<ContentObjectPtr> key_packets_;

  ContentObjectPtr copyPacket(const Packet& packet) {
    std::shared_ptr<utils::MemBuf> packet_copy =
        packet.acquireMemBufReference();
    ContentObjectPtr content_object_copy =
        std::make_shared<ContentObject>(std::move(packet_copy));
    std::unique_ptr<utils::MemBuf> payload_copy = packet.getPayload();
    content_object_copy->appendPayload(std::move(payload_copy));
    return content_object_copy;
  }
};

}  // end namespace protocol

}  // end namespace transport
