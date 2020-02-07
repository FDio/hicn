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

#include <hicn/transport/protocols/verification_manager.h>

#include <hicn/transport/interfaces/socket_consumer.h>

namespace transport {

namespace protocol {

interface::VerificationPolicy SignatureVerificationManager::onPacketToVerify(
    const Packet& packet) {
  using namespace interface;

  bool verify_signature;
  VerificationPolicy ret = VerificationPolicy::DROP_PACKET;

  ConsumerContentObjectVerificationFailedCallback*
      verification_failed_callback = VOID_HANDLER;
  icn_socket_->getSocketOption(GeneralTransportOptions::VERIFY_SIGNATURE,
                               verify_signature);

  if (!verify_signature) {
    return VerificationPolicy::ACCEPT_PACKET;
  }

  icn_socket_->getSocketOption(ConsumerCallbacksOptions::VERIFICATION_FAILED,
                               &verification_failed_callback);
  if (!verification_failed_callback) {
    throw errors::RuntimeException(
        "No verification failed callback provided by application. "
        "Aborting.");
  }

  std::shared_ptr<utils::Verifier> verifier;
  icn_socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier);

  if (TRANSPORT_EXPECT_FALSE(!verifier)) {
    ret = (*verification_failed_callback)(
        *icn_socket_, dynamic_cast<const ContentObject&>(packet),
        make_error_code(protocol_error::no_verifier_provided));
    return ret;
  }

  if (!verifier->verify(packet)) {
    ret = (*verification_failed_callback)(
        *icn_socket_, dynamic_cast<const ContentObject&>(packet),
        make_error_code(protocol_error::signature_verification_failed));
  } else {
    ret = VerificationPolicy::ACCEPT_PACKET;
  }

  return ret;
}

}  // end namespace protocol

}  // end namespace transport
