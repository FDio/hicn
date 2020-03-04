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

#include <hicn/transport/interfaces/socket_consumer.h>

#include <implementation/socket_consumer.h>
#include <protocols/protocol.h>

namespace transport {

namespace protocol {

using namespace interface;

TransportProtocol::TransportProtocol(implementation::ConsumerSocket *icn_socket,
                                     Reassembly *reassembly_protocol)
    : socket_(icn_socket),
      reassembly_protocol_(reassembly_protocol),
      index_manager_(
          std::make_unique<IndexManager>(socket_, this, reassembly_protocol)),
      is_running_(false),
      is_first_(false),
      on_interest_retransmission_(VOID_HANDLER),
      on_interest_output_(VOID_HANDLER),
      on_interest_timeout_(VOID_HANDLER),
      on_interest_satisfied_(VOID_HANDLER),
      on_content_object_input_(VOID_HANDLER),
      on_content_object_verification_(VOID_HANDLER),
      stats_summary_(VOID_HANDLER),
      verification_failed_callback_(VOID_HANDLER),
      on_payload_(VOID_HANDLER) {
  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal_);
  socket_->getSocketOption(OtherOptions::STATISTICS, &stats_);
}

int TransportProtocol::start() {
  // If the protocol is already running, return otherwise set as running
  if (is_running_) return -1;

  // Reset the protocol state machine
  reset();

  // Set it is the first time we schedule an interest
  is_first_ = true;

  // Get all callbacks references before starting
  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_RETRANSMISSION,
                           &on_interest_retransmission_);
  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_OUTPUT,
                           &on_interest_output_);
  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_EXPIRED,
                           &on_interest_timeout_);
  socket_->getSocketOption(ConsumerCallbacksOptions::INTEREST_SATISFIED,
                           &on_interest_satisfied_);
  socket_->getSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT,
                           &on_content_object_input_);
  socket_->getSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY,
                           &on_content_object_verification_);
  socket_->getSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                           &stats_summary_);
  socket_->getSocketOption(ConsumerCallbacksOptions::VERIFICATION_FAILED,
                           &verification_failed_callback_);
  socket_->getSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
                           &on_payload_);

  // Schedule next interests
  scheduleNextInterests();

  is_first_ = false;

  // Set the protocol as running
  is_running_ = true;

  // Start Event loop
  portal_->runEventsLoop();

  // Not running anymore
  is_running_ = false;

  return 0;
}

void TransportProtocol::stop() {
  is_running_ = false;
  portal_->stopEventsLoop();
}

void TransportProtocol::resume() {
  if (is_running_) return;

  is_running_ = true;

  scheduleNextInterests();

  portal_->runEventsLoop();

  is_running_ = false;
}

void TransportProtocol::onContentReassembled(std::error_code ec) {
  if (!on_payload_) {
    throw errors::RuntimeException(
        "The read callback must be installed in the transport before "
        "starting "
        "the content retrieval.");
  }

  if (!ec) {
    on_payload_->readSuccess(stats_->getBytesRecv());
  } else {
    on_payload_->readError(ec);
  }

  stop();
}

}  // end namespace protocol

}  // end namespace transport
