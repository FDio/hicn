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
#include <hicn/transport/protocols/protocol.h>

namespace transport {

namespace protocol {

using namespace interface;

TransportProtocol::TransportProtocol(interface::ConsumerSocket *icn_socket,
                                     Reassembly *reassembly_protocol,
                                     IndexVerificationManager *index_manager)
    : socket_(icn_socket),
      reassembly_protocol_(reassembly_protocol),
      index_manager_(index_manager),
      is_running_(false),
      is_first_(false) {
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
  interface::ConsumerSocket::ReadCallback *on_payload = VOID_HANDLER;
  socket_->getSocketOption(READ_CALLBACK, &on_payload);

  if (!on_payload) {
    throw errors::RuntimeException(
        "The read callback must be installed in the transport before "
        "starting "
        "the content retrieval.");
  }

  if (!ec) {
    on_payload->readSuccess(stats_->getBytesRecv());
  } else {
    on_payload->readError(ec);
  }

  stop();
}

}  // end namespace protocol

}  // end namespace transport
