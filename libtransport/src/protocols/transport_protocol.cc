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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <implementation/socket_consumer.h>
#include <protocols/transport_protocol.h>

namespace transport {

namespace protocol {

using namespace interface;

TransportProtocol::TransportProtocol(implementation::ConsumerSocket *icn_socket,
                                     Indexer *indexer, Reassembly *reassembly)
    : Protocol(),
      socket_(icn_socket),
      indexer_verifier_(indexer),
      reassembly_(reassembly),
      fec_decoder_(nullptr),
      is_first_(false),
      on_interest_retransmission_(VOID_HANDLER),
      on_interest_output_(VOID_HANDLER),
      on_interest_timeout_(VOID_HANDLER),
      on_interest_satisfied_(VOID_HANDLER),
      on_content_object_input_(VOID_HANDLER),
      stats_summary_(VOID_HANDLER),
      on_fwd_strategy_(VOID_HANDLER),
      on_rec_strategy_(VOID_HANDLER),
      on_payload_(VOID_HANDLER),
      fec_type_(fec::FECType::UNKNOWN) {
  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal_);
  socket_->getSocketOption(OtherOptions::STATISTICS, &stats_);

  indexer_verifier_->setReassembly(reassembly_.get());
  reassembly->setIndexer(indexer_verifier_.get());
}

TransportProtocol::~TransportProtocol() {}

int TransportProtocol::start() {
  // If the protocol is already running, return otherwise set as running
  if (isRunning()) {
    return -1;
  }

  // Start protocol on its own thread
  portal_->getThread().add([this]() {
    // Get all callbacks references
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
    socket_->getSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                             &stats_summary_);
    socket_->getSocketOption(ConsumerCallbacksOptions::FWD_STRATEGY_CHANGE,
                             &on_fwd_strategy_);
    socket_->getSocketOption(ConsumerCallbacksOptions::REC_STRATEGY_CHANGE,
                             &on_rec_strategy_);
    socket_->getSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
                             &on_payload_);

    socket_->getSocketOption(GeneralTransportOptions::ASYNC_MODE, is_async_);
    socket_->getSocketOption(GeneralTransportOptions::SIGNER, signer_);

    // Set it is the first time we schedule an interest
    is_first_ = true;

    // Reset the protocol state machine
    reset();

    // Set this transport protocol as portal's consumer callback
    portal_->registerTransportCallback(this);

    // Schedule next interests
    scheduleNextInterests();

    is_first_ = false;

    // Set the protocol as running
    setRunning();
  });

  return 0;
}

void TransportProtocol::resume() {
  if (isRunning()) return;

  setRunning();

  portal_->getThread().tryRunHandlerNow([this]() { scheduleNextInterests(); });
}

void TransportProtocol::reset() {
  reassembly_->reInitialize();
  indexer_verifier_->reset();
  if (fec_decoder_) {
    fec_decoder_->reset();
  }
}

void TransportProtocol::onContentReassembled(const std::error_code &ec) {
  stop();

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
}

void TransportProtocol::sendInterest(
    const Name &interest_name,
    std::array<uint32_t, MAX_AGGREGATED_INTEREST> *additional_suffixes,
    uint32_t len) {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending interest for name " << interest_name;

  Packet::Format format;
  socket_->getSocketOption(interface::GeneralTransportOptions::PACKET_FORMAT,
                           format);
  size_t signature_size = 0;

  // If aggregated interest, add spapce for signature
  if (len > 0) {
    format = Packet::toAHFormat(format);
    signature_size = signer_->getSignatureFieldSize();
  }

  auto interest = core::PacketManager<>::getInstance().getPacket<Interest>(
      format, signature_size);
  interest->setName(interest_name);

  for (uint32_t i = 0; i < len; i++) {
    interest->appendSuffix(additional_suffixes->at(i));
  }
  interest->encodeSuffixes();

  uint32_t lifetime = default_values::interest_lifetime;
  socket_->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                           lifetime);
  interest->setLifetime(uint32_t(lifetime));

  if (*on_interest_output_) {
    (*on_interest_output_)(*socket_->getInterface(), *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!isRunning() && !is_first_)) {
    return;
  }

  bool content_sharing_mode;
  socket_->getSocketOption(RtcTransportOptions::CONTENT_SHARING_MODE,
                           content_sharing_mode);
  if (content_sharing_mode) lifetime = ceil((double)lifetime * 0.9);

  // Compute signature
  bool is_ah = _is_ah(interest->getFormat());
  if (is_ah) signer_->signPacket(interest.get());

  portal_->sendInterest(interest, lifetime);
}

void TransportProtocol::onError(const std::error_code &ec) {
  // error from portal: stop socket
  stop();

  // signal error to application
  on_payload_->readError(ec);
}

void TransportProtocol::onTimeout(Interest::Ptr &i, const Name &n) {
  if (TRANSPORT_EXPECT_FALSE(!isRunning())) {
    return;
  }

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Timeout on content " << n;

  onInterestTimeout(i, n);
}

void TransportProtocol::onContentObject(Interest &i, ContentObject &c) {
  // Check whether it makes sense to continue
  if (TRANSPORT_EXPECT_FALSE(!isRunning())) {
    return;
  }

  // Call transport protocol function
  std::error_code ec;
  onContentObjectReceived(i, c, ec);

  // Call reassemble function, if packet is eligible for reassemblying
  bool reassemble = false;
  if (!ec) {
    reassemble = true;
  }

  // Perform verification and update indexer. This step may be performed offline
  // - i.e. we may not get a result here (e.g. we use manifest). Verification
  // failures in that case will be handled in the onPacketDropped function.
  // XXX This step should be done before calling onContentObjectReceived, but
  // for now we do it here since currently the indexer does not need manifests
  // to move forward.
  indexer_verifier_->onContentObject(i, c, reassemble);
}

}  // end namespace protocol

}  // end namespace transport
