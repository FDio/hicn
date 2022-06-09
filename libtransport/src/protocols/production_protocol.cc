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

#include <implementation/socket_producer.h>
#include <protocols/production_protocol.h>

namespace transport {

namespace protocol {

using namespace interface;

ProductionProtocol::ProductionProtocol(
    implementation::ProducerSocket *icn_socket)
    : Protocol(),
      socket_(icn_socket),
      fec_encoder_(nullptr),
      on_interest_input_(VOID_HANDLER),
      on_interest_dropped_input_buffer_(VOID_HANDLER),
      on_interest_inserted_input_buffer_(VOID_HANDLER),
      on_interest_satisfied_output_buffer_(VOID_HANDLER),
      on_interest_process_(VOID_HANDLER),
      on_new_segment_(VOID_HANDLER),
      on_content_object_to_sign_(VOID_HANDLER),
      on_content_object_in_output_buffer_(VOID_HANDLER),
      on_content_object_output_(VOID_HANDLER),
      on_content_object_evicted_from_output_buffer_(VOID_HANDLER),
      on_content_produced_(VOID_HANDLER),
      producer_callback_(VOID_HANDLER),
      fec_type_(fec::FECType::UNKNOWN) {
  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal_);
  // TODO add statistics for producer
  //   socket_->getSocketOption(OtherOptions::STATISTICS, &stats_);
}

ProductionProtocol::~ProductionProtocol() {}

int ProductionProtocol::start() {
  if (isRunning()) {
    return -1;
  }

  portal_->getThread().addAndWaitForExecution([this]() {
    socket_->getSocketOption(ProducerCallbacksOptions::INTEREST_INPUT,
                             &on_interest_input_);
    socket_->getSocketOption(ProducerCallbacksOptions::INTEREST_DROP,
                             &on_interest_dropped_input_buffer_);
    socket_->getSocketOption(ProducerCallbacksOptions::INTEREST_PASS,
                             &on_interest_inserted_input_buffer_);
    socket_->getSocketOption(ProducerCallbacksOptions::CACHE_HIT,
                             &on_interest_satisfied_output_buffer_);
    socket_->getSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                             &on_interest_process_);
    socket_->getSocketOption(ProducerCallbacksOptions::NEW_CONTENT_OBJECT,
                             &on_new_segment_);
    socket_->getSocketOption(ProducerCallbacksOptions::CONTENT_OBJECT_READY,
                             &on_content_object_in_output_buffer_);
    socket_->getSocketOption(ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT,
                             &on_content_object_output_);
    socket_->getSocketOption(ProducerCallbacksOptions::CONTENT_OBJECT_TO_SIGN,
                             &on_content_object_to_sign_);
    socket_->getSocketOption(ProducerCallbacksOptions::CONTENT_PRODUCED,
                             &on_content_produced_);
    socket_->getSocketOption(ProducerCallbacksOptions::PRODUCER_CALLBACK,
                             &producer_callback_);

    socket_->getSocketOption(GeneralTransportOptions::ASYNC_MODE, is_async_);
    socket_->getSocketOption(GeneralTransportOptions::SIGNER, signer_);
    socket_->getSocketOption(GeneralTransportOptions::MANIFEST_MAX_CAPACITY,
                             manifest_max_capacity_);

    std::string fec_type_str = "";
    socket_->getSocketOption(GeneralTransportOptions::FEC_TYPE, fec_type_str);
    if (fec_type_str != "") {
      fec_type_ = fec::FECUtils::fecTypeFromString(fec_type_str.c_str());
    }

    portal_->registerTransportCallback(this);
    setProducerParam();

    setRunning();
  });

  return 0;
}

void ProductionProtocol::produce(ContentObject &content_object) {
  auto content_object_ptr = content_object.shared_from_this();
  portal_->getThread().add([this, co = std::move(content_object_ptr)]() {
    if (*on_content_object_in_output_buffer_) {
      on_content_object_in_output_buffer_->operator()(*socket_->getInterface(),
                                                      *co);
    }

    output_buffer_.insert(co);

    if (*on_content_object_output_) {
      on_content_object_output_->operator()(*socket_->getInterface(), *co);
    }

    portal_->sendContentObject(*co);
  });
}

void ProductionProtocol::sendMapme() { portal_->sendMapme(); }

void ProductionProtocol::onError(const std::error_code &ec) {
  // Stop production protocol
  stop();

  // Call error callback
  if (producer_callback_) {
    producer_callback_->produceError(ec);
  }
}

}  // namespace protocol

}  // namespace transport
