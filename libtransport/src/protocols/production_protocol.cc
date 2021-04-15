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
    : socket_(icn_socket),
      is_running_(false),
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
      on_content_produced_(VOID_HANDLER) {
  socket_->getSocketOption(GeneralTransportOptions::PORTAL, portal_);
  // TODO add statistics for producer
  //   socket_->getSocketOption(OtherOptions::STATISTICS, &stats_);
}

ProductionProtocol::~ProductionProtocol() {
  if (!is_async_ && is_running_) {
    stop();
  }

  if (listening_thread_.joinable()) {
    listening_thread_.join();
  }
}

int ProductionProtocol::start() {
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

  socket_->getSocketOption(GeneralTransportOptions::ASYNC_MODE, is_async_);

  bool first = true;

  for (core::Prefix &producer_namespace : served_namespaces_) {
    if (first) {
      core::BindConfig bind_config(producer_namespace, 1000);
      portal_->bind(bind_config);
      portal_->setProducerCallback(this);
      first = !first;
    } else {
      portal_->registerRoute(producer_namespace);
    }
  }

  is_running_ = true;

  if (!is_async_) {
    listening_thread_ = std::thread([this]() { portal_->runEventsLoop(); });
  }

  return 0;
}

void ProductionProtocol::stop() {
  is_running_ = false;

  if (!is_async_) {
    portal_->stopEventsLoop();
  } else {
    portal_->clear();
  }
}

void ProductionProtocol::produce(ContentObject &content_object) {
  if (*on_content_object_in_output_buffer_) {
    on_content_object_in_output_buffer_->operator()(*socket_->getInterface(),
                                                    content_object);
  }

  output_buffer_.insert(std::static_pointer_cast<ContentObject>(
      content_object.shared_from_this()));

  if (*on_content_object_output_) {
    on_content_object_output_->operator()(*socket_->getInterface(),
                                          content_object);
  }

  portal_->sendContentObject(content_object);
}

void ProductionProtocol::registerNamespaceWithNetwork(
    const Prefix &producer_namespace) {
  served_namespaces_.push_back(producer_namespace);
}

}  // namespace protocol

}  // namespace transport
