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
#include <hicn/transport/protocols/cbr.h>
#include <hicn/transport/protocols/raaqm.h>
#include <hicn/transport/protocols/rtc.h>

namespace transport {

namespace interface {

ConsumerSocket::ConsumerSocket(int protocol)
    : ConsumerSocket(protocol, internal_io_service_) {}

ConsumerSocket::ConsumerSocket(int protocol, asio::io_service &io_service)
    : io_service_(io_service),
      portal_(std::make_shared<Portal>(io_service_)),
      async_downloader_(),
      interest_lifetime_(default_values::interest_lifetime),
      min_window_size_(default_values::min_window_size),
      max_window_size_(default_values::max_window_size),
      current_window_size_(-1),
      max_retransmissions_(
          default_values::transport_protocol_max_retransmissions),
      /****** RAAQM Parameters ******/
      minimum_drop_probability_(default_values::minimum_drop_probability),
      sample_number_(default_values::sample_number),
      gamma_(default_values::gamma_value),
      beta_(default_values::beta_value),
      drop_factor_(default_values::drop_factor),
      /****** END RAAQM Parameters ******/
      rate_estimation_alpha_(default_values::rate_alpha),
      rate_estimation_observer_(nullptr),
      rate_estimation_choice_(0),
      is_async_(false),
      verifier_(std::make_shared<utils::Verifier>()),
      verify_signature_(false),
      on_interest_output_(VOID_HANDLER),
      on_interest_timeout_(VOID_HANDLER),
      on_interest_satisfied_(VOID_HANDLER),
      on_content_object_input_(VOID_HANDLER),
      on_content_object_verification_(VOID_HANDLER),
      on_content_object_(VOID_HANDLER),
      on_manifest_(VOID_HANDLER),
      stats_summary_(VOID_HANDLER),
      read_callback_(nullptr),
      virtual_download_(false),
      rtt_stats_(false),
      timer_interval_milliseconds_(0) {
  switch (protocol) {
    case TransportProtocolAlgorithms::CBR:
      transport_protocol_ = std::make_unique<CbrTransportProtocol>(this);
      break;
    case TransportProtocolAlgorithms::RTC:
      transport_protocol_ = std::make_unique<RTCTransportProtocol>(this);
      break;
    case TransportProtocolAlgorithms::RAAQM:
    default:
      transport_protocol_ = std::make_unique<RaaqmTransportProtocol>(this);
      break;
  }
}

ConsumerSocket::~ConsumerSocket() {
  stop();
  async_downloader_.stop();
}

void ConsumerSocket::connect() { portal_->connect(); }

int ConsumerSocket::consume(const Name &name) {
  if (transport_protocol_->isRunning()) {
    return CONSUMER_BUSY;
  }

  network_name_ = name;
  network_name_.setSuffix(0);
  is_async_ = false;

  transport_protocol_->start();

  return CONSUMER_FINISHED;
}

int ConsumerSocket::asyncConsume(const Name &name) {
  if (!async_downloader_.stopped()) {
    async_downloader_.add([this, name]() {
      network_name_ = std::move(name);
      network_name_.setSuffix(0);
      is_async_ = true;
      transport_protocol_->start();
    });
  }

  return CONSUMER_RUNNING;
}

void ConsumerSocket::asyncSendInterest(Interest::Ptr &&interest,
                                       Portal::ConsumerCallback *callback) {
  if (!async_downloader_.stopped()) {
    // TODO Workaround, to be fixed!
    auto i = interest.release();
    async_downloader_.add([this, i, callback]() mutable {
      Interest::Ptr _interest(i);
      portal_->setConsumerCallback(callback);
      portal_->sendInterest(std::move(_interest));
      portal_->runEventsLoop();
    });
  }
}

void ConsumerSocket::stop() {
  auto &io_service = getIoService();
  io_service.dispatch([this]() {
    if (transport_protocol_->isRunning()) {
      transport_protocol_->stop();
    }
  });
}

void ConsumerSocket::resume() {
  if (!transport_protocol_->isRunning()) {
    transport_protocol_->resume();
  }
}

asio::io_service &ConsumerSocket::getIoService() {
  return portal_->getIoService();
}

}  // namespace interface

}  // end namespace transport