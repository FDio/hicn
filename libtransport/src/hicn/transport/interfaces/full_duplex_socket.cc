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

#include <hicn/transport/interfaces/full_duplex_socket.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/utils/sharable_vector.h>

#include <memory>

namespace transport {

namespace interface {

static const std::string producer_identity = "producer_socket";

AsyncFullDuplexSocket::AsyncFullDuplexSocket(const Prefix &locator)
    : AsyncFullDuplexSocket(locator, internal_io_service_) {}

AsyncFullDuplexSocket::AsyncFullDuplexSocket(const Prefix &locator,
                                             asio::io_service &io_service)
    : locator_(locator),
      incremental_suffix_(0),
      io_service_(io_service),
      work_(io_service),
      producer_(std::make_unique<ProducerSocket>(io_service_)),
      consumer_(std::make_unique<ConsumerSocket>(
          TransportProtocolAlgorithms::RAAQM /* , io_service_ */)),
      read_callback_(nullptr),
      write_callback_(nullptr),
      connect_callback_(nullptr),
      accept_callback_(nullptr),
      internal_connect_callback_(new OnConnectCallback(*this)),
      internal_signal_callback_(new OnSignalCallback(*this)),
      send_timeout_milliseconds_(~0),
      counters_({0}),
      receive_buffer_(std::make_shared<utils::SharableVector<uint8_t>>()) {
  using namespace transport;
  using namespace std::placeholders;
  producer_->registerPrefix(locator);

  producer_->setSocketOption(
      ProducerCallbacksOptions::CACHE_MISS,
      std::bind(&AsyncFullDuplexSocket::onControlInterest, this, _1, _2));

  producer_->setSocketOption(GeneralTransportOptions::OUTPUT_BUFFER_SIZE,
                             uint32_t{150000});

  producer_->setSocketOption(
      ProducerCallbacksOptions::CONTENT_PRODUCED,
      std::bind(&AsyncFullDuplexSocket::onContentProduced, this, _1, _2, _3));

  producer_->connect();

  consumer_->setSocketOption(ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY,
                             (ConsumerContentObjectVerificationCallback)[](
                                 ConsumerSocket & s, const ContentObject &c)
                                 ->bool { return true; });

  consumer_->setSocketOption(
      ConsumerCallbacksOptions::CONTENT_RETRIEVED,
      std::bind(&AsyncFullDuplexSocket::onContentRetrieved, this, _1, _2, _3));

  consumer_->setSocketOption(GeneralTransportOptions::MAX_INTEREST_RETX,
                             uint32_t{4});

  consumer_->connect();
}

void AsyncFullDuplexSocket::close() {
  this->consumer_->stop();
  this->producer_->stop();
}

void AsyncFullDuplexSocket::closeNow() { close(); }

void AsyncFullDuplexSocket::shutdownWrite() { producer_->stop(); }

void AsyncFullDuplexSocket::shutdownWriteNow() { shutdownWrite(); }

bool AsyncFullDuplexSocket::good() const { return true; }

bool AsyncFullDuplexSocket::readable() const {
  // TODO return status of consumer socket
  return true;
}

bool AsyncFullDuplexSocket::writable() const {
  // TODO return status of producer socket
  return true;
}

bool AsyncFullDuplexSocket::isPending() const {
  // TODO save if there are production operation in the ops queue
  // in producer socket
  return true;
}

bool AsyncFullDuplexSocket::connected() const {
  // No real connection here (ICN world). Return good
  return good();
}

bool AsyncFullDuplexSocket::error() const { return !good(); }

void AsyncFullDuplexSocket::setSendTimeout(uint32_t milliseconds) {
  // TODO if production takes too much to complete
  // let's abort the operation.

  // Normally with hicn this should be done for content
  // pull, not for production.

  send_timeout_milliseconds_ = milliseconds;
}

uint32_t AsyncFullDuplexSocket::getSendTimeout() const {
  return send_timeout_milliseconds_;
}

size_t AsyncFullDuplexSocket::getAppBytesWritten() const {
  return counters_.app_bytes_written_;
}

size_t AsyncFullDuplexSocket::getRawBytesWritten() const { return 0; }

size_t AsyncFullDuplexSocket::getAppBytesReceived() const {
  return counters_.app_bytes_read_;
}

size_t AsyncFullDuplexSocket::getRawBytesReceived() const { return 0; }

void AsyncFullDuplexSocket::connect(ConnectCallback *callback,
                                    const core::Prefix &prefix) {
  connect_callback_ = callback;

  // Create an interest for a subscription
  auto interest =
      core::Interest::Ptr(new core::Interest(prefix.makeRandomName()));
  auto _payload = utils::MemBuf::create(sizeof(ActionMessage));
  _payload->append(sizeof(ActionMessage));
  auto payload = _payload->writableData();
  ActionMessage *subscription_message =
      reinterpret_cast<ActionMessage *>(payload);
  subscription_message->header.msg_type = MessageType::ACTION;
  subscription_message->action = Action::SUBSCRIBE;
  subscription_message->header.reserved[0] = 0;
  subscription_message->header.reserved[1] = 0;

  // Set the name the other part should use for notifying a content production
  sync_notification_ = std::move(locator_.makeRandomName());
  sync_notification_.copyToDestination(
      reinterpret_cast<uint8_t *>(subscription_message->name));

  TRANSPORT_LOGI(
      "Trying to connect. Sending interest: %s, name for notifications: %s",
      prefix.getName().toString().c_str(),
      sync_notification_.toString().c_str());

  interest->setLifetime(1000);
  interest->appendPayload(std::move(_payload));
  consumer_->asyncSendInterest(std::move(interest),
                               internal_connect_callback_.get());
}

void AsyncFullDuplexSocket::write(WriteCallback *callback, const void *buf,
                                  size_t bytes,
                                  const PublicationOptions &options,
                                  WriteFlags flags) {
  using namespace transport;

  // 1 asynchronously write the content. I assume here the
  // buffer contains the whole application frame. FIXME: check
  // if this is true and fix it accordingly
  std::cout << "Size of the PAYLOAD: " << bytes << std::endl;

  if (bytes > core::Packet::default_mtu - sizeof(PayloadMessage)) {
    TRANSPORT_LOGI("Producing content with name %s",
                   options.name.toString().c_str());
    producer_->asyncProduce(options.name,
                            reinterpret_cast<const uint8_t *>(buf), bytes);
    signalProductionToSubscribers(options.name);
  } else {
    TRANSPORT_LOGI("Sending payload through interest");
    piggybackPayloadToSubscribers(
        options.name, reinterpret_cast<const uint8_t *>(buf), bytes);
  }
}

void AsyncFullDuplexSocket::write(
    WriteCallback *callback, utils::SharableVector<uint8_t> &&output_buffer,
    const PublicationOptions &options, WriteFlags flags) {
  using namespace transport;

  // 1 asynchronously write the content. I assume here the
  // buffer contains the whole application frame. FIXME: check
  // if this is true and fix it accordingly
  std::cout << "Size of the PAYLOAD: " << output_buffer.size() << std::endl;

  if (output_buffer.size() >
      core::Packet::default_mtu - sizeof(PayloadMessage)) {
    TRANSPORT_LOGI("Producing content with name %s",
                   options.name.toString().c_str());
    producer_->asyncProduce(options.name, std::move(output_buffer));
    signalProductionToSubscribers(options.name);
  } else {
    TRANSPORT_LOGI("Sending payload through interest");
    piggybackPayloadToSubscribers(options.name, &output_buffer[0],
                                  output_buffer.size());
  }
}

void AsyncFullDuplexSocket::piggybackPayloadToSubscribers(
    const core::Name &name, const uint8_t *buffer, std::size_t bytes) {
  for (auto &sub : subscribers_) {
    auto interest = core::Interest::Ptr(new core::Interest(name));
    auto _payload = utils::MemBuf::create(bytes + sizeof(PayloadMessage));
    _payload->append(bytes + sizeof(PayloadMessage));
    auto payload = _payload->writableData();

    PayloadMessage *interest_payload =
        reinterpret_cast<PayloadMessage *>(payload);
    interest_payload->header.msg_type = MessageType::PAYLOAD;
    interest_payload->header.reserved[0] = 0;
    interest_payload->header.reserved[1] = 0;
    interest_payload->reserved[0] = 0;
    std::memcpy(payload + sizeof(PayloadMessage), buffer, bytes);
    interest->appendPayload(std::move(_payload));

    // Set the timeout of 0.2 second
    interest->setLifetime(1000);
    interest->setName(sub);
    interest->getWritableName().setSuffix(incremental_suffix_++);
    // TRANSPORT_LOGI("Sending signalization to %s",
    // interest->getName().toString().c_str());

    consumer_->asyncSendInterest(std::move(interest),
                                 internal_signal_callback_.get());
  }
}

void AsyncFullDuplexSocket::signalProductionToSubscribers(
    const core::Name &name) {
  // Signal the other part we are producing a content
  // Create an interest for a subscription

  for (auto &sub : subscribers_) {
    auto interest = core::Interest::Ptr(new core::Interest(name));
    // Todo consider using preallocated pool of membufs
    auto _payload = utils::MemBuf::create(sizeof(ActionMessage));
    _payload->append(sizeof(ActionMessage));
    auto payload = const_cast<uint8_t *>(interest->getPayload().data());

    ActionMessage *produce_notification =
        reinterpret_cast<ActionMessage *>(payload);
    produce_notification->header.msg_type = MessageType::ACTION;
    produce_notification->action = Action::SIGNAL_PRODUCTION;
    produce_notification->header.reserved[0] = 0;
    produce_notification->header.reserved[1] = 0;
    name.copyToDestination(
        reinterpret_cast<uint8_t *>(produce_notification->name));
    interest->appendPayload(std::move(_payload));

    // Set the timeout of 0.2 second
    interest->setLifetime(1000);
    interest->setName(sub);
    interest->getWritableName().setSuffix(incremental_suffix_++);
    // TRANSPORT_LOGI("Sending signalization to %s",
    // interest->getName().toString().c_str());

    consumer_->asyncSendInterest(std::move(interest),
                                 internal_signal_callback_.get());
  }
}

void AsyncFullDuplexSocket::waitForSubscribers(AcceptCallback *cb) {
  accept_callback_ = cb;
}

std::shared_ptr<core::ContentObject>
AsyncFullDuplexSocket::decodeSynchronizationMessage(
    const core::Interest &interest) {
  auto mesg = interest.getPayload();
  const MessageHeader *header =
      reinterpret_cast<const MessageHeader *>(mesg.data());

  switch (header->msg_type) {
    case MessageType::ACTION: {
      // Check what is the action to perform
      const ActionMessage *message =
          reinterpret_cast<const ActionMessage *>(header);

      if (message->action == Action::SUBSCRIBE) {
        // Add consumer to list on consumers to be notified
        auto ret =
            subscribers_.emplace(AF_INET6, (const uint8_t *)message->name, 0);
        TRANSPORT_LOGI("Added subscriber %s :)", ret.first->toString().c_str());
        if (ret.second) {
          accept_callback_->connectionAccepted(*ret.first);
        }

        TRANSPORT_LOGI("Connection success!");

        sync_notification_ = std::move(locator_.makeRandomName());
        return createSubscriptionResponse(sync_notification_);

      } else if (message->action == Action::CANCEL_SUBSCRIPTION) {
        // XXX Modify name!!! Each allocated name allocates a 128 bit array.
        subscribers_.erase(
            core::Name(AF_INET6, (const uint8_t *)message->name, 0));
        return createAck();
      } else if (message->action == Action::SIGNAL_PRODUCTION) {
        // trigger a reverse pull for the name contained in the message
        core::Name n(AF_INET6, (const uint8_t *)message->name, 0);
        std::cout << "PROD NOTIFICATION: Content to retrieve: " << n
                  << std::endl;
        std::cout << "PROD NOTIFICATION: Interest name: " << interest.getName()
                  << std::endl;  // << " compared to " << sync_notification_ <<
                                 // std::endl;

        if (sync_notification_.equals(interest.getName(), false)) {
          std::cout << "Starting reverse pull for " << n << std::endl;
          consumer_->asyncConsume(n, receive_buffer_);
          return createAck();
        }
      } else {
        TRANSPORT_LOGE("Received unknown message. Dropping it.");
      }

      break;
    }
    case MessageType::RESPONSE: {
      throw errors::RuntimeException(
          "The response should be a content object!!");
    }
    case MessageType::PAYLOAD: {
      // The interest contains the payload directly.
      // We saved one round trip :)

      auto buffer = std::make_shared<utils::SharableVector<uint8_t>>();
      const uint8_t *data = mesg.data() + sizeof(PayloadMessage);
      buffer->assign(data, data + mesg.length() - sizeof(PayloadMessage));
      read_callback_->readBufferAvailable(std::move(*buffer));
      return createAck();
    }
    default: {
      return std::shared_ptr<core::ContentObject>(nullptr);
    }
  }

  return std::shared_ptr<core::ContentObject>(nullptr);
}

void AsyncFullDuplexSocket::onControlInterest(ProducerSocket &s,
                                              const core::Interest &i) {
  auto payload = i.getPayload();
  if (payload.length()) {
    // Try to decode payload and see if starting an async pull operation
    auto response = decodeSynchronizationMessage(i);
    if (response) {
      response->setName(i.getName());
      s.produce(*response);
    }
  }
}

void AsyncFullDuplexSocket::onContentProduced(ProducerSocket &producer,
                                              const std::error_code &ec,
                                              uint64_t bytes_written) {
  if (write_callback_) {
    if (!ec) {
      write_callback_->writeSuccess();
    } else {
      write_callback_->writeErr(bytes_written);
    }
  }
}

void AsyncFullDuplexSocket::onContentRetrieved(ConsumerSocket &s,
                                               std::size_t size,
                                               const std::error_code &ec) {
  // Sanity check
  if (size != receive_buffer_->size()) {
    TRANSPORT_LOGE(
        "Received content size differs from size retrieved from the buffer.");
    return;
  }

  TRANSPORT_LOGI("Received content with size %lu", size);
  if (!ec) {
    read_callback_->readBufferAvailable(std::move(*receive_buffer_));
  } else {
    TRANSPORT_LOGE("Error retrieving content.");
  }
  // consumer_->stop();
}

void AsyncFullDuplexSocket::OnConnectCallback::onContentObject(
    core::Interest::Ptr &&, core::ContentObject::Ptr &&content_object) {
  // The ack message should contain the name to be used for notifying
  // the production of the content to the other part

  if (content_object->getPayload().length() == 0) {
    TRANSPORT_LOGW("Connection response message empty....");
    return;
  }

  SubscriptionResponseMessage *response =
      reinterpret_cast<SubscriptionResponseMessage *>(
          content_object->getPayload().writableData());

  if (response->response.header.msg_type == MessageType::RESPONSE) {
    if (response->response.return_code == ReturnCode::OK) {
      auto ret =
          socket_.subscribers_.emplace(AF_INET6, (uint8_t *)response->name, 0);
      TRANSPORT_LOGI("Successfully connected!!!! Subscriber added: %s",
                     ret.first->toString().c_str());
      socket_.connect_callback_->connectSuccess();
    }
  }
}

void AsyncFullDuplexSocket::OnSignalCallback::onContentObject(
    core::Interest::Ptr &&, core::ContentObject::Ptr &&content_object) {
  return;
}

void AsyncFullDuplexSocket::OnSignalCallback::onTimeout(
    core::Interest::Ptr &&interest) {
  TRANSPORT_LOGE("Retransmitting signalization interest to %s!!",
                 interest->getName().toString().c_str());
  socket_.consumer_->asyncSendInterest(std::move(interest),
                                       socket_.internal_signal_callback_.get());
}

void AsyncFullDuplexSocket::OnConnectCallback::onTimeout(
    core::Interest::Ptr &&interest) {
  socket_.connect_callback_->connectErr(
      std::make_error_code(std::errc::not_connected));
}

std::shared_ptr<core::ContentObject> AsyncFullDuplexSocket::createAck() {
  // Send the response back
  core::Name name("b001::abcd");
  auto response = std::make_shared<core::ContentObject>(name);
  auto _payload = utils::MemBuf::create(sizeof(ActionMessage));
  _payload->append(sizeof(ResponseMessage));
  auto payload = response->getPayload().data();
  ResponseMessage *response_message = (ResponseMessage *)payload;
  response_message->header.msg_type = MessageType::RESPONSE;
  response_message->header.reserved[0] = 0;
  response_message->header.reserved[1] = 0;
  response_message->return_code = ReturnCode::OK;
  response->appendPayload(std::move(_payload));
  response->setLifetime(0);
  return response;
}

std::shared_ptr<core::ContentObject>
AsyncFullDuplexSocket::createSubscriptionResponse(const core::Name &name) {
  // Send the response back
  core::Name tmp_name("b001::abcd");
  auto response = std::make_shared<core::ContentObject>(tmp_name);
  auto _payload = utils::MemBuf::create(sizeof(SubscriptionResponseMessage));
  _payload->append(sizeof(SubscriptionResponseMessage));
  auto payload = _payload->data();
  SubscriptionResponseMessage *response_message =
      (SubscriptionResponseMessage *)payload;
  response_message->response.header.msg_type = MessageType::RESPONSE;
  response_message->response.header.reserved[0] = 0;
  response_message->response.header.reserved[1] = 0;
  response_message->response.return_code = ReturnCode::OK;
  name.copyToDestination(reinterpret_cast<uint8_t *>(response_message->name));
  response->appendPayload(std::move(_payload));
  response->setLifetime(0);
  return response;
}

}  // namespace interface
}  // namespace transport
