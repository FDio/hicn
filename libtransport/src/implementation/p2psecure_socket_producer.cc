/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <hicn/transport/core/interest.h>

#include <implementation/p2psecure_socket_producer.h>
#include <implementation/tls_rtc_socket_producer.h>
#include <implementation/tls_socket_producer.h>
#include <interfaces/tls_rtc_socket_producer.h>
#include <interfaces/tls_socket_producer.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace transport {
namespace implementation {

/* Workaround to prevent content with expiry time equal to 0 to be lost when
 * pushed in the forwarder */
#define HICN_HANDSHAKE_CONTENT_EXPIRY_TIME 100;

P2PSecureProducerSocket::P2PSecureProducerSocket(
    interface::ProducerSocket *producer_socket)
    : ProducerSocket(producer_socket),
      mtx_(),
      cv_(),
      map_secure_producers(),
      map_secure_rtc_producers(),
      list_secure_producers() {}

P2PSecureProducerSocket::P2PSecureProducerSocket(
    interface::ProducerSocket *producer_socket, bool rtc,
    const std::shared_ptr<utils::Identity> &identity)
    : ProducerSocket(producer_socket),
      rtc_(rtc),
      mtx_(),
      cv_(),
      map_secure_producers(),
      map_secure_rtc_producers(),
      list_secure_producers() {
  /*
   * Setup SSL context (identity and parameter to use TLS 1.3)
   */
  der_cert_ = parcKeyStore_GetDEREncodedCertificate(
      (identity->getSigner()->getKeyStore()));
  der_prk_ = parcKeyStore_GetDEREncodedPrivateKey(
      (identity->getSigner()->getKeyStore()));

  int cert_size = parcBuffer_Limit(der_cert_);
  int prk_size = parcBuffer_Limit(der_prk_);
  const uint8_t *cert =
      reinterpret_cast<uint8_t *>(parcBuffer_Overlay(der_cert_, cert_size));
  const uint8_t *prk =
      reinterpret_cast<uint8_t *>(parcBuffer_Overlay(der_prk_, prk_size));
  cert_509_ = d2i_X509(NULL, &cert, cert_size);
  pkey_rsa_ = d2i_AutoPrivateKey(NULL, &prk, prk_size);

  /*
   * Set the callback so that when an interest is received we catch it and we
   * decrypt the payload before passing it to the application.
   */
  ProducerSocket::setSocketOption(
      ProducerCallbacksOptions::INTEREST_INPUT,
      (ProducerInterestCallback)std::bind(
          &P2PSecureProducerSocket::onInterestCallback, this,
          std::placeholders::_1, std::placeholders::_2));
}

P2PSecureProducerSocket::~P2PSecureProducerSocket() {
  if (der_cert_) parcBuffer_Release(&der_cert_);
  if (der_prk_) parcBuffer_Release(&der_prk_);
}

void P2PSecureProducerSocket::onInterestCallback(interface::ProducerSocket &p,
                                                 Interest &interest) {
  std::unique_lock<std::mutex> lck(mtx_);

  TRANSPORT_LOGD("Start handshake at %s",
                 interest.getName().toString().c_str());
  if (!rtc_) {
    auto it = map_secure_producers.find(interest.getName());
    if (it != map_secure_producers.end()) return;
    TLSProducerSocket *tls_producer =
        new TLSProducerSocket(nullptr, this, interest.getName());
    tls_producer->setInterface(new interface::TLSProducerSocket(tls_producer));

    tls_producer->on_content_produced_application_ =
        this->on_content_produced_application_;
    tls_producer->setSocketOption(CONTENT_OBJECT_EXPIRY_TIME,
                                  this->content_object_expiry_time_);
    tls_producer->setSocketOption(SIGNER, this->signer_);
    tls_producer->setSocketOption(MAKE_MANIFEST, this->making_manifest_);
    tls_producer->setSocketOption(DATA_PACKET_SIZE,
                                  (uint32_t)(this->data_packet_size_));
    tls_producer->output_buffer_.setLimit(this->output_buffer_.getLimit());
    map_secure_producers.insert(
        {interest.getName(), std::unique_ptr<TLSProducerSocket>(tls_producer)});
    tls_producer->onInterest(*tls_producer, interest);
    tls_producer->async_accept();
  } else {
    auto it = map_secure_rtc_producers.find(interest.getName());
    if (it != map_secure_rtc_producers.end()) return;
    TLSRTCProducerSocket *tls_producer =
        new TLSRTCProducerSocket(nullptr, this, interest.getName());
    tls_producer->setInterface(
        new interface::TLSRTCProducerSocket(tls_producer));
    tls_producer->on_content_produced_application_ =
        this->on_content_produced_application_;
    tls_producer->setSocketOption(CONTENT_OBJECT_EXPIRY_TIME,
                                  this->content_object_expiry_time_);
    tls_producer->setSocketOption(SIGNER, this->signer_);
    tls_producer->setSocketOption(MAKE_MANIFEST, this->making_manifest_);
    tls_producer->setSocketOption(DATA_PACKET_SIZE,
                                  (uint32_t)(this->data_packet_size_));
    tls_producer->output_buffer_.setLimit(this->output_buffer_.getLimit());
    map_secure_rtc_producers.insert(
        {interest.getName(),
         std::unique_ptr<TLSRTCProducerSocket>(tls_producer)});
    tls_producer->onInterest(*tls_producer, interest);
    tls_producer->async_accept();
  }
}

void P2PSecureProducerSocket::produce(const uint8_t *buffer,
                                      size_t buffer_size) {
  if (!rtc_) {
    throw errors::RuntimeException(
        "RTC must be the transport protocol to start the production of current "
        "data. Aborting.");
  }

  std::unique_lock<std::mutex> lck(mtx_);
  if (list_secure_rtc_producers.empty()) cv_.wait(lck);

  for (auto it = list_secure_rtc_producers.cbegin();
       it != list_secure_rtc_producers.cend(); it++) {
    (*it)->produce(utils::MemBuf::copyBuffer(buffer, buffer_size));
  }
}

uint32_t P2PSecureProducerSocket::produce(
    Name content_name, std::unique_ptr<utils::MemBuf> &&buffer, bool is_last,
    uint32_t start_offset) {
  if (rtc_) {
    throw errors::RuntimeException(
        "RTC transport protocol is not compatible with the production of "
        "current data. Aborting.");
  }

  std::unique_lock<std::mutex> lck(mtx_);
  uint32_t segments = 0;
  if (list_secure_producers.empty()) cv_.wait(lck);

  for (auto it = list_secure_producers.cbegin();
       it != list_secure_producers.cend(); it++)
    segments +=
        (*it)->produce(content_name, buffer->clone(), is_last, start_offset);
  return segments;
}

uint32_t P2PSecureProducerSocket::produce(Name content_name,
                                          const uint8_t *buffer,
                                          size_t buffer_size, bool is_last,
                                          uint32_t start_offset) {
  if (rtc_) {
    throw errors::RuntimeException(
        "RTC transport protocol is not compatible with the production of "
        "current data. Aborting.");
  }

  std::unique_lock<std::mutex> lck(mtx_);
  uint32_t segments = 0;
  if (list_secure_producers.empty()) cv_.wait(lck);

  for (auto it = list_secure_producers.cbegin();
       it != list_secure_producers.cend(); it++)
    segments += (*it)->produce(content_name, buffer, buffer_size, is_last,
                               start_offset);
  return segments;
}

void P2PSecureProducerSocket::asyncProduce(const Name &content_name,
                                           const uint8_t *buf,
                                           size_t buffer_size, bool is_last,
                                           uint32_t *start_offset) {
  if (rtc_) {
    throw errors::RuntimeException(
        "RTC transport protocol is not compatible with the production of "
        "current data. Aborting.");
  }

  std::unique_lock<std::mutex> lck(mtx_);
  if (list_secure_producers.empty()) cv_.wait(lck);

  for (auto it = list_secure_producers.cbegin();
       it != list_secure_producers.cend(); it++) {
    (*it)->asyncProduce(content_name, buf, buffer_size, is_last, start_offset);
  }
}

void P2PSecureProducerSocket::asyncProduce(
    Name content_name, std::unique_ptr<utils::MemBuf> &&buffer, bool is_last,
    uint32_t offset, uint32_t **last_segment) {
  if (rtc_) {
    throw errors::RuntimeException(
        "RTC transport protocol is not compatible with the production of "
        "current data. Aborting.");
  }

  std::unique_lock<std::mutex> lck(mtx_);
  if (list_secure_producers.empty()) cv_.wait(lck);

  for (auto it = list_secure_producers.cbegin();
       it != list_secure_producers.cend(); it++) {
    (*it)->asyncProduce(content_name, buffer->clone(), is_last, offset,
                        last_segment);
  }
}

// Socket Option Redefinition to avoid name hiding

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, ProducerInterestCallback socket_option_value) {
  if (!list_secure_producers.empty()) {
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);
  }

  switch (socket_option_key) {
    case ProducerCallbacksOptions::INTEREST_INPUT:
      on_interest_input_decrypted_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::INTEREST_DROP:
      on_interest_dropped_input_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::INTEREST_PASS:
      on_interest_inserted_input_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CACHE_HIT:
      on_interest_satisfied_output_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CACHE_MISS:
      on_interest_process_decrypted_ = socket_option_value;
      return SOCKET_OPTION_SET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<utils::Signer> &socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  switch (socket_option_key) {
    case GeneralTransportOptions::SIGNER: {
      signer_.reset();
      signer_ = socket_option_value;

      return SOCKET_OPTION_SET;
    }
    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int P2PSecureProducerSocket::setSocketOption(int socket_option_key,
                                             uint32_t socket_option_value) {
  if (!list_secure_producers.empty()) {
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);
  }
  switch (socket_option_key) {
    case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
      content_object_expiry_time_ =
          socket_option_value;  // HICN_HANDSHAKE_CONTENT_EXPIRY_TIME;
      return SOCKET_OPTION_SET;
  }
  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(int socket_option_key,
                                             bool socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(int socket_option_key,
                                             Name *socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, std::list<Prefix> socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentObjectCallback socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentCallback socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  switch (socket_option_key) {
    case ProducerCallbacksOptions::CONTENT_PRODUCED:
      on_content_produced_application_ = socket_option_value;
      break;

    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, HashAlgorithm socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, utils::CryptoSuite socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

int P2PSecureProducerSocket::setSocketOption(
    int socket_option_key, const std::string &socket_option_value) {
  if (!list_secure_producers.empty())
    for (auto it = list_secure_producers.cbegin();
         it != list_secure_producers.cend(); it++)
      (*it)->setSocketOption(socket_option_key, socket_option_value);

  return ProducerSocket::setSocketOption(socket_option_key,
                                         socket_option_value);
}

}  // namespace implementation

}  // namespace transport
