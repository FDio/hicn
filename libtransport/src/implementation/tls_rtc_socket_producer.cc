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

#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/p2psecure_socket_producer.h>

#include <implementation/p2psecure_socket_producer.h>
#include <implementation/tls_rtc_socket_producer.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace transport {
namespace implementation {

int TLSRTCProducerSocket::read(BIO *b, char *buf, size_t size,
                               size_t *readbytes) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = TLSRTCProducerSocket::readOld(b, buf, (int)size);

  if (ret <= 0) {
    *readbytes = 0;
    return ret;
  }

  *readbytes = (size_t)ret;

  return 1;
}

int TLSRTCProducerSocket::readOld(BIO *b, char *buf, int size) {
  TLSRTCProducerSocket *socket;
  socket = (TLSRTCProducerSocket *)BIO_get_data(b);

  std::unique_lock<std::mutex> lck(socket->mtx_);
  if (!socket->something_to_read_) {
    (socket->cv_).wait(lck);
  }

  utils::MemBuf *membuf = socket->packet_->next();
  int size_to_read;

  if ((int)membuf->length() > size) {
    size_to_read = size;
  } else {
    size_to_read = membuf->length();
    socket->something_to_read_ = false;
  }

  std::memcpy(buf, membuf->data(), size_to_read);
  membuf->trimStart(size_to_read);

  return size_to_read;
}

int TLSRTCProducerSocket::write(BIO *b, const char *buf, size_t size,
                                size_t *written) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = TLSRTCProducerSocket::writeOld(b, buf, (int)size);

  if (ret <= 0) {
    *written = 0;
    return ret;
  }

  *written = (size_t)ret;

  return 1;
}

int TLSRTCProducerSocket::writeOld(BIO *b, const char *buf, int num) {
  TLSRTCProducerSocket *socket;
  socket = (TLSRTCProducerSocket *)BIO_get_data(b);

  if ((SSL_in_before(socket->ssl_) || SSL_in_init(socket->ssl_)) &&
      socket->first_) {
    socket->tls_chunks_--;
    bool making_manifest = socket->parent_->making_manifest_;
    socket->parent_->setSocketOption(GeneralTransportOptions::MAKE_MANIFEST,
                                     false);
    socket->parent_->ProducerSocket::produce(
        socket->name_, (const uint8_t *)buf, num, socket->tls_chunks_ == 0, 0);
    socket->parent_->setSocketOption(GeneralTransportOptions::MAKE_MANIFEST,
                                     making_manifest);
    socket->first_ = false;

  } else {
    std::unique_ptr<utils::MemBuf> mbuf =
        utils::MemBuf::copyBuffer(buf, (std::size_t)num, 0, 0);
    auto a = mbuf.release();
    socket->async_thread_.add([socket = socket, a]() {
      socket->to_call_oncontentproduced_--;
      auto mbuf = std::unique_ptr<utils::MemBuf>(a);
      socket->RTCProducerSocket::produce(std::move(mbuf));
      ProducerContentCallback on_content_produced_application;
      socket->getSocketOption(ProducerCallbacksOptions::CONTENT_PRODUCED,
                              on_content_produced_application);
      if (socket->to_call_oncontentproduced_ == 0 &&
          on_content_produced_application) {
        on_content_produced_application(
            (transport::interface::ProducerSocket &)(*socket->getInterface()),
            std::error_code(), 0);
      }
    });
  }

  return num;
}

TLSRTCProducerSocket::TLSRTCProducerSocket(
    interface::ProducerSocket *producer_socket, P2PSecureProducerSocket *parent,
    const Name &handshake_name)
    : ProducerSocket(producer_socket),
      RTCProducerSocket(producer_socket),
      TLSProducerSocket(producer_socket, parent, handshake_name) {
  BIO_METHOD *bio_meth =
      BIO_meth_new(BIO_TYPE_ACCEPT, "secure rtc producer socket");
  BIO_meth_set_read(bio_meth, TLSRTCProducerSocket::readOld);
  BIO_meth_set_write(bio_meth, TLSRTCProducerSocket::writeOld);
  BIO_meth_set_ctrl(bio_meth, TLSProducerSocket::ctrl);
  BIO *bio = BIO_new(bio_meth);
  BIO_set_init(bio, 1);
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
}

void TLSRTCProducerSocket::accept() {
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    tls_chunks_ = 1;
    int result = SSL_accept(ssl_);
    if (result != 1)
      throw errors::RuntimeException("Unable to perform client handshake");
  }

  TRANSPORT_LOGD("Handshake performed!");
  parent_->list_secure_rtc_producers.push_front(
      std::move(parent_->map_secure_rtc_producers[handshake_name_]));
  parent_->map_secure_rtc_producers.erase(handshake_name_);

  ProducerInterestCallback on_interest_process_decrypted;
  getSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                  on_interest_process_decrypted);

  if (on_interest_process_decrypted) {
    Interest inter(std::move(packet_));
    on_interest_process_decrypted(
        (transport::interface::ProducerSocket &)(*getInterface()), inter);
  }

  parent_->cv_.notify_one();
}

int TLSRTCProducerSocket::async_accept() {
  if (!async_thread_.stopped()) {
    async_thread_.add([this]() { this->TLSRTCProducerSocket::accept(); });
  } else {
    throw errors::RuntimeException(
        "Async thread not running, impossible to perform handshake");
  }

  return 1;
}

void TLSRTCProducerSocket::produce(std::unique_ptr<utils::MemBuf> &&buffer) {
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    throw errors::RuntimeException(
        "New handshake on the same P2P secure producer socket not supported");
  }

  size_t buf_size = buffer->length();
  tls_chunks_ = ceil((float)buf_size / (float)SSL3_RT_MAX_PLAIN_LENGTH);
  to_call_oncontentproduced_ = tls_chunks_;

  SSL_write(ssl_, buffer->data(), buf_size);
  BIO *wbio = SSL_get_wbio(ssl_);
  int i = BIO_flush(wbio);
  (void)i;  // To shut up gcc 5
}

}  // namespace implementation

}  // namespace transport
