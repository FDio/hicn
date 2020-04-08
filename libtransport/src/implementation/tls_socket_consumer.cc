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

#include <implementation/tls_socket_consumer.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <random>

namespace transport {
namespace implementation {

void TLSConsumerSocket::setInterestPayload(interface::ConsumerSocket &c,
                                           const core::Interest &interest) {
  Interest &int2 = const_cast<Interest &>(interest);
  random_suffix_ = int2.getName().getSuffix();

  if (payload_ != NULL) int2.appendPayload(std::move(payload_));
}

/* Return the number of read bytes in the return param */
int readOldTLS(BIO *b, char *buf, int size) {
  if (size < 0) return size;

  TLSConsumerSocket *socket;
  socket = (TLSConsumerSocket *)BIO_get_data(b);

  std::unique_lock<std::mutex> lck(socket->mtx_);

  if (!socket->something_to_read_) {
    if (!socket->transport_protocol_->isRunning()) {
      socket->network_name_.setSuffix(socket->random_suffix_);
      socket->ConsumerSocket::asyncConsume(socket->network_name_);
    }

    if (!socket->something_to_read_) socket->cv_.wait(lck);
  }

  size_t size_to_read, read;
  size_t chain_size = socket->head_->length();

  if (socket->head_->isChained())
    chain_size = socket->head_->computeChainDataLength();

  if (chain_size > (size_t)size) {
    read = size_to_read = (size_t)size;
  } else {
    read = size_to_read = chain_size;
    socket->something_to_read_ = false;
  }

  while (size_to_read) {
    if (socket->head_->length() < size_to_read) {
      std::memcpy(buf, socket->head_->data(), socket->head_->length());
      size_to_read -= socket->head_->length();
      buf += socket->head_->length();
      socket->head_ = socket->head_->pop();
    } else {
      std::memcpy(buf, socket->head_->data(), size_to_read);
      socket->head_->trimStart(size_to_read);
      size_to_read = 0;
    }
  }

  return read;
}

/* Return the number of read bytes in readbytes */
int readTLS(BIO *b, char *buf, size_t size, size_t *readbytes) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = readOldTLS(b, buf, (int)size);

  if (ret <= 0) {
    *readbytes = 0;
    return ret;
  }

  *readbytes = (size_t)ret;

  return 1;
}

/* Return the number of written bytes in the return param */
int writeOldTLS(BIO *b, const char *buf, int num) {
  TLSConsumerSocket *socket;
  socket = (TLSConsumerSocket *)BIO_get_data(b);

  socket->payload_ = utils::MemBuf::copyBuffer(buf, num);

  socket->ConsumerSocket::setSocketOption(
      ConsumerCallbacksOptions::INTEREST_OUTPUT,
      (ConsumerInterestCallback)std::bind(
          &TLSConsumerSocket::setInterestPayload, socket, std::placeholders::_1,
          std::placeholders::_2));

  return num;
}

/* Return the number of written bytes in written */
int writeTLS(BIO *b, const char *buf, size_t size, size_t *written) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = writeOldTLS(b, buf, (int)size);

  if (ret <= 0) {
    *written = 0;
    return ret;
  }

  *written = (size_t)ret;

  return 1;
}

long ctrlTLS(BIO *b, int cmd, long num, void *ptr) { return 1; }

TLSConsumerSocket::TLSConsumerSocket(interface::ConsumerSocket *consumer_socket,
                                     int protocol, SSL *ssl)
    : ConsumerSocket(consumer_socket, protocol),
      name_(),
      buf_pool_(),
      decrypted_content_(),
      payload_(),
      head_(),
      something_to_read_(false),
      content_downloaded_(false),
      random_suffix_(),
      producer_namespace_(),
      read_callback_decrypted_(),
      mtx_(),
      cv_(),
      async_downloader_tls_() {
  /* Create the (d)TLS state */
  const SSL_METHOD *meth = TLS_client_method();
  ctx_ = SSL_CTX_new(meth);

  int result =
      SSL_CTX_set_ciphersuites(ctx_,
                               "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
                               "SHA256:TLS_AES_128_GCM_SHA256");
  if (result != 1) {
    throw errors::RuntimeException(
        "Unable to set cipher list on TLS subsystem. Aborting.");
  }

  SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_ssl_version(ctx_, meth);

  ssl_ = ssl;

  BIO_METHOD *bio_meth =
      BIO_meth_new(BIO_TYPE_CONNECT, "secure consumer socket");
  BIO_meth_set_read(bio_meth, readOldTLS);
  BIO_meth_set_write(bio_meth, writeOldTLS);
  BIO_meth_set_ctrl(bio_meth, ctrlTLS);
  BIO *bio = BIO_new(bio_meth);
  BIO_set_init(bio, 1);
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);

  ConsumerSocket::getSocketOption(MAX_WINDOW_SIZE, old_max_win_);
  ConsumerSocket::setSocketOption(MAX_WINDOW_SIZE, (double)1.0);

  ConsumerSocket::getSocketOption(CURRENT_WINDOW_SIZE, old_current_win_);
  ConsumerSocket::setSocketOption(CURRENT_WINDOW_SIZE, (double)1.0);

  std::default_random_engine generator;
  std::uniform_int_distribution<int> distribution(
      1, std::numeric_limits<uint32_t>::max());
  random_suffix_ = 0;

  this->ConsumerSocket::setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
                                        this);
};

/* The producer interface is not owned by the application, so is TLSSocket task
 * to deallocate the memory */
TLSConsumerSocket::~TLSConsumerSocket() { delete consumer_interface_; }

int TLSConsumerSocket::consume(const Name &name,
                               std::unique_ptr<utils::MemBuf> &&buffer) {
  this->payload_ = std::move(buffer);

  this->ConsumerSocket::setSocketOption(
      ConsumerCallbacksOptions::INTEREST_OUTPUT,
      (ConsumerInterestCallback)std::bind(
          &TLSConsumerSocket::setInterestPayload, this, std::placeholders::_1,
          std::placeholders::_2));

  return consume(name);
}

int TLSConsumerSocket::consume(const Name &name) {
  if (transport_protocol_->isRunning()) {
    return CONSUMER_BUSY;
  }

  if ((SSL_in_before(this->ssl_) || SSL_in_init(this->ssl_))) {
    throw errors::RuntimeException("Handshake not performed");
  }

  return download_content(name);
}

int TLSConsumerSocket::download_content(const Name &name) {
  network_name_ = name;
  network_name_.setSuffix(0);
  something_to_read_ = false;
  content_downloaded_ = false;

  decrypted_content_ = utils::MemBuf::createCombined(SSL3_RT_MAX_PLAIN_LENGTH);
  uint8_t *buf = decrypted_content_->writableData();
  size_t size = 0;
  int result = -1;

  while (!content_downloaded_ || something_to_read_) {
    if (decrypted_content_->tailroom() < SSL3_RT_MAX_PLAIN_LENGTH) {
      decrypted_content_->appendChain(
          utils::MemBuf::createCombined(SSL3_RT_MAX_PLAIN_LENGTH));
      // decrypted_content_->computeChainDataLength();
      buf = decrypted_content_->prev()->writableData();
    } else {
      buf = decrypted_content_->writableTail();
    }

    result = SSL_read(this->ssl_, buf, SSL3_RT_MAX_PLAIN_LENGTH);

    /* SSL_read returns the data only if there were SSL3_RT_MAX_PLAIN_LENGTH of
     * the data has been fully downloaded */

    /* ASSERT((result < SSL3_RT_MAX_PLAIN_LENGTH && content_downloaded_) || */
    /*         result == SSL3_RT_MAX_PLAIN_LENGTH); */

    if (result >= 0) {
      size += result;
      decrypted_content_->prepend(result);
    } else {
      throw errors::RuntimeException("Unable to download content");
    }

    if (size >= read_callback_decrypted_->maxBufferSize()) {
      if (read_callback_decrypted_->isBufferMovable()) {
        /* No need to perform an additional copy. The whole buffer will be
         * tranferred to the application. */
        read_callback_decrypted_->readBufferAvailable(
            std::move(decrypted_content_));
        decrypted_content_ = utils::MemBuf::create(SSL3_RT_MAX_PLAIN_LENGTH);
      } else {
        /* The buffer will be copied into the application-provided buffer */
        uint8_t *buffer;
        std::size_t length;
        std::size_t total_length = decrypted_content_->length();

        while (decrypted_content_->length()) {
          buffer = nullptr;
          length = 0;
          read_callback_decrypted_->getReadBuffer(&buffer, &length);

          if (!buffer || !length) {
            throw errors::RuntimeException(
                "Invalid buffer provided by the application.");
          }

          auto to_copy = std::min(decrypted_content_->length(), length);
          std::memcpy(buffer, decrypted_content_->data(), to_copy);
          decrypted_content_->trimStart(to_copy);
        }

        read_callback_decrypted_->readDataAvailable(total_length);
        decrypted_content_->clear();
      }
    }
  }

  read_callback_decrypted_->readSuccess(size);

  return CONSUMER_FINISHED;
}

int TLSConsumerSocket::asyncConsume(const Name &name,
                                    std::unique_ptr<utils::MemBuf> &&buffer) {
  this->payload_ = std::move(buffer);

  this->ConsumerSocket::setSocketOption(
      ConsumerCallbacksOptions::INTEREST_OUTPUT,
      (ConsumerInterestCallback)std::bind(
          &TLSConsumerSocket::setInterestPayload, this, std::placeholders::_1,
          std::placeholders::_2));

  return asyncConsume(name);
}

int TLSConsumerSocket::asyncConsume(const Name &name) {
  if ((SSL_in_before(this->ssl_) || SSL_in_init(this->ssl_))) {
    throw errors::RuntimeException("Handshake not performed");
  }

  if (!async_downloader_tls_.stopped()) {
    async_downloader_tls_.add([this, name]() {
      is_async_ = true;
      download_content(name);
    });
  }

  return CONSUMER_RUNNING;
}

void TLSConsumerSocket::registerPrefix(const Prefix &producer_namespace) {
  producer_namespace_ = producer_namespace;
}

int TLSConsumerSocket::setSocketOption(int socket_option_key,
                                       ReadCallback *socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key, ReadCallback *socket_option_value) -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::READ_CALLBACK:
            read_callback_decrypted_ = socket_option_value;
            break;
          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

void TLSConsumerSocket::getReadBuffer(uint8_t **application_buffer,
                                      size_t *max_length) {}

void TLSConsumerSocket::readDataAvailable(size_t length) noexcept {}

size_t TLSConsumerSocket::maxBufferSize() const {
  return SSL3_RT_MAX_PLAIN_LENGTH;
}

void TLSConsumerSocket::readBufferAvailable(
    std::unique_ptr<utils::MemBuf> &&buffer) noexcept {
  std::unique_lock<std::mutex> lck(this->mtx_);

  if (head_) {
    head_->prependChain(std::move(buffer));
  } else {
    head_ = std::move(buffer);
  }

  something_to_read_ = true;
  cv_.notify_one();
}

void TLSConsumerSocket::readError(const std::error_code ec) noexcept {}

void TLSConsumerSocket::readSuccess(std::size_t total_size) noexcept {
  std::unique_lock<std::mutex> lck(this->mtx_);
  content_downloaded_ = true;
  something_to_read_ = true;
  cv_.notify_one();
}

bool TLSConsumerSocket::isBufferMovable() noexcept { return true; }

}  // namespace implementation
}  // namespace transport
