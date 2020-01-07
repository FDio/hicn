#include <hicn/transport/interfaces/p2psecure_socket_consumer.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <random>

namespace transport {

namespace interface {

void P2PSecureConsumerSocket::setInterestPayload(
    ConsumerSocket &c, const core::Interest &interest) {
  Interest &int2 = const_cast<Interest &>(interest);
  random_suffix_ = int2.getName().getSuffix();

  if (payload_ != NULL) int2.appendPayload(std::move(payload_));
}

// implement void readBufferAvailable(), size_t maxBufferSize() const override,
// void readError(), void readSuccess(). getReadBuffer() and readDataAvailable()
// must be implemented even if empty.

/* Return the number of read bytes in the return param */
int readOld(BIO *b, char *buf, int size) {
  if (size < 0) return size;

  P2PSecureConsumerSocket *socket;
  socket = (P2PSecureConsumerSocket *)BIO_get_data(b);

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
int read(BIO *b, char *buf, size_t size, size_t *readbytes) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = transport::interface::readOld(b, buf, (int)size);

  if (ret <= 0) {
    *readbytes = 0;
    return ret;
  }

  *readbytes = (size_t)ret;

  return 1;
}

/* Return the number of written bytes in the return param */
int writeOld(BIO *b, const char *buf, int num) {
  P2PSecureConsumerSocket *socket;
  socket = (P2PSecureConsumerSocket *)BIO_get_data(b);

  socket->payload_ = utils::MemBuf::copyBuffer(buf, num);
  socket->ConsumerSocket::setSocketOption(
      ConsumerCallbacksOptions::INTEREST_OUTPUT,
      (ConsumerInterestCallback)std::bind(
          &P2PSecureConsumerSocket::setInterestPayload, socket,
          std::placeholders::_1, std::placeholders::_2));

  return num;
}

/* Return the number of written bytes in written */
int write(BIO *b, const char *buf, size_t size, size_t *written) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = transport::interface::writeOld(b, buf, (int)size);

  if (ret <= 0) {
    *written = 0;
    return ret;
  }

  *written = (size_t)ret;

  return 1;
}

long ctrl(BIO *b, int cmd, long num, void *ptr) { return 1; }

int P2PSecureConsumerSocket::addHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                            unsigned int context,
                                            const unsigned char **out,
                                            size_t *outlen, X509 *x,
                                            size_t chainidx, int *al,
                                            void *add_arg) {
  if (ext_type == 100) {
    *out = (unsigned char *)malloc(4);
    *(uint32_t *)*out = 10;
    *outlen = 4;
  }
  return 1;
}

void P2PSecureConsumerSocket::freeHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                              unsigned int context,
                                              const unsigned char *out,
                                              void *add_arg) {
  free(const_cast<unsigned char *>(out));
}

int P2PSecureConsumerSocket::parseHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                              unsigned int context,
                                              const unsigned char *in,
                                              size_t inlen, X509 *x,
                                              size_t chainidx, int *al,
                                              void *add_arg) {
  P2PSecureConsumerSocket *socket =
      reinterpret_cast<P2PSecureConsumerSocket *>(add_arg);
  if (ext_type == 100) {
    memcpy(&socket->secure_prefix_, in, sizeof(ip_prefix_t));
  }
  return 1;
}

P2PSecureConsumerSocket::P2PSecureConsumerSocket(int handshake_protocol, int transport_protocol)
    : ConsumerSocket(handshake_protocol),
      name_(),
      tls_consumer_(),
      buf_pool_(),
      decrypted_content_(),
      payload_(),
      head_(),
      something_to_read_(false),
      content_downloaded_(false),
      random_suffix_(),
      secure_prefix_(),
      producer_namespace_(),
      read_callback_decrypted_(),
      mtx_(),
      cv_(),
      protocol_(transport_protocol) {
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

  result = SSL_CTX_add_custom_ext(
      ctx_, 100, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
      P2PSecureConsumerSocket::addHicnKeyIdCb,
      P2PSecureConsumerSocket::freeHicnKeyIdCb, NULL,
      P2PSecureConsumerSocket::parseHicnKeyIdCb, this);

  ssl_ = SSL_new(ctx_);

  bio_meth_ = BIO_meth_new(BIO_TYPE_CONNECT, "secure consumer socket");
  BIO_meth_set_read(bio_meth_, transport::interface::readOld);
  BIO_meth_set_write(bio_meth_, transport::interface::writeOld);
  BIO_meth_set_ctrl(bio_meth_, transport::interface::ctrl);
  BIO *bio = BIO_new(bio_meth_);
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

P2PSecureConsumerSocket::~P2PSecureConsumerSocket() {
  BIO_meth_free(bio_meth_);
  SSL_shutdown(ssl_);
}

int P2PSecureConsumerSocket::consume(const Name &name) {
  if (transport_protocol_->isRunning()) {
    return CONSUMER_BUSY;
  }

  if ((SSL_in_before(this->ssl_) || SSL_in_init(this->ssl_))) {
    ConsumerSocket::setSocketOption(MAX_WINDOW_SIZE, (double)1.0);
    network_name_ = producer_namespace_.getRandomName();
    network_name_.setSuffix(0);
    int result = SSL_connect(this->ssl_);
    ConsumerSocket::setSocketOption(MAX_WINDOW_SIZE, old_max_win_);
    ConsumerSocket::setSocketOption(CURRENT_WINDOW_SIZE, old_current_win_);
    if (result != 1)
      throw errors::RuntimeException("Unable to perform client handshake");
  }
  std::shared_ptr<Name> prefix_name = std::make_shared<Name>(
      secure_prefix_.family,
      ip_address_get_buffer(&(secure_prefix_.address), secure_prefix_.family));
  std::shared_ptr<Prefix> prefix =
      std::make_shared<Prefix>(*prefix_name, secure_prefix_.len);
  TLSConsumerSocket tls_consumer(this->protocol_, this->ssl_);

  ConsumerTimerCallback *stats_summary_callback = nullptr;
  this->getSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                        &stats_summary_callback);

  uint32_t lifetime;
  this->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME, lifetime);
  tls_consumer.setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                               lifetime);
  tls_consumer.setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
                               read_callback_decrypted_);
  tls_consumer.setSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                               *stats_summary_callback);
  tls_consumer.setSocketOption(GeneralTransportOptions::STATS_INTERVAL,
                               this->timer_interval_milliseconds_);
  tls_consumer.setSocketOption(MAX_WINDOW_SIZE, old_max_win_);
  tls_consumer.setSocketOption(CURRENT_WINDOW_SIZE, old_current_win_);
  tls_consumer.connect();

  if (payload_ != NULL)
    return tls_consumer.consume((prefix->mapName(name)), std::move(payload_));
  else
    return tls_consumer.consume((prefix->mapName(name)));
}

int P2PSecureConsumerSocket::asyncConsume(const Name &name) {
  if ((SSL_in_before(this->ssl_) || SSL_in_init(this->ssl_))) {
    ConsumerSocket::setSocketOption(CURRENT_WINDOW_SIZE, (double)1.0);
    ConsumerSocket::setSocketOption(MAX_WINDOW_SIZE, (double)1.0);
    network_name_ = producer_namespace_.getRandomName();
    network_name_.setSuffix(0);
    TRANSPORT_LOGD("Start handshake at %s", network_name_.toString().c_str());
    interface::ConsumerSocket::ReadCallback *on_payload = VOID_HANDLER;
    this->getSocketOption(ConsumerCallbacksOptions::READ_CALLBACK, &on_payload);
    int result = SSL_connect(this->ssl_);
    ConsumerSocket::setSocketOption(MAX_WINDOW_SIZE, old_max_win_);
    ConsumerSocket::setSocketOption(CURRENT_WINDOW_SIZE, old_current_win_);
    if (result != 1)
      throw errors::RuntimeException("Unable to perform client handshake");
    TRANSPORT_LOGD("Handshake performed!");
  }

  std::shared_ptr<Name> prefix_name = std::make_shared<Name>(
      secure_prefix_.family,
      ip_address_get_buffer(&(secure_prefix_.address), secure_prefix_.family));
  std::shared_ptr<Prefix> prefix =
      std::make_shared<Prefix>(*prefix_name, secure_prefix_.len);
  tls_consumer_ =
      std::make_shared<TLSConsumerSocket>(this->protocol_, this->ssl_);

  ConsumerTimerCallback *stats_summary_callback = nullptr;
  this->getSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                        &stats_summary_callback);

  uint32_t lifetime;
  this->getSocketOption(GeneralTransportOptions::INTEREST_LIFETIME, lifetime);
  tls_consumer_->setSocketOption(GeneralTransportOptions::INTEREST_LIFETIME,
                                 lifetime);
  tls_consumer_->setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK,
                                 read_callback_decrypted_);
  tls_consumer_->setSocketOption(ConsumerCallbacksOptions::STATS_SUMMARY,
                                 *stats_summary_callback);
  tls_consumer_->setSocketOption(GeneralTransportOptions::STATS_INTERVAL,
                                 this->timer_interval_milliseconds_);
  tls_consumer_->setSocketOption(MAX_WINDOW_SIZE, old_max_win_);
  tls_consumer_->setSocketOption(CURRENT_WINDOW_SIZE, old_current_win_);
  tls_consumer_->connect();

  if (payload_ != NULL)
    return tls_consumer_->asyncConsume((prefix->mapName(name)),
                                       std::move(payload_));
  else
    return tls_consumer_->asyncConsume((prefix->mapName(name)));
}

void P2PSecureConsumerSocket::registerPrefix(const Prefix &producer_namespace) {
  producer_namespace_ = producer_namespace;
}

int P2PSecureConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerSocket::ReadCallback *socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ConsumerSocket::ReadCallback *socket_option_value) -> int {
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

void P2PSecureConsumerSocket::getReadBuffer(uint8_t **application_buffer,
                                            size_t *max_length){};

void P2PSecureConsumerSocket::readDataAvailable(size_t length) noexcept {};

size_t P2PSecureConsumerSocket::maxBufferSize() const {
  return SSL3_RT_MAX_PLAIN_LENGTH;
}

void P2PSecureConsumerSocket::readBufferAvailable(
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

void P2PSecureConsumerSocket::readError(const std::error_code ec) noexcept {};

void P2PSecureConsumerSocket::readSuccess(std::size_t total_size) noexcept {
  std::unique_lock<std::mutex> lck(this->mtx_);
  content_downloaded_ = true;
  something_to_read_ = true;
  cv_.notify_one();
}

bool P2PSecureConsumerSocket::isBufferMovable() noexcept { return true; }

}  // namespace interface

}  // namespace transport
