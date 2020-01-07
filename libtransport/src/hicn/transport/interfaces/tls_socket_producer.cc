#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/p2psecure_socket_producer.h>
#include <hicn/transport/interfaces/tls_socket_producer.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace transport {

namespace interface {

/* Return the number of read bytes in readbytes */
int TLSProducerSocket::read(BIO *b, char *buf, size_t size, size_t *readbytes) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = TLSProducerSocket::readOld(b, buf, (int)size);

  if (ret <= 0) {
    *readbytes = 0;
    return ret;
  }

  *readbytes = (size_t)ret;

  return 1;
}

/* Return the number of read bytes in the return param */
int TLSProducerSocket::readOld(BIO *b, char *buf, int size) {
  TLSProducerSocket *socket;
  socket = (TLSProducerSocket *)BIO_get_data(b);

  /* take a lock on the mutex. It will be unlocked by */
  std::unique_lock<std::mutex> lck(socket->mtx_);
  if (!socket->something_to_read_) {
    (socket->cv_).wait(lck);
  }

  /* Either there already is something to read, or the thread has been waken up
   */
  /* must return the payload in the interest */

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

/* Return the number of written bytes in written */
int TLSProducerSocket::write(BIO *b, const char *buf, size_t size,
                             size_t *written) {
  int ret;

  if (size > INT_MAX) size = INT_MAX;

  ret = TLSProducerSocket::writeOld(b, buf, (int)size);

  if (ret <= 0) {
    *written = 0;
    return ret;
  }

  *written = (size_t)ret;

  return 1;
}

/* Return the number of written bytes in the return param */
int TLSProducerSocket::writeOld(BIO *b, const char *buf, int num) {
  TLSProducerSocket *socket;
  socket = (TLSProducerSocket *)BIO_get_data(b);

  if ((SSL_in_before(socket->ssl_) || SSL_in_init(socket->ssl_)) &&
      socket->first_) {
    //! socket->tls_chunks_ corresponds to is_last
    socket->tls_chunks_--;
    bool making_manifest = socket->parent_->making_manifest_;
    socket->parent_->setSocketOption(GeneralTransportOptions::MAKE_MANIFEST,
                                     false);
    socket->parent_->ProducerSocket::produce(
        socket->name_, (const uint8_t *)buf, num, socket->tls_chunks_ == 0,
        socket->last_segment_);
    socket->parent_->setSocketOption(GeneralTransportOptions::MAKE_MANIFEST,
                                     making_manifest);
    socket->first_ = false;
  } else {
    socket->still_writing_ = true;

    std::unique_ptr<utils::MemBuf> mbuf =
        utils::MemBuf::copyBuffer(buf, (std::size_t)num, 0, 0);
    auto a = mbuf.release();
    socket->async_thread_.add([socket = socket, a]() {
      socket->tls_chunks_--;
      socket->to_call_oncontentproduced_--;
      auto mbuf = std::unique_ptr<utils::MemBuf>(a);
      socket->last_segment_ += socket->ProducerSocket::produce(
          socket->name_, std::move(mbuf), socket->tls_chunks_ == 0,
          socket->last_segment_);
      ProducerContentCallback on_content_produced_application;
      socket->getSocketOption(ProducerCallbacksOptions::CONTENT_PRODUCED,
                              on_content_produced_application);
      if (socket->to_call_oncontentproduced_ == 0 &&
          on_content_produced_application) {
        on_content_produced_application(*socket, std::error_code(), 0);
      }
    });
  }

  return num;
}

TLSProducerSocket::TLSProducerSocket(P2PSecureProducerSocket *parent,
                                     const Name &handshake_name)
    : ProducerSocket(),
      on_content_produced_application_(),
      mtx_(),
      cv_(),
      something_to_read_(),
      name_(),
      last_segment_(0),
      parent_(parent),
      first_(true),
      handshake_name_(handshake_name),
      tls_chunks_(0),
      to_call_oncontentproduced_(0),
      still_writing_(false),
      encryption_thread_() {
  const SSL_METHOD *meth = TLS_server_method();
  ctx_ = SSL_CTX_new(meth);

  /*
   * Setup SSL context (identity and parameter to use TLS 1.3)
   */
  SSL_CTX_use_certificate(ctx_, parent->cert_509_);
  SSL_CTX_use_PrivateKey(ctx_, parent->pkey_rsa_);

  int result =
      SSL_CTX_set_ciphersuites(ctx_,
                               "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
                               "SHA256:TLS_AES_128_GCM_SHA256");
  if (result != 1) {
    throw errors::RuntimeException(
        "Unable to set cipher list on TLS subsystem. Aborting.");
  }

  // We force it to be TLS 1.3
  SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_num_tickets(ctx_, 0);

  result = SSL_CTX_add_custom_ext(
      ctx_, 100, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
      TLSProducerSocket::addHicnKeyIdCb, TLSProducerSocket::freeHicnKeyIdCb,
      this, TLSProducerSocket::parseHicnKeyIdCb, NULL);

  ssl_ = SSL_new(ctx_);
  /*
   * Setup this producer socker as the bio that TLS will use to write and read
   * data (in stream mode)
   */
  BIO_METHOD *bio_meth =
      BIO_meth_new(BIO_TYPE_ACCEPT, "secure producer socket");
  BIO_meth_set_read(bio_meth, TLSProducerSocket::readOld);
  BIO_meth_set_write(bio_meth, TLSProducerSocket::writeOld);
  BIO_meth_set_ctrl(bio_meth, TLSProducerSocket::ctrl);
  BIO *bio = BIO_new(bio_meth);
  BIO_set_init(bio, 1);
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  /*
   * Set the callback so that when an interest is received we catch it and we
   * decrypt the payload before passing it to the application.
   */
  this->ProducerSocket::setSocketOption(
      ProducerCallbacksOptions::CACHE_MISS,
      (ProducerInterestCallback)std::bind(&TLSProducerSocket::cacheMiss, this,
                                          std::placeholders::_1,
                                          std::placeholders::_2));
  this->ProducerSocket::setSocketOption(
      ProducerCallbacksOptions::CONTENT_PRODUCED,
      (ProducerContentCallback)bind(
          &TLSProducerSocket::onContentProduced, this, std::placeholders::_1,
          std::placeholders::_2, std::placeholders::_3));
}

void TLSProducerSocket::accept() {
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    tls_chunks_ = 1;
    int result = SSL_accept(ssl_);
    if (result != 1)
      throw errors::RuntimeException("Unable to perform client handshake");
  }
  TRANSPORT_LOGD("Handshake performed!");
  parent_->list_secure_producers.push_front(
      std::move(parent_->map_secure_producers[handshake_name_]));
  parent_->map_secure_producers.erase(handshake_name_);

  ProducerInterestCallback on_interest_process_decrypted;
  getSocketOption(ProducerCallbacksOptions::CACHE_MISS,
                  on_interest_process_decrypted);

  if (on_interest_process_decrypted) {
    Interest inter(std::move(packet_));
    on_interest_process_decrypted(*this, inter);
  } else {
    throw errors::RuntimeException(
        "On interest process unset. Unable to perform handshake");
  }
}

int TLSProducerSocket::async_accept() {
  if (!async_thread_.stopped()) {
    async_thread_.add([this]() { this->accept(); });
  } else {
    throw errors::RuntimeException(
        "Async thread not running, impossible to perform handshake");
  }

  return 1;
}

void TLSProducerSocket::onInterest(ProducerSocket &p, Interest &interest) {
  /* Based on the state machine of (D)TLS, we know what action to do */
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    std::unique_lock<std::mutex> lck(mtx_);
    name_ = interest.getName();
    something_to_read_ = true;
    packet_ = interest.acquireMemBufReference();
    if (head_) {
      payload_->prependChain(interest.getPayload());
    } else {
      payload_ = interest.getPayload();  // std::move(interest.getPayload());
    }
    cv_.notify_one();
  } else {
    name_ = interest.getName();
    packet_ = interest.acquireMemBufReference();
    payload_ = interest.getPayload();
    something_to_read_ = true;

    if (interest.getPayload()->length() > 0)
      SSL_read(
          ssl_,
          const_cast<unsigned char *>(interest.getPayload()->writableData()),
          interest.getPayload()->length());
  }

  ProducerInterestCallback on_interest_input_decrypted;
  getSocketOption(ProducerCallbacksOptions::INTEREST_INPUT,
                  on_interest_input_decrypted);
  if (on_interest_input_decrypted)
    (on_interest_input_decrypted)(*this, interest);
}

void TLSProducerSocket::cacheMiss(ProducerSocket &p, Interest &interest) {
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    std::unique_lock<std::mutex> lck(mtx_);
    name_ = interest.getName();
    something_to_read_ = true;
    packet_ = interest.acquireMemBufReference();
    payload_ = interest.getPayload();
    cv_.notify_one();
  } else {
    name_ = interest.getName();
    packet_ = interest.acquireMemBufReference();
    payload_ = interest.getPayload();
    something_to_read_ = true;

    if (interest.getPayload()->length() > 0)
      SSL_read(
          ssl_,
          const_cast<unsigned char *>(interest.getPayload()->writableData()),
          interest.getPayload()->length());

    if (on_interest_process_decrypted_ != VOID_HANDLER)
      on_interest_process_decrypted_(*this, interest);
  }
}

void TLSProducerSocket::onContentProduced(ProducerSocket &p,
                                          const std::error_code &err,
                                          uint64_t bytes_written) {}

uint32_t TLSProducerSocket::produce(Name content_name,
                                    std::unique_ptr<utils::MemBuf> &&buffer,
                                    bool is_last, uint32_t start_offset) {
  if (SSL_in_before(ssl_) || SSL_in_init(ssl_)) {
    throw errors::RuntimeException(
        "New handshake on the same P2P secure producer socket not supported");
  }
  size_t buf_size = buffer->length();
  name_ = served_namespaces_.front().mapName(content_name);

  tls_chunks_ = to_call_oncontentproduced_ =
      ceil((float)buf_size / (float)SSL3_RT_MAX_PLAIN_LENGTH);

  if (!is_last) {
    tls_chunks_++;
  }

  last_segment_ = start_offset;

  SSL_write(ssl_, buffer->data(), buf_size);
  BIO *wbio = SSL_get_wbio(ssl_);
  int i = BIO_flush(wbio);
  (void)i;  // To shut up gcc 5

  return 0;
}

void TLSProducerSocket::asyncProduce(const Name &content_name,
                                     const uint8_t *buf, size_t buffer_size,
                                     bool is_last, uint32_t *start_offset) {
  if (!encryption_thread_.stopped()) {
    encryption_thread_.add([this, content_name, buffer = buf,
                            size = buffer_size, is_last, start_offset]() {
      if (start_offset != NULL) {
        produce(content_name, buffer, size, is_last, *start_offset);
      } else {
        produce(content_name, buffer, size, is_last, 0);
      }
    });
  }
}

void TLSProducerSocket::asyncProduce(Name content_name,
                                     std::unique_ptr<utils::MemBuf> &&buffer,
                                     bool is_last, uint32_t offset,
                                     uint32_t **last_segment) {
  if (!encryption_thread_.stopped()) {
    auto a = buffer.release();
    encryption_thread_.add(
        [this, content_name, a, is_last, offset, last_segment]() {
          auto buf = std::unique_ptr<utils::MemBuf>(a);
          if (last_segment != NULL) {
            *last_segment = &last_segment_;
          }
          produce(content_name, std::move(buf), is_last, offset);
        });
  }
}

void TLSProducerSocket::asyncProduce(ContentObject &content_object) {
  throw errors::RuntimeException("API not supported");
}

void TLSProducerSocket::produce(ContentObject &content_object) {
  throw errors::RuntimeException("API not supported");
}

long TLSProducerSocket::ctrl(BIO *b, int cmd, long num, void *ptr) {
  if (cmd == BIO_CTRL_FLUSH) {
  }
  return 1;
}

int TLSProducerSocket::addHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                      unsigned int context,
                                      const unsigned char **out, size_t *outlen,
                                      X509 *x, size_t chainidx, int *al,
                                      void *add_arg) {
  TLSProducerSocket *socket = reinterpret_cast<TLSProducerSocket *>(add_arg);
  if (ext_type == 100) {
    ip_prefix_t ip_prefix =
        socket->parent_->served_namespaces_.front().toIpPrefixStruct();
    int inet_family =
        socket->parent_->served_namespaces_.front().getAddressFamily();
    uint16_t prefix_len_bits =
        socket->parent_->served_namespaces_.front().getPrefixLength();
    uint8_t prefix_len_bytes = prefix_len_bits / 8;
    uint8_t prefix_len_u32 = prefix_len_bits / 32;

    ip_prefix_t *out_ip = (ip_prefix_t *)malloc(sizeof(ip_prefix_t));
    out_ip->family = inet_family;
    out_ip->len = prefix_len_bits + 32;
    u8 *out_ip_buf = const_cast<u8 *>(
        ip_address_get_buffer(&(out_ip->address), inet_family));
    *out = reinterpret_cast<unsigned char *>(out_ip);

    RAND_bytes((unsigned char *)&socket->key_id_, 4);

    memcpy(out_ip_buf, ip_address_get_buffer(&(ip_prefix.address), inet_family),
           prefix_len_bytes);
    memcpy((out_ip_buf + prefix_len_bytes), &socket->key_id_, 4);
    *outlen = sizeof(ip_prefix_t);

    ip_address_t mask = {};
    ip_address_t keyId_component = {};
    u32 *mask_buf;
    u32 *keyId_component_buf;
    switch (inet_family) {
      case AF_INET:
        mask_buf = &(mask.v4.as_u32);
        keyId_component_buf = &(keyId_component.v4.as_u32);
        break;
      case AF_INET6:
        mask_buf = mask.v6.as_u32;
        keyId_component_buf = keyId_component.v6.as_u32;
        break;
      default:
        throw errors::RuntimeException("Unknown protocol");
    }

    if (prefix_len_bits > (inet_family == AF_INET6 ? IPV6_ADDR_LEN_BITS - 32
                                                   : IPV4_ADDR_LEN_BITS - 32))
      throw errors::RuntimeException(
          "Not enough space in the content name to add key_id");

    mask_buf[prefix_len_u32] = 0xffffffff;
    keyId_component_buf[prefix_len_u32] = socket->key_id_;
    socket->last_segment_ = 0;

    socket->on_interest_process_decrypted_ =
        socket->parent_->on_interest_process_decrypted_;

    socket->registerPrefix(
        Prefix(socket->parent_->served_namespaces_.front().getName(
                   Name(inet_family, (uint8_t *)&mask),
                   Name(inet_family, (uint8_t *)&keyId_component),
                   socket->parent_->served_namespaces_.front().getName()),
               out_ip->len));
    socket->connect();
  }
  return 1;
}

void TLSProducerSocket::freeHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char *out,
                                        void *add_arg) {
  free(const_cast<unsigned char *>(out));
}

int TLSProducerSocket::parseHicnKeyIdCb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char *in, size_t inlen,
                                        X509 *x, size_t chainidx, int *al,
                                        void *add_arg) {
  return 1;
}

int TLSProducerSocket::setSocketOption(
    int socket_option_key, ProducerInterestCallback socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ProducerInterestCallback socket_option_value) -> int {
        int result = SOCKET_OPTION_SET;
        switch (socket_option_key) {
          case ProducerCallbacksOptions::INTEREST_INPUT:
            on_interest_input_decrypted_ = socket_option_value;
            break;

          case ProducerCallbacksOptions::INTEREST_DROP:
            on_interest_dropped_input_buffer_ = socket_option_value;
            break;

          case ProducerCallbacksOptions::INTEREST_PASS:
            on_interest_inserted_input_buffer_ = socket_option_value;
            break;

          case ProducerCallbacksOptions::CACHE_HIT:
            on_interest_satisfied_output_buffer_ = socket_option_value;
            break;

          case ProducerCallbacksOptions::CACHE_MISS:
            on_interest_process_decrypted_ = socket_option_value;
            break;

          default:
            result = SOCKET_OPTION_NOT_SET;
            break;
        }
        return result;
      });
}

int TLSProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentCallback socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ProducerContentCallback socket_option_value) -> int {
        switch (socket_option_key) {
          case ProducerCallbacksOptions::CONTENT_PRODUCED:
            on_content_produced_application_ = socket_option_value;
            break;

          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

int TLSProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentCallback **socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ProducerContentCallback **socket_option_value) -> int {
        switch (socket_option_key) {
          case ProducerCallbacksOptions::CONTENT_PRODUCED:
            *socket_option_value = &on_content_produced_application_;
            break;

          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

int TLSProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentCallback &socket_option_value) {
  return rescheduleOnIOServiceWithReference(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ProducerContentCallback &socket_option_value) -> int {
        switch (socket_option_key) {
          case ProducerCallbacksOptions::CONTENT_PRODUCED:
            socket_option_value = on_content_produced_application_;
            break;

          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

int TLSProducerSocket::getSocketOption(
    int socket_option_key, ProducerInterestCallback &socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOServiceWithReference(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ProducerInterestCallback &socket_option_value) -> int {
        switch (socket_option_key) {
          case ProducerCallbacksOptions::INTEREST_INPUT:
            socket_option_value = on_interest_input_decrypted_;
            break;

          case ProducerCallbacksOptions::INTEREST_DROP:
            socket_option_value = on_interest_dropped_input_buffer_;
            break;

          case ProducerCallbacksOptions::INTEREST_PASS:
            socket_option_value = on_interest_inserted_input_buffer_;
            break;

          case ProducerCallbacksOptions::CACHE_HIT:
            socket_option_value = on_interest_satisfied_output_buffer_;
            break;

          case ProducerCallbacksOptions::CACHE_MISS:
            socket_option_value = on_interest_process_decrypted_;
            break;

          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

}  // namespace interface

}  // namespace transport
