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

#include <hicn/transport/interfaces/c_api.h>
#include <hicn/transport/interfaces/c_api_errors.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/spinlock.h>

#include <set>

namespace transport {
namespace interface {
namespace details {

enum class RC {
  ERROR = -1,
  NO_ERROR = 0,
};

/**
 * Integer pool for managing reusing of socket integers.
 */
class IntegerPool {
  static constexpr uint32_t max_socket_number = (1 << 10);

  IntegerPool() {
    for (int i = 10; i < 10 + max_socket_number; i++) {
      insert(i);
    }
  }

 public:
  static IntegerPool* getInstance() {
    if (!instance_) {
      instance_ = std::unique_ptr<IntegerPool>(new IntegerPool());
    }

    return instance_.get();
  }

  void insert(int number) {
    utils::SpinLock::Acquire locked(lock_);
    integer_set_.emplace(number);
  }

  int get() {
    int ret = -1;

    {
      utils::SpinLock::Acquire locked(lock_);
      auto it = integer_set_.begin();
      if (it != integer_set_.end()) {
        ret = *it;
        integer_set_.erase(it);
      }
    }

    return ret;
  }

 private:
  utils::SpinLock lock_;
  std::set<int> integer_set_;
  static std::unique_ptr<IntegerPool> instance_;
};

/* Null, because instance will be initialized on demand. */
std::unique_ptr<IntegerPool> IntegerPool::instance_ = nullptr;

class Adapter {
 public:
  virtual int connectAddress(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                             hicn_socklen_t* __restrict len) = 0;
  virtual int send(int socket, const void* buff, size_t length, int flags) = 0;
  virtual int recv(int socket, const void* buff, size_t length, int flags) = 0;
  virtual int sendto(int socket, const void* buff, size_t length, int flags,
                     TRANSPORT_CONST_SOCKADDR_ARG address,
                     hicn_socklen_t addr_len) = 0;
  virtual int recvfrom(int socket, void* buff, size_t length, int flags,
                       TRANSPORT_SOCKADDR_ARG address,
                       hicn_socklen_t* __restrict len) = 0;
  virtual int sendmsg(int socket, const struct hicn_msghdr* message,
                      int flags) = 0;
  virtual int recvmsg(int socket, struct hicn_msghdr* message, int flags) = 0;
  virtual int shutdown(int socket, int how) = 0;
  virtual int close(int socket, int how) = 0;
  virtual int getsockopt(int socket, int level, int optname,
                         void* __restrict optval,
                         hicn_socklen_t* __restrict optlen) = 0;
  virtual int setsockopt(int socket, int level, int optname, const void* optval,
                         hicn_socklen_t optlen) = 0;
};

class ConsumerAdapter : ConsumerSocket, public Adapter {
 public:
  template <typename... Args>
  ConsumerAdapter(Args&&... args)
      : ConsumerSocket(std::forward<Args>(args)...) {}

  int connectAddress(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                     hicn_socklen_t* __restrict len) override {
    return 0;
  }

  int send(int socket, const void* buff, size_t length, int flags) override {
    return C_API_ERROR_NOT_IMPLEMENTED;
  }

  int recv(int socket, const void* buff, size_t length, int flags) override {
    return 0;
  }

  int sendto(int socket, const void* buff, size_t length, int flags,
             TRANSPORT_CONST_SOCKADDR_ARG address,
             hicn_socklen_t addr_len) override {
    return 0;
  }

  int recvfrom(int socket, void* buff, size_t length, int flags,
               TRANSPORT_SOCKADDR_ARG address,
               hicn_socklen_t* __restrict len) override {
    return 0;
  }

  int sendmsg(int socket, const struct hicn_msghdr* message,
              int flags) override {
    return 0;
  }

  int recvmsg(int socket, struct hicn_msghdr* message, int flags) override {
    return 0;
  }

  int shutdown(int socket, int how) override { return 0; }

  int close(int socket, int how) override { return 0; }

  int getsockopt(int socket, int level, int optname, void* __restrict optval,
                 hicn_socklen_t* __restrict optlen) override {
    return 0;
  }

  int setsockopt(int socket, int level, int optname, const void* optval,
                 hicn_socklen_t optlen) override {
    return 0;
  }
};

class ProducerAdapter : ProducerSocket, public Adapter {
 public:
  template <typename... Args>
  ProducerAdapter(Args&&... args)
      : ProducerSocket(std::forward<Args>(args)...) {}

  int connectAddress(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                     hicn_socklen_t* __restrict len) override {
    return 0;
  }

  int send(int socket, const void* buff, size_t length, int flags) override {
    return 0;
  }

  int recv(int socket, const void* buff, size_t length, int flags) override {
    return 0;
  }

  int sendto(int socket, const void* buff, size_t length, int flags,
             TRANSPORT_CONST_SOCKADDR_ARG address,
             hicn_socklen_t addr_len) override {
    return 0;
  }

  int recvfrom(int socket, void* buff, size_t length, int flags,
               TRANSPORT_SOCKADDR_ARG address,
               hicn_socklen_t* __restrict len) override {
    return 0;
  }

  int sendmsg(int socket, const struct hicn_msghdr* message,
              int flags) override {
    return 0;
  }

  int recvmsg(int socket, struct hicn_msghdr* message, int flags) override {
    return 0;
  }

  int shutdown(int socket, int how) override { return 0; }

  int close(int socket, int how) override { return 0; }

  int getsockopt(int socket, int level, int optname, void* __restrict optval,
                 hicn_socklen_t* __restrict optlen) override {
    return 0;
  }

  int setsockopt(int socket, int level, int optname, const void* optval,
                 hicn_socklen_t optlen) override {
    return 0;
  }
};

template <typename T>
class SocketManager {
 public:
  template <typename S, typename... Args>
  int makeSocket(Args&&... args) {
    int index = IntegerPool::getInstance()->get();
    if (index > 0) {
      utils::SpinLock::Acquire locked(lock_);
      auto ret = sockets_.emplace(
          std::move(index), std::make_unique<S>(std::forward<Args>(args)...));
      // Check if the insertion happened
      if (ret.second == false) {
        return -1;
      }
    }

    return index;
  }

  T* get(int fd) {
    {
      utils::SpinLock::Acquire locked(lock_);
      auto it = sockets_.find(fd);
      if (it != sockets_.end()) {
        return it->second.get();
      }
    }

    return nullptr;
  }

 protected:
  utils::SpinLock lock_;
  std::unordered_map<int, std::unique_ptr<T> > sockets_;
};

}  // namespace details

details::SocketManager<details::Adapter> sock_adapters;

}  // namespace interface
}  // namespace transport

extern "C" {

const char* C_API_ERROR_STRING[] = {
#define _(a, b, c) c,
    foreach_c_api_error
#undef _
};

#define CHECK_SOCKET_EXIST(socket)                             \
  auto sock = transport::interface::sock_adapters.get(socket); \
  if (!sock) {                                                 \
    return C_API_ERROR_SOCKET_NOT_FOUND;                       \
  }

int hicn_socket(int domain, int type, int protocol) {
  int ret = C_API_ERROR_NONE;

  if (TRANSPORT_EXPECT_FALSE(domain != AF_HICN)) {
    return C_API_ERROR_UNEXPECTED_DOMAIN;
  }

  if (TRANSPORT_EXPECT_FALSE(type != SOCK_PROD || type != SOCK_CONS)) {
    return C_API_ERROR_UNEXPECTED_SOCKET_TYPE;
  }

  bool wrong_protocol_prod = protocol < PROD_REL || protocol > PROD_UNREL;
  bool wrong_protocol_cons = protocol > CONS_CBR || protocol < CONS_REL;

  if (TRANSPORT_EXPECT_FALSE(type == SOCK_PROD && wrong_protocol_prod ||
                             type == SOCK_CONS && wrong_protocol_cons)) {
    return C_API_ERROR_UNEXPECTED_PROTOCOL;
  }

  // Create socket
  if (type == SOCK_CONS) {
    ret = transport::interface::sock_adapters
              .makeSocket<transport::interface::details::ConsumerAdapter>(
                  protocol);
  } else {
    ret = transport::interface::sock_adapters
              .makeSocket<transport::interface::details::ProducerAdapter>(
                  protocol);
  }

  return ret;
}

int hicn_bind(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
              hicn_socklen_t len) {
  return C_API_ERROR_NOT_IMPLEMENTED;
}

int hicn_listen(int socket, int n) { return C_API_ERROR_NOT_IMPLEMENTED; }

int hicn_connect(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                 hicn_socklen_t* __restrict len) {
  CHECK_SOCKET_EXIST(socket)
  return sock->connectAddress(socket, address, len);
}

int hicn_send(int socket, const void* buff, size_t length, int flags) {
  CHECK_SOCKET_EXIST(socket)
  return sock->send(socket, buff, length, flags);
}

// int hicn_send(int socket, const void* buff, size_t length, int flags) {
//   CHECK_SOCKET_EXIST(socket)
//   return sock->send(socket, buff, length, flags);
// }

int hicn_recv(int socket, void* buff, size_t length, int flags) {
  CHECK_SOCKET_EXIST(socket)
  return sock->recv(socket, buff, length, flags);
}

int hicn_sendto(int socket, const void* buff, size_t length, int flags,
                TRANSPORT_CONST_SOCKADDR_ARG address, hicn_socklen_t addr_len) {
  CHECK_SOCKET_EXIST(socket)
  return sock->sendto(socket, buff, length, flags, address, addr_len);
}

int hicn_recvfrom(int socket, void* buff, size_t length, int flags,
                  TRANSPORT_SOCKADDR_ARG address,
                  hicn_socklen_t* __restrict len) {
  CHECK_SOCKET_EXIST(socket)
  return sock->recvfrom(socket, buff, length, flags, address, len);
}

int hicn_sendmsg(int socket, const struct hicn_msghdr* message, int flags) {
  CHECK_SOCKET_EXIST(socket)
  return sock->sendmsg(socket, message, flags);
}

int hicn_recvmsg(int socket, struct hicn_msghdr* message, int flags) {
  CHECK_SOCKET_EXIST(socket)
  return sock->recvmsg(socket, message, flags);
}

int hicn_shutdown(int socket, int how) {
  CHECK_SOCKET_EXIST(socket)
  return sock->shutdown(socket, how);
}

int hicn_close(int socket, int how) {
  CHECK_SOCKET_EXIST(socket)
  return sock->close(socket, how);
}

int hicn_getsockopt(int socket, int level, int optname, void* __restrict optval,
                    hicn_socklen_t* __restrict optlen) {
  CHECK_SOCKET_EXIST(socket)
  return sock->getsockopt(socket, level, optname, optval, optlen);
}

int hicn_setsockopt(int socket, int level, int optname, const void* optval,
                    hicn_socklen_t optlen) {
  CHECK_SOCKET_EXIST(socket)
  return sock->setsockopt(socket, level, optname, optval, optlen);
}
}