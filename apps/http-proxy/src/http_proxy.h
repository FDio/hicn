/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#pragma once

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/utils/event_thread.h>

#include "http_session.h"
#include "icn_receiver.h"

#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/version.hpp>
#include <unordered_set>

class TcpListener {
 public:
  using AcceptCallback = std::function<void(asio::ip::tcp::socket&&)>;

  TcpListener(asio::io_service& io_service, short port, AcceptCallback callback)
      : acceptor_(io_service,
                  asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
#if ((ASIO_VERSION / 100 % 1000) < 12)
        socket_(io_service),
#endif
        callback_(callback) {
    do_accept();
  }

 private:
  void do_accept() {
#if ((ASIO_VERSION / 100 % 1000) >= 12)
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
#else
    acceptor_.async_accept(socket_, [this](std::error_code ec) {
      auto socket = std::move(socket_);
#endif
          if (!ec) {
            callback_(std::move(socket));
          }

          do_accept();
        });
  }

  asio::ip::tcp::acceptor acceptor_;
#if ((ASIO_VERSION / 100 % 1000) < 12)
  asio::ip::tcp::socket socket_;
#endif
  AcceptCallback callback_;
};

namespace transport {

class HTTPClientConnectionCallback;

class Receiver {
 public:
  Receiver() : thread_() {}

 protected:
  utils::EventThread thread_;
};

class TcpReceiver : public Receiver {
  friend class HTTPClientConnectionCallback;

 public:
  TcpReceiver(std::uint16_t port, const std::string& prefix,
              const std::string& ipv6_first_word);

 private:
  void onNewConnection(asio::ip::tcp::socket&& socket);
  void onClientDisconnect(HTTPClientConnectionCallback* client);

  TcpListener listener_;
  std::string prefix_;
  std::string ipv6_first_word_;
  std::deque<HTTPClientConnectionCallback*> http_clients_;
  std::unordered_set<HTTPClientConnectionCallback*> used_http_clients_;
};

class IcnReceiver : public Receiver {
 public:
  template <typename... Args>
  IcnReceiver(Args&&... args)
      : Receiver(),
        icn_consum_producer_(thread_.getIoService(),
                             std::forward<Args>(args)...) {
    icn_consum_producer_.run();
  }

 private:
  AsyncConsumerProducer icn_consum_producer_;
};

class HTTPProxy {
 public:
  enum Server { CREATE };
  enum Client { WRAP_BUFFER };

  struct CommonParams {
    std::string prefix;
    std::string first_ipv6_word;

    virtual void printParams() { std::cout << "Parameters: " << std::endl; };
  };

  struct ClientParams : virtual CommonParams {
    short tcp_listen_port;
    void printParams() override {
      std::cout << "Running HTTP/TCP -> HTTP/hICN proxy." << std::endl;
      CommonParams::printParams();
      std::cout << "\t"
                << "HTTP listen port: " << tcp_listen_port << std::endl;
      std::cout << "\t"
                << "Consumer Prefix: " << prefix << std::endl;
      std::cout << "\t"
                << "Prefix first word: " << first_ipv6_word << std::endl;
    }
  };

  struct ServerParams : virtual CommonParams {
    std::string origin_address;
    std::string origin_port;
    std::string cache_size;
    std::string mtu;
    std::string content_lifetime;
    bool manifest;

    void printParams() override {
      std::cout << "Running HTTP/hICN -> HTTP/TCP proxy." << std::endl;
      CommonParams::printParams();
      std::cout << "\t"
                << "Origin address: " << origin_address << std::endl;
      std::cout << "\t"
                << "Origin port: " << origin_port << std::endl;
      std::cout << "\t"
                << "Producer cache size: " << cache_size << std::endl;
      std::cout << "\t"
                << "hICN MTU: " << mtu << std::endl;
      std::cout << "\t"
                << "Default content lifetime: " << content_lifetime
                << std::endl;
      std::cout << "\t"
                << "Producer Prefix: " << prefix << std::endl;
      std::cout << "\t"
                << "Prefix first word: " << first_ipv6_word << std::endl;
      std::cout << "\t"
                << "Use manifest: " << manifest << std::endl;
    }
  };

  HTTPProxy(ClientParams& icn_params, std::size_t n_thread = 1);
  HTTPProxy(ServerParams& icn_params, std::size_t n_thread = 1);

  void run() { sleep(1000000); }

 private:
  void acceptTCPClient(asio::ip::tcp::socket&& socket);

 private:
  std::vector<std::unique_ptr<Receiver>> receivers_;
};

}  // namespace transport