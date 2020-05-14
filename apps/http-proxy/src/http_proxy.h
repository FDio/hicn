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
#include <unordered_set>

class TcpListener {
 public:
  using AcceptCallback = std::function<void(asio::ip::tcp::socket&&)>;

  TcpListener(asio::io_service& io_service, short port, AcceptCallback callback)
      : acceptor_(io_service,
                  asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
        callback_(callback) {
    do_accept();
  }

 private:
  void do_accept() {
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
          if (!ec) {
            callback_(std::move(socket));
          }

          do_accept();
        });
  }

  asio::ip::tcp::acceptor acceptor_;
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
 public:
  TcpReceiver(std::uint16_t port, const std::string& prefix,
              const std::string& ipv6_first_word);

  void onNewConnection(asio::ip::tcp::socket&& socket);
  void onClientDisconnect(HTTPClientConnectionCallback* client);

 private:
  TcpListener listener_;
  std::string prefix_;
  std::string ipv6_first_word_;
  std::deque<HTTPClientConnectionCallback*> http_clients_;
  std::unordered_set<HTTPClientConnectionCallback*> used_http_clients_;
};

class IcnReceiver : public Receiver {
 public:
  IcnReceiver(AsyncConsumerProducer::Params& icn_params)
      : Receiver(), icn_consum_producer_(icn_params, thread_.getIoService()) {}

 private:
  AsyncConsumerProducer icn_consum_producer_;
};

class HTTPProxy {
 public:
  HTTPProxy(AsyncConsumerProducer::Params& icn_params, short tcp_port,
            std::size_t n_thread = 1);

  void run() { sleep(1000000); }

 private:
  void acceptTCPClient(asio::ip::tcp::socket&& socket);

 private:
  std::vector<std::unique_ptr<IcnReceiver>> icn_receivers_;
  std::vector<std::unique_ptr<TcpReceiver>> tcp_receivers_;
};

}  // namespace transport