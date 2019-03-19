/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "common.h"
#include "configuration.h"
#include "icn_request.h"
#include "icn_response.h"
#include "socket_request.h"
#include "socket_response.h"

typedef std::function<void(std::shared_ptr<icn_httpserver::Response>,
                           std::shared_ptr<icn_httpserver::Request>)>
    ResourceCallback;

#define SERVER_NAME "/webserver"
#define PACKET_SIZE 1500
#define SEND_BUFFER_SIZE 30000

#define GET "GET"
#define POST "POST"
#define PUT "PUT"
#define DELETE "DELETE"
#define PATCH "PATCH"

namespace icn_httpserver {

class HttpServer {
 public:
  explicit HttpServer(unsigned short port, std::string icn_name,
                      size_t num_threads, long timeout_request,
                      long timeout_send_or_receive);

  explicit HttpServer(unsigned short port, std::string icn_name,
                      size_t num_threads, long timeout_request,
                      long timeout_send_or_receive,
                      asio::io_service &ioService);

  void start();

  void stop();

  void accept();

  void send(std::shared_ptr<Response> response,
            SendCallback callback = nullptr) const;

  std::unordered_map<std::string,
                     std::unordered_map<std::string, ResourceCallback>>
      resource;

  std::unordered_map<std::string, ResourceCallback> default_resource;

  void onIcnRequest(
      std::shared_ptr<libl4::http::HTTPServerPublisher> &publisher,
      const uint8_t *buffer, std::size_t size, int request_id);

 private:
  void spawnThreads();

  void setIcnAcceptor();

  std::shared_ptr<asio::steady_timer> set_timeout_on_socket(
      std::shared_ptr<socket_type> socket, long seconds);

  void read_request_and_content(std::shared_ptr<socket_type> socket);

  bool parse_request(std::shared_ptr<Request> request,
                     std::istream &stream) const;

  void find_resource(std::shared_ptr<socket_type> socket,
                     std::shared_ptr<Request> request);

  void write_response(std::shared_ptr<socket_type> socket,
                      std::shared_ptr<Request> request,
                      ResourceCallback &resource_function);

  Configuration config_;

  std::vector<std::pair<std::string,
                        std::vector<std::pair<std::regex, ResourceCallback>>>>
      opt_resource_;

  std::shared_ptr<asio::io_service> internal_io_service_;
  asio::io_service &io_service_;
  asio::ip::tcp::acceptor acceptor_;
  std::vector<std::thread> socket_threads_;
  std::string icn_name_;
  std::shared_ptr<libl4::http::HTTPServerAcceptor> icn_acceptor_;
  std::mutex thread_list_mtx_;

  long timeout_request_;
  long timeout_content_;
};

}  // end namespace icn_httpserver
