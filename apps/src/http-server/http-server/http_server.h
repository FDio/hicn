/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Ole Christian Eidheim
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

  void
  onIcnRequest(std::shared_ptr<libl4::http::HTTPServerPublisher> &publisher,
               const uint8_t *buffer, std::size_t size, int request_id);

private:
  void spawnThreads();

  void setIcnAcceptor();

  std::shared_ptr<asio::steady_timer>
  set_timeout_on_socket(std::shared_ptr<socket_type> socket, long seconds);

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

} // end namespace icn_httpserver
