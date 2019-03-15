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

#include "http_server.h"

#include <asio.hpp>
#include <fstream>
#include <istream>

namespace icn_httpserver {

HttpServer::HttpServer(unsigned short port, std::string icn_name,
                       size_t num_threads, long timeout_request,
                       long timeout_send_or_receive)
    : config_(port, num_threads),
      internal_io_service_(std::make_shared<asio::io_service>()),
      io_service_(*internal_io_service_), acceptor_(io_service_),
      icn_name_(icn_name), timeout_request_(timeout_request),
      timeout_content_(timeout_send_or_receive) {}

HttpServer::HttpServer(unsigned short port, std::string icn_name,
                       size_t num_threads, long timeout_request,
                       long timeout_send_or_receive,
                       asio::io_service &ioService)
    : config_(port, num_threads), io_service_(ioService),
      acceptor_(io_service_), icn_name_(icn_name),
      timeout_request_(timeout_request),
      timeout_content_(timeout_send_or_receive) {}

void HttpServer::onIcnRequest(
    std::shared_ptr<libl4::http::HTTPServerPublisher> &publisher,
    const uint8_t *buffer, std::size_t size, int request_id) {
  std::shared_ptr<Request> request = std::make_shared<IcnRequest>(publisher);
  request->getContent().rdbuf()->sputn((char *)buffer, size);

  if (!parse_request(request, request->getContent())) {
    return;
  }

  std::map<int, std::shared_ptr<libl4::http::HTTPServerPublisher>>
      &icn_publishers = icn_acceptor_->getPublishers();

  std::unique_lock<std::mutex> lock(thread_list_mtx_);
  if (icn_publishers.size() < config_.getNum_threads()) {
    std::cout << "Received request for: " << request->getPath() << std::endl;

    publisher->attachPublisher();
    std::cout << "Starting new thread" << std::endl;
    io_service_.dispatch([this, request, request_id]() {
      std::map<int, std::shared_ptr<libl4::http::HTTPServerPublisher>>
          &icn_publishers = icn_acceptor_->getPublishers();
      find_resource(nullptr, request);
      icn_publishers[request_id]->serveClients();
      std::unique_lock<std::mutex> lock(thread_list_mtx_);
      icn_publishers.erase(request_id);
    });
  }
}

void HttpServer::setIcnAcceptor() {
  icn_acceptor_ = std::make_shared<libl4::http::HTTPServerAcceptor>(
      icn_name_, std::bind(&HttpServer::onIcnRequest, this,
                           std::placeholders::_1, std::placeholders::_2,
                           std::placeholders::_3, std::placeholders::_4));
  icn_acceptor_->listen(true);
}

void HttpServer::spawnThreads() {
  if (io_service_.stopped()) {
    io_service_.reset();
  }

  asio::ip::tcp::endpoint endpoint;

  if (config_.getAddress().size() > 0) {
    endpoint = asio::ip::tcp::endpoint(
        asio::ip::address::from_string(config_.getAddress()),
        config_.getPort());
  } else {
    endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), config_.getPort());
  }

  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(
      asio::socket_base::reuse_address(config_.isReuse_address()));
  acceptor_.bind(endpoint);
  acceptor_.listen();

  accept();

  // If num_threads>1, start m_io_service.run() in (num_threads-1) threads for
  // thread-pooling
  socket_threads_.clear();
  for (size_t c = 1; c < config_.getNum_threads(); c++) {
    socket_threads_.emplace_back([this]() { io_service_.run(); });
  }
}

void HttpServer::start() {
  // Copy the resources to opt_resource for more efficient request processing
  opt_resource_.clear();
  for (auto &res : resource) {
    for (auto &res_method : res.second) {
      auto it = opt_resource_.end();
      for (auto opt_it = opt_resource_.begin(); opt_it != opt_resource_.end();
           opt_it++) {
        if (res_method.first == opt_it->first) {
          it = opt_it;
          break;
        }
      }
      if (it == opt_resource_.end()) {
        opt_resource_.emplace_back();
        it = opt_resource_.begin() + (opt_resource_.size() - 1);
        it->first = res_method.first;
      }
      it->second.emplace_back(std::regex(res.first), res_method.second);
    }
  }

  spawnThreads();

  setIcnAcceptor();

  // Wait for the rest of the threads, if any, to finish as well
  for (auto &t : socket_threads_) {
    t.join();
  }
  //  for (auto &t : icn_threads) {
  //    t.second.get();
  //  }
}

void HttpServer::stop() {
  acceptor_.close();

  io_service_.stop();

  std::map<int, std::shared_ptr<libl4::http::HTTPServerPublisher>>
      &icn_publishers = icn_acceptor_->getPublishers();

  for (auto &p : icn_publishers) {
    p.second->stop();
  }
}

void HttpServer::accept() {
  // Create new socket for this connection
  // Shared_ptr is used to pass temporary objects to the asynchronous functions
  std::shared_ptr<socket_type> socket =
      std::make_shared<socket_type>(io_service_);

  acceptor_.async_accept(*socket, [this, socket](const std::error_code &ec) {
    // Immediately start accepting a new connection
    accept();

    if (!ec) {
      asio::ip::tcp::no_delay option(true);
      socket->set_option(option);
      read_request_and_content(socket);
    }
  });
}

void HttpServer::send(std::shared_ptr<Response> response,
                      SendCallback callback) const {
  response->send(callback);
}

std::shared_ptr<asio::steady_timer>
HttpServer::set_timeout_on_socket(std::shared_ptr<socket_type> socket,
                                  long seconds) {
  std::shared_ptr<asio::steady_timer> timer =
      std::make_shared<asio::steady_timer>(io_service_);
  timer->expires_from_now(std::chrono::seconds(seconds));
  timer->async_wait([socket](const std::error_code &ec) {
    if (!ec) {
      std::error_code ec;
      socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
      socket->lowest_layer().close();
    }
  });
  return timer;
}

void HttpServer::read_request_and_content(std::shared_ptr<socket_type> socket) {
  // Create new streambuf (Request::streambuf) for async_read_until()
  // shared_ptr is used to pass temporary objects to the asynchronous functions
  std::shared_ptr<Request> request = std::make_shared<SocketRequest>();
  request->read_remote_endpoint_data(*socket);

  // Set timeout on the following asio::async-read or write function
  std::shared_ptr<asio::steady_timer> timer;
  if (timeout_request_ > 0) {
    timer = set_timeout_on_socket(socket, timeout_request_);
  }

  asio::async_read_until(
      *socket, request->getStreambuf(), "\r\n\r\n",
      [this, socket, request, timer](const std::error_code &ec,
                                     size_t bytes_transferred) {
        if (timeout_request_ > 0) {
          timer->cancel();
        }
        if (!ec) {
          // request->streambuf.size() is not necessarily the same as
          // bytes_transferred, from Asio-docs: "After a successful
          //async_read_until operation, the streambuf may contain additional
          //data beyond the delimiter" The chosen solution is to extract lines
          // from the stream directly when parsing the header. What is left of
          // the streambuf (maybe some bytes of the content) is appended to in
          // the async_read-function below (for retrieving content).
          size_t num_additional_bytes =
              request->getStreambuf().in_avail() - bytes_transferred;

          if (!parse_request(request, request->getContent())) {
            return;
          }

          // If content, read that as well
          auto it = request->getHeader().find("Content-Length");
          if (it != request->getHeader().end()) {
            // Set timeout on the following asio::async-read or write function
            std::shared_ptr<asio::steady_timer> timer;
            if (timeout_content_ > 0) {
              timer = set_timeout_on_socket(socket, timeout_content_);
            }
            unsigned long long content_length;
            try {
              content_length = atol(it->second.c_str());
            } catch (const std::exception &) {
              return;
            }
            if (content_length > num_additional_bytes) {
              asio::async_read(
                  *socket, request->getStreambuf(),
                  asio::transfer_exactly(content_length - num_additional_bytes),
                  [this, socket, request, timer](const std::error_code &ec,
                                                 size_t /*bytes_transferred*/) {
                    if (timeout_content_ > 0) {
                      timer->cancel();
                    }
                    if (!ec) {
                      find_resource(socket, request);
                    }
                  });
            } else {

              if (timeout_content_ > 0) {
                timer->cancel();
              }

              find_resource(socket, request);
            }
          } else {
            find_resource(socket, request);
          }
        }
      });
}

bool HttpServer::parse_request(std::shared_ptr<Request> request,
                               std::istream &stream) const {
  std::string line;
  getline(stream, line);
  size_t method_end;
  if ((method_end = line.find(' ')) != std::string::npos) {
    size_t path_end;
    if ((path_end = line.find(' ', method_end + 1)) != std::string::npos) {
      request->setMethod(line.substr(0, method_end));
      request->setPath(line.substr(method_end + 1, path_end - method_end - 1));

      size_t protocol_end;
      if ((protocol_end = line.find('/', path_end + 1)) != std::string::npos) {
        if (line.substr(path_end + 1, protocol_end - path_end - 1) != "HTTP") {
          return false;
        }
        request->setHttp_version(
            line.substr(protocol_end + 1, line.size() - protocol_end - 2));
      } else {
        return false;
      }

      getline(stream, line);
      size_t param_end;
      while ((param_end = line.find(':')) != std::string::npos) {
        size_t value_start = param_end + 1;
        if ((value_start) < line.size()) {
          if (line[value_start] == ' ') {
            value_start++;
          }
          if (value_start < line.size()) {
            request->getHeader().insert(std::make_pair(
                line.substr(0, param_end),
                line.substr(value_start, line.size() - value_start - 1)));
          }
        }

        getline(stream, line);
      }
    } else {
      return false;
    }
  } else {
    return false;
  }
  return true;
}

void HttpServer::find_resource(std::shared_ptr<socket_type> socket,
                               std::shared_ptr<Request> request) {
  // Find path- and method-match, and call write_response
  for (auto &res : opt_resource_) {
    if (request->getMethod() == res.first) {
      for (auto &res_path : res.second) {
        std::smatch sm_res;
        if (std::regex_match(request->getPath(), sm_res, res_path.first)) {
          request->setPath_match(std::move(sm_res));
          write_response(socket, request, res_path.second);
          return;
        }
      }
    }
  }
  auto it_method = default_resource.find(request->getMethod());
  if (it_method != default_resource.end()) {
    write_response(socket, request, it_method->second);
    return;
  }

  std::cout << "resource not found" << std::endl;
}

void HttpServer::write_response(std::shared_ptr<socket_type> socket,
                                std::shared_ptr<Request> request,
                                ResourceCallback &resource_function) {
  // Set timeout on the following asio::async-read or write function
  std::shared_ptr<asio::steady_timer> timer;
  if (timeout_content_ > 0 && socket) {
    timer = set_timeout_on_socket(socket, timeout_content_);
  }

  Response *resp;

  if (socket) {
    resp = new SocketResponse(socket);
  } else {
    resp = new IcnResponse(
        std::static_pointer_cast<IcnRequest>(request)->getHttpPublisher(),
        std::static_pointer_cast<IcnRequest>(request)->getName(),
        std::static_pointer_cast<IcnRequest>(request)->getPath());
  }

  auto response = std::shared_ptr<Response>(resp, [this, request, timer,
                                                   socket](
                                                      Response *response_ptr) {
    auto response = std::shared_ptr<Response>(response_ptr);
    response->setIsLast(true);

    send(response, [this, response, request, timer,
                    socket](const std::error_code &ec) {
      if (!ec) {
        if (socket && timeout_content_ > 0) {
          timer->cancel();
        }

        float http_version;
        try {
          http_version = atof(request->getHttp_version().c_str());
        } catch (const std::exception &) {
          return;
        }

        auto range = request->getHeader().equal_range("Connection");
        for (auto it = range.first; it != range.second; it++) {
          if (caseInsCompare(it->second, "close")) {
            return;
          }
        }
        if (http_version > 1.05 && socket) {
          read_request_and_content(
              std::static_pointer_cast<SocketResponse>(response)->getSocket());
        }
      }
    });
  });

  try {
    resource_function(response, request);
  } catch (const std::exception &) {
    return;
  }
}

} // end namespace icn_httpserver
