/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#pragma once

#include <hicn/transport/core/connector.h>
#include <hicn/transport/portability/platform.h>
#include <io_modules/forwarder/errors.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <iostream>
#include <memory>

namespace transport {
namespace core {

class UdpTunnelListener;

class UdpTunnelConnector : public Connector {
  friend class UdpTunnelListener;

 public:
  template <typename ReceiveCallback, typename SentCallback, typename OnClose,
            typename OnReconnect>
  UdpTunnelConnector(asio::io_service &io_service,
                     ReceiveCallback &&receive_callback,
                     SentCallback &&packet_sent, OnClose &&on_close_callback,
                     OnReconnect &&on_reconnect)
      : Connector(receive_callback, packet_sent, on_close_callback,
                  on_reconnect),
        io_service_(io_service),
        strand_(std::make_shared<asio::io_service::strand>(io_service_)),
        socket_(std::make_shared<asio::ip::udp::socket>(io_service_)),
        resolver_(io_service_),
        timer_(io_service_),
#ifdef LINUX
        send_timer_(io_service_),
        tx_iovecs_{0},
        tx_msgs_{0},
        rx_iovecs_{0},
        rx_msgs_{0},
        current_position_(0),
#else
        read_msg_(nullptr, 0),
#endif
        data_available_(false) {
  }

  template <typename ReceiveCallback, typename SentCallback, typename OnClose,
            typename OnReconnect, typename EndpointType>
  UdpTunnelConnector(std::shared_ptr<asio::ip::udp::socket> &socket,
                     std::shared_ptr<asio::io_service::strand> &strand,
                     ReceiveCallback &&receive_callback,
                     SentCallback &&packet_sent, OnClose &&on_close_callback,
                     OnReconnect &&on_reconnect, EndpointType &&remote_endpoint)
      : Connector(receive_callback, packet_sent, on_close_callback,
                  on_reconnect),
#if ((ASIO_VERSION / 100 % 1000) < 12)
        io_service_(socket->get_io_service()),
#else
        io_service_((asio::io_context &)(socket->get_executor().context())),
#endif
        strand_(strand),
        socket_(socket),
        resolver_(io_service_),
        remote_endpoint_send_(std::forward<EndpointType &&>(remote_endpoint)),
        timer_(io_service_),
#ifdef LINUX
        send_timer_(io_service_),
        tx_iovecs_{0},
        tx_msgs_{0},
        rx_iovecs_{0},
        rx_msgs_{0},
        current_position_(0),
#else
        read_msg_(nullptr, 0),
#endif
        data_available_(false) {
    if (socket_->is_open()) {
      state_ = State::CONNECTED;
      remote_endpoint_ = Endpoint(remote_endpoint_send_);
      local_endpoint_ = socket_->local_endpoint();
    }
  }

  ~UdpTunnelConnector() override;

  void send(Packet &packet) override;

  void send(const uint8_t *packet, std::size_t len) override;

  void close() override;

  void connect(const std::string &hostname, std::uint16_t port,
               const std::string &bind_address = "",
               std::uint16_t bind_port = 0);

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  void doConnect();
  void doRecvPacket();

  void doRecvPacket(utils::MemBuf &buffer) {
    receive_callback_(this, buffer, make_error_code(forwarder_error::success));
  }

#ifdef LINUX
  void readHandler(std::error_code ec);
  void writeHandler(std::error_code ec);
#endif

  void setConnected() { state_ = State::CONNECTED; }

  void doSendPacket();
  void doClose();

 private:
  asio::io_service &io_service_;
  std::shared_ptr<asio::io_service::strand> strand_;
  std::shared_ptr<asio::ip::udp::socket> socket_;
  asio::ip::udp::resolver resolver_;
  asio::ip::udp::resolver::iterator endpoint_iterator_;
  asio::ip::udp::endpoint remote_endpoint_send_;
  asio::ip::udp::endpoint remote_endpoint_recv_;

  asio::steady_timer timer_;

#ifdef LINUX
  asio::steady_timer send_timer_;
  struct iovec tx_iovecs_[max_burst][8];
  struct mmsghdr tx_msgs_[max_burst];
  struct iovec rx_iovecs_[max_burst][8];
  struct mmsghdr rx_msgs_[max_burst];
  std::uint8_t current_position_;
#else
  std::pair<uint8_t *, std::size_t> read_msg_;
#endif

  bool data_available_;
};

}  // namespace core

}  // namespace transport
