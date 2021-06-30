/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#pragma once

#include <hicn/transport/core/connector.h>
#include <hicn/transport/portability/platform.h>

#include <hicn/transport/core/asio_wrapper.h>
#include <unordered_map>

namespace std {
template <>
struct hash<asio::ip::udp::endpoint> {
  size_t operator()(const asio::ip::udp::endpoint &endpoint) const;
};
}  // namespace std

namespace transport {
namespace core {

class UdpTunnelListener
    : public std::enable_shared_from_this<UdpTunnelListener> {
  using PacketReceivedCallback = Connector::PacketReceivedCallback;
  using EndpointId = std::pair<uint32_t, uint16_t>;

  static constexpr uint16_t default_port = 5004;

 public:
  using Ptr = std::shared_ptr<UdpTunnelListener>;

  template <typename ReceiveCallback>
  UdpTunnelListener(asio::io_service &io_service,
                    ReceiveCallback &&receive_callback,
                    asio::ip::udp::endpoint endpoint = asio::ip::udp::endpoint(
                        asio::ip::udp::v4(), default_port))
      : io_service_(io_service),
        strand_(std::make_shared<asio::io_service::strand>(io_service_)),
        socket_(std::make_shared<asio::ip::udp::socket>(io_service_,
                                                        endpoint.protocol())),
        local_endpoint_(endpoint),
        receive_callback_(std::forward<ReceiveCallback &&>(receive_callback)),
#ifndef LINUX
        read_msg_(nullptr, 0)
#else
        iovecs_{0},
        msgs_{0},
        current_position_(0)
#endif
  {
    if (endpoint.protocol() == asio::ip::udp::v6()) {
      std::error_code ec;
      socket_->set_option(asio::ip::v6_only(false), ec);
      // Call succeeds only on dual stack systems.
    }
    socket_->bind(local_endpoint_);
    io_service_.post(std::bind(&UdpTunnelListener::doRecvPacket, this));
  }

  ~UdpTunnelListener();

  void close();

  int deleteConnector(Connector *connector) {
    return connectors_.erase(connector->getConnectorId());
  }

  template <typename ReceiveCallback>
  void setReceiveCallback(ReceiveCallback &&callback) {
    receive_callback_ = std::forward<ReceiveCallback &&>(callback);
  }

  Connector *findConnector(Connector::Id connId) {
    auto it = connectors_.find(connId);
    if (it != connectors_.end()) {
      return it->second.get();
    }

    return nullptr;
  }

 private:
  void doRecvPacket();

  void readHandler(std::error_code ec);

  asio::io_service &io_service_;
  std::shared_ptr<asio::io_service::strand> strand_;
  std::shared_ptr<asio::ip::udp::socket> socket_;
  asio::ip::udp::endpoint local_endpoint_;
  asio::ip::udp::endpoint remote_endpoint_;
  std::unordered_map<Connector::Id, std::shared_ptr<Connector>> connectors_;

  PacketReceivedCallback receive_callback_;

#ifdef LINUX
  struct iovec iovecs_[Connector::max_burst][8];
  struct mmsghdr msgs_[Connector::max_burst];
  struct sockaddr_storage remote_endpoints_[Connector::max_burst];
  std::uint8_t current_position_;
#else
  std::pair<uint8_t *, std::size_t> read_msg_;
#endif
};

}  // namespace core

}  // namespace transport
