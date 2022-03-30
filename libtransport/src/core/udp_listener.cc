/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <core/udp_connector.h>
#include <core/udp_listener.h>
#include <glog/logging.h>
#include <hicn/transport/utils/hash.h>

#ifndef LINUX
namespace std {
size_t hash<asio::ip::udp::endpoint>::operator()(
    const asio::ip::udp::endpoint &endpoint) const {
  auto hash_ip = endpoint.address().is_v4()
                     ? endpoint.address().to_v4().to_ulong()
                     : utils::hash::fnv32_buf(
                           endpoint.address().to_v6().to_bytes().data(), 16);
  uint16_t port = endpoint.port();
  return utils::hash::fnv32_buf(&port, 2, hash_ip);
}
}  // namespace std
#endif

namespace transport {
namespace core {

UdpTunnelListener::~UdpTunnelListener() {}

void UdpTunnelListener::close() {
  strand_->post([this]() {
    if (socket_->is_open()) {
      socket_->close();
    }
  });
}

#ifdef LINUX
void UdpTunnelListener::readHandler(const std::error_code &ec) {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "UdpTunnelConnector receive packet";

  if (TRANSPORT_EXPECT_TRUE(!ec)) {
    if (current_position_ == 0) {
      for (int i = 0; i < Connector::max_burst; i++) {
        auto read_buffer = Connector::getRawBuffer();
        iovecs_[i][0].iov_base = read_buffer.first;
        iovecs_[i][0].iov_len = read_buffer.second;
        msgs_[i].msg_hdr.msg_iov = iovecs_[i];
        msgs_[i].msg_hdr.msg_iovlen = 1;
        msgs_[i].msg_hdr.msg_name = &remote_endpoints_[i];
        msgs_[i].msg_hdr.msg_namelen = sizeof(remote_endpoints_[i]);
      }
    }

    int res = recvmmsg(socket_->native_handle(), msgs_ + current_position_,
                       Connector::max_burst - current_position_, MSG_DONTWAIT,
                       nullptr);
    if (res < 0) {
      LOG(ERROR) << "Error in  recvmmsg.";
      return;
    }

    for (int i = 0; i < res; i++) {
      auto packet = Connector::getPacketFromBuffer(
          reinterpret_cast<uint8_t *>(
              msgs_[current_position_].msg_hdr.msg_iov[0].iov_base),
          msgs_[current_position_].msg_len);
      auto connector_id =
          utils::hash::fnv64_buf(msgs_[current_position_].msg_hdr.msg_name,
                                 msgs_[current_position_].msg_hdr.msg_namelen);

      auto connector = connectors_.find(connector_id);
      if (connector == connectors_.end()) {
        // Create new connector corresponding to new client

        /*
         * Get the remote endpoint for this particular message
         */
        using namespace asio::ip;
        if (local_endpoint_.address().is_v4()) {
          auto addr = reinterpret_cast<struct sockaddr_in *>(
              &remote_endpoints_[current_position_]);
          address_v4::bytes_type address_bytes;
          std::copy_n(reinterpret_cast<uint8_t *>(&addr->sin_addr),
                      address_bytes.size(), address_bytes.begin());
          address_v4 address(address_bytes);
          remote_endpoint_ = udp::endpoint(address, ntohs(addr->sin_port));
        } else {
          auto addr = reinterpret_cast<struct sockaddr_in6 *>(
              &remote_endpoints_[current_position_]);
          address_v6::bytes_type address_bytes;
          std::copy_n(reinterpret_cast<uint8_t *>(&addr->sin6_addr),
                      address_bytes.size(), address_bytes.begin());
          address_v6 address(address_bytes);
          remote_endpoint_ = udp::endpoint(address, ntohs(addr->sin6_port));
        }

        /**
         * Create new connector sharing the same socket of this listener.
         */
        auto ret = connectors_.emplace(
            connector_id,
            std::make_shared<UdpTunnelConnector>(
                socket_, strand_, receive_callback_,
                [](Connector *, const std::error_code &) {}, [](Connector *) {},
                [](Connector *, const std::error_code &) {},
                std::move(remote_endpoint_)));
        connector = ret.first;
        connector->second->setConnectorId(connector_id);
      }

      /**
       * Use connector callback to process incoming message.
       */
      UdpTunnelConnector *c =
          dynamic_cast<UdpTunnelConnector *>(connector->second.get());
      c->doRecvPacket(packet);

      ++current_position_;
    }

    doRecvPacket();
  } else if (ec.value() == static_cast<int>(std::errc::operation_canceled)) {
    LOG(ERROR) << "The connection has been closed by the application.";
    return;
  } else {
    LOG(ERROR) << ec.value() << " " << ec.message();
  }
}
#endif

void UdpTunnelListener::doRecvPacket() {
#ifdef LINUX
#if ((ASIO_VERSION / 100 % 1000) < 11)
  socket_->async_receive(
      asio::null_buffers(),
#else
  socket_->async_wait(
      asio::ip::tcp::socket::wait_read,
#endif
      std::bind(&UdpTunnelListener::readHandler, this, std::placeholders::_1));
#else
  read_msg_ = Connector::getRawBuffer();
  socket_->async_receive_from(
      asio::buffer(read_msg_.first, read_msg_.second), remote_endpoint_,
      [this](const std::error_code &ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          auto packet = Connector::getPacketFromBuffer(read_msg_.first, length);
          auto connector_id =
              std::hash<asio::ip::udp::endpoint>{}(remote_endpoint_);
          auto connector = connectors_.find(connector_id);
          if (connector == connectors_.end()) {
            // Create new connector corresponding to new client
            auto ret = connectors_.emplace(
                connector_id, std::make_shared<UdpTunnelConnector>(
                                  socket_, strand_, receive_callback_,
                                  [](Connector *, const std::error_code &) {},
                                  [](Connector *) {},
                                  [](Connector *, const std::error_code &) {},
                                  std::move(remote_endpoint_)));
            connector = ret.first;
            connector->second->setConnectorId(connector_id);
          }

          UdpTunnelConnector *c =
              dynamic_cast<UdpTunnelConnector *>(connector->second.get());
          c->doRecvPacket(packet);
          doRecvPacket();
        } else if (ec.value() ==
                   static_cast<int>(std::errc::operation_canceled)) {
          LOG(ERROR) << "The connection has been closed by the application.";
          return;
        } else {
          LOG(ERROR) << ec.value() << " " << ec.message();
        }
      });
#endif
}
}  // namespace core
}  // namespace transport