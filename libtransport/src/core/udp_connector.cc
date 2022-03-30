/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <core/errors.h>
#include <core/udp_connector.h>
#include <glog/logging.h>
#include <hicn/transport/utils/branch_prediction.h>

#include <iostream>
#include <thread>
#include <vector>

namespace transport {
namespace core {

UdpTunnelConnector::~UdpTunnelConnector() {}

void UdpTunnelConnector::connect(const std::string &hostname, uint16_t port,
                                 const std::string &bind_address,
                                 uint16_t bind_port) {
  if (state_ == State::CLOSED) {
    state_ = State::CONNECTING;

    asio::ip::udp::resolver::query query(asio::ip::udp::v4(), hostname,
                                         std::to_string(port));

    endpoint_iterator_ = resolver_.resolve(query);
    remote_endpoint_send_ = *endpoint_iterator_;
    socket_->open(remote_endpoint_send_.protocol());

    if (!bind_address.empty() && bind_port != 0) {
      using namespace asio::ip;

      auto address = address::from_string(bind_address);
      if (address.is_v6()) {
        std::error_code ec;
        socket_->set_option(asio::ip::v6_only(false), ec);
        // Call succeeds only on dual stack systems.
      }

      socket_->bind(udp::endpoint(address, bind_port));
    }

    remote_endpoint_ = Endpoint(remote_endpoint_send_);
    local_endpoint_ = Endpoint(socket_->local_endpoint());

    auto self = shared_from_this();
    doConnect(self);
  }
}

void UdpTunnelConnector::send(Packet &packet) {
  send(packet.shared_from_this());
}

void UdpTunnelConnector::send(const utils::MemBuf::Ptr &buffer) {
  auto self = shared_from_this();
  io_service_.post([self, pkt{buffer}]() {
    bool write_in_progress = !self->output_buffer_.empty();
    self->output_buffer_.push_back(std::move(pkt));
    if (TRANSPORT_EXPECT_TRUE(self->state_ == State::CONNECTED)) {
      if (!write_in_progress) {
        self->doSendPacket(self);
      }
    } else {
      self->data_available_ = true;
    }
  });
}

void UdpTunnelConnector::close() {
  DLOG_IF(INFO, VLOG_IS_ON(2)) << "UDPTunnelConnector::close";
  state_ = State::CLOSED;
  bool is_socket_owned = socket_.use_count() == 1;
  if (is_socket_owned) {
    // Here we use a shared ptr to keep the object alive until we call the close
    // function
    auto self = shared_from_this();
    io_service_.dispatch([this, self]() {
      socket_->close();
      // on_close_callback_(shared_from_this());
    });
  }
}

void UdpTunnelConnector::doSendPacket(
    const std::shared_ptr<UdpTunnelConnector> &self) {
#ifdef LINUX
  send_timer_.expires_from_now(std::chrono::microseconds(50));
  send_timer_.async_wait([self](const std::error_code &ec) {
    if (ec) {
      return;
    }

    self->writeHandler();
  });
#else
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const ::utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  socket_->async_send_to(
      std::move(array), remote_endpoint_send_,
      [this, self](const std::error_code &ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          sent_callback_(this, make_error_code(core_error::success));
        } else if (ec.value() ==
                   static_cast<int>(std::errc::operation_canceled)) {
          // The connection has been closed by the application.
          return;
        } else {
          sendFailed();
          sent_callback_(this, ec);
        }

        output_buffer_.pop_front();
        if (!output_buffer_.empty()) {
          doSendPacket(self);
        }
      });
#endif
}

void UdpTunnelConnector::retryConnection() {
  // The connection was refused. In this case let's retry to reconnect.
  connection_reattempts_++;
  LOG(ERROR) << "Error in UDP: Connection refused. Retrying...";
  state_ = State::CONNECTING;
  timer_.expires_from_now(std::chrono::milliseconds(500));
  std::weak_ptr<UdpTunnelConnector> self = shared_from_this();
  timer_.async_wait([self, this](const std::error_code &ec) {
    if (ec) {
    }
    if (auto ptr = self.lock()) {
      doConnect(ptr);
    }
  });
  return;
}

#ifdef LINUX
void UdpTunnelConnector::writeHandler() {
  if (TRANSPORT_EXPECT_FALSE(state_ != State::CONNECTED)) {
    return;
  }

  auto len = std::min(output_buffer_.size(), std::size_t(Connector::max_burst));

  if (len) {
    int m = 0;
    for (auto &p : output_buffer_) {
      auto packet = p.get();
      ::utils::MemBuf *current = packet;
      int b = 0;
      do {
        // array.push_back(asio::const_buffer(current->data(),
        // current->length()));
        tx_iovecs_[m][b].iov_base = current->writableData();
        tx_iovecs_[m][b].iov_len = current->length();
        current = current->next();
        b++;
      } while (current != packet);

      tx_msgs_[m].msg_hdr.msg_iov = tx_iovecs_[m];
      tx_msgs_[m].msg_hdr.msg_iovlen = b;
      tx_msgs_[m].msg_hdr.msg_name = remote_endpoint_send_.data();
      tx_msgs_[m].msg_hdr.msg_namelen = remote_endpoint_send_.size();
      m++;

      if (--len == 0) {
        break;
      }
    }

    int retval = sendmmsg(socket_->native_handle(), tx_msgs_, m, MSG_DONTWAIT);
    if (retval > 0) {
      while (retval--) {
        output_buffer_.pop_front();
      }
    } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
      LOG(ERROR) << "Error sending messages: " << strerror(errno);
      sent_callback_(this, make_error_code(core_error::send_failed));
      return;
    }
  }

  if (!output_buffer_.empty()) {
    send_timer_.expires_from_now(std::chrono::microseconds(50));
    std::weak_ptr<UdpTunnelConnector> self = shared_from_this();
    send_timer_.async_wait([self](const std::error_code &ec) {
      if (ec) {
        return;
      }
      if (auto ptr = self.lock()) {
        ptr->writeHandler();
      }
    });
  }
}

void UdpTunnelConnector::readHandler(const std::error_code &ec) {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "UdpTunnelConnector receive packet";

  if (TRANSPORT_EXPECT_TRUE(!ec)) {
    if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
      if (current_position_ == 0) {
        for (int i = 0; i < max_burst; i++) {
          auto read_buffer = getRawBuffer();
          rx_iovecs_[i][0].iov_base = read_buffer.first;
          rx_iovecs_[i][0].iov_len = read_buffer.second;
          rx_msgs_[i].msg_hdr.msg_iov = rx_iovecs_[i];
          rx_msgs_[i].msg_hdr.msg_iovlen = 1;
        }
      }

      int res = recvmmsg(socket_->native_handle(), rx_msgs_ + current_position_,
                         max_burst - current_position_, MSG_DONTWAIT, nullptr);
      if (res < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          // Try again later
          return;
        }

        if (errno == ECONNREFUSED &&
            connection_reattempts_ < max_reconnection_reattempts) {
          retryConnection();
          return;
        }

        LOG(ERROR) << "Error receiving messages! " << strerror(errno) << " "
                   << res;
        std::vector<utils::MemBuf::Ptr> v;
        auto ec = make_error_code(core_error::receive_failed);

        receive_callback_(this, v, ec);
        return;
      }

      std::vector<utils::MemBuf::Ptr> v;
      v.reserve(res);
      for (int i = 0; i < res; i++) {
        auto packet = getPacketFromBuffer(
            reinterpret_cast<uint8_t *>(
                rx_msgs_[current_position_].msg_hdr.msg_iov[0].iov_base),
            rx_msgs_[current_position_].msg_len);
        receiveSuccess(*packet);
        v.push_back(std::move(packet));
        ++current_position_;
      }

      receive_callback_(this, v, make_error_code(core_error::success));

      doRecvPacket();
    } else {
      LOG(ERROR) << "Error in UDP: Receiving packets from a not "
                    "connected socket.";
    }
  } else if (ec.value() == static_cast<int>(std::errc::operation_canceled)) {
    LOG(ERROR) << "The connection has been closed by the application.";
    return;
  } else {
    if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
      // receive_callback_(this, *read_msg_, ec);
      LOG(ERROR) << "Error in UDP connector: " << ec.value() << " "
                 << ec.message();
    } else {
      LOG(ERROR) << "Error in connector while not connected. " << ec.value()
                 << " " << ec.message();
    }
  }
}
#endif

void UdpTunnelConnector::doRecvPacket() {
  std::weak_ptr<UdpTunnelConnector> self = shared_from_this();
#ifdef LINUX
  if (state_ == State::CONNECTED) {
#if ((ASIO_VERSION / 100 % 1000) < 11)
    socket_->async_receive(asio::null_buffers(),
#else
    socket_->async_wait(asio::ip::tcp::socket::wait_read,
#endif
                           [self](const std::error_code &ec) {
                             if (ec) {
                               LOG(ERROR)
                                   << "Error in UDP connector: " << ec.value()
                                   << " " << ec.message();
                               return;
                             }
                             if (auto ptr = self.lock()) {
                               ptr->readHandler(ec);
                             }
                           });
  }
#else
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "UdpTunnelConnector receive packet";
  read_msg_ = getRawBuffer();
  socket_->async_receive_from(
      asio::buffer(read_msg_.first, read_msg_.second), remote_endpoint_recv_,
      [this, self](const std::error_code &ec, std::size_t length) {
        if (auto ptr = self.lock()) {
          DLOG_IF(INFO, VLOG_IS_ON(3))
              << "UdpTunnelConnector received packet length=" << length;
          if (TRANSPORT_EXPECT_TRUE(!ec)) {
            if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
              auto packet = getPacketFromBuffer(read_msg_.first, length);
              receiveSuccess(*packet);
              std::vector<utils::MemBuf::Ptr> v{std::move(packet)};
              receive_callback_(this, v, make_error_code(core_error::success));
              doRecvPacket();
            } else {
              LOG(ERROR) << "Error in UDP: Receiving packets from a not "
                            "connected socket.";
            }
          } else if (ec.value() ==
                     static_cast<int>(std::errc::operation_canceled)) {
            LOG(ERROR) << "The connection has been closed by the application.";
            return;
          } else if (ec.value() ==
                     static_cast<int>(std::errc::connection_refused)) {
            if (connection_reattempts_ < max_reconnection_reattempts) {
              retryConnection();
            }
          } else {
            if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
              LOG(ERROR) << "Error in UDP connector: " << ec.value()
                         << ec.message();
            } else {
              LOG(ERROR) << "Error while not connected";
            }
          }
        }
      });
#endif
}

void UdpTunnelConnector::doConnect(
    std::shared_ptr<UdpTunnelConnector> &self_shared) {
  std::weak_ptr<UdpTunnelConnector> self = self_shared;
  asio::async_connect(*socket_, endpoint_iterator_,
                      [this, self](const std::error_code &ec,
                                   asio::ip::udp::resolver::iterator) {
                        if (auto ptr = self.lock()) {
                          if (!ec) {
                            state_ = State::CONNECTED;
                            doRecvPacket();

                            if (data_available_) {
                              data_available_ = false;
                              doSendPacket(ptr);
                            }

                            on_reconnect_callback_(
                                this, make_error_code(core_error::success));
                          } else {
                            LOG(ERROR) << "UDP Connection failed!!!";
                            retryConnection();
                          }
                        }
                      });
}

}  // namespace core

}  // namespace transport
