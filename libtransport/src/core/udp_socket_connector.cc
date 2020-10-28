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

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

#include <core/udp_socket_connector.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/object_pool.h>

#include <thread>
#include <vector>

namespace transport {

namespace core {

UdpSocketConnector::UdpSocketConnector(
    PacketReceivedCallback &&receive_callback,
    OnReconnect &&on_reconnect_callback, asio::io_service &io_service,
    std::string app_name)

    UdpSocketConnector::~UdpSocketConnector() {}

void UdpSocketConnector::connect(std::string ip_address, std::string port)

    void UdpSocketConnector::send(const uint8_t *packet, std::size_t len,
                                  const PacketSentCallback &packet_sent)

        void UdpSocketConnector::send(const Packet::MemBufPtr &packet)

            void UdpSocketConnector::close()

                void UdpSocketConnector::doClose()

                    void UdpSocketConnector::doWrite()

                        void UdpSocketConnector::doRead()

                            void UdpSocketConnector::tryReconnect()

                                void UdpSocketConnector::doConnect()

                                    bool UdpSocketConnector::checkConnected() {
  return state_ == ConnectorState::CONNECTED;
}

void UdpSocketConnector::startConnectionTimer()

    void UdpSocketConnector::handleDeadline(const std::error_code &ec)

}  // end namespace core

}  // end namespace transport
