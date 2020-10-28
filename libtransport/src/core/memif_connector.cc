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

#include <core/memif_connector.h>

#ifdef __vpp__

namespace transport {

namespace core {

MemifConnector::MemifConnector(PacketReceivedCallback &&receive_callback,
                               OnReconnect &&on_reconnect_callback,
                               asio::io_service &io_service,
                               std::string app_name)

}

MemifConnector::~MemifConnector()

    void MemifConnector::init()

        void MemifConnector::connect(uint32_t memif_id, long memif_mode)

            int MemifConnector::createMemif(uint32_t index, uint8_t mode,
                                            char *s)

                int MemifConnector::deleteMemif()

                    int MemifConnector::controlFdUpdate(int fd, uint8_t events,
                                                        void *private_ctx)

                        int MemifConnector::bufferAlloc(long n, uint16_t qid)

                            int MemifConnector::txBurst(uint16_t qid)

                                void MemifConnector::sendCallback(
                                    const std::error_code &ec)

                                    void MemifConnector::processInputBuffer(
                                        std::uint16_t total_packets)

    /* informs user about connected status. private_ctx is used by user to
       identify connection (multiple connections WIP) */
    int MemifConnector::onConnect(memif_conn_handle_t conn, void *private_ctx)

    /* informs user about disconnected status. private_ctx is used by user to
       identify connection (multiple connections WIP) */
    int MemifConnector::onDisconnect(memif_conn_handle_t conn,
                                     void *private_ctx)

        void MemifConnector::threadMain()

            int MemifConnector::onInterrupt(memif_conn_handle_t conn,
                                            void *private_ctx, uint16_t qid)

                void MemifConnector::close()

                    void MemifConnector::send(const Packet::MemBufPtr &packet)

                        int MemifConnector::doSend()

                            void MemifConnector::send(
                                const uint8_t *packet, std::size_t len,
                                const PacketSentCallback &packet_sent)

}  // namespace transport

}  // end namespace transport

#endif  // __vpp__
