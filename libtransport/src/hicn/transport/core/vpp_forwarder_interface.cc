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

#include <hicn/transport/config.h>

#ifdef __vpp__

#include <hicn/transport/core/hicn_binary_api.h>
#include <hicn/transport/core/memif_binary_api.h>
#include <hicn/transport/core/vpp_forwarder_interface.h>

typedef enum { MASTER = 0, SLAVE = 1 } memif_role_t;

#define MEMIF_DEFAULT_RING_SIZE 2048
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

namespace transport {

namespace core {

vpp_binary_api_t *VPPForwarderInterface::api_ = nullptr;
vpp_plugin_binary_api_t *VPPForwarderInterface::memif_api_ = nullptr;
vpp_plugin_binary_api_t *VPPForwarderInterface::hicn_api_ = nullptr;
std::mutex VPPForwarderInterface::global_lock_;

VPPForwarderInterface::VPPForwarderInterface(MemifConnector &connector)
    : ForwarderInterface<VPPForwarderInterface, MemifConnector>(connector),
      sw_if_index_(~0),
      face_id_(~0) {}

VPPForwarderInterface::~VPPForwarderInterface() {}

/**
 * @brief Create a memif interface in the local VPP forwarder.
 */
uint32_t VPPForwarderInterface::getMemifConfiguration() {
  memif_create_params_t input_params = {0};

  memif_id_ =
      memif_binary_api_get_next_memif_id(VPPForwarderInterface::memif_api_);

  input_params.id = memif_id_;
  input_params.role = memif_role_t::MASTER;
  input_params.mode = memif_interface_mode_t::MEMIF_INTERFACE_MODE_IP;
  input_params.rx_queues = MEMIF_DEFAULT_RX_QUEUES;
  input_params.tx_queues = MEMIF_DEFAULT_TX_QUEUES;
  input_params.ring_size = MEMIF_DEFAULT_RING_SIZE;
  input_params.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_output_params_t output_params = {0};

  if (memif_binary_api_create_memif(VPPForwarderInterface::memif_api_,
                                    &input_params, &output_params) < 0) {
    throw errors::RuntimeException(
        "Error creating memif interface in the local VPP forwarder.");
  }

  return output_params.sw_if_index;
}

void VPPForwarderInterface::consumerConnection() {
  hicn_consumer_input_params input = {0};
  hicn_consumer_output_params output;

  std::memset(&output, 0, sizeof(hicn_consumer_output_params));

  input.swif = sw_if_index_;

  if (int ret = hicn_binary_api_register_cons_app(
                    VPPForwarderInterface::hicn_api_, &input, &output) < 0) {
    throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
  }

  inet_address_.family = AF_INET;
  inet_address_.prefix_len = output.src4.prefix_length;
  std::memcpy(inet_address_.buffer, output.src4.ip4.as_u8, IPV4_ADDR_LEN);

  inet6_address_.family = AF_INET6;
  inet6_address_.prefix_len = output.src6.prefix_length;
  std::memcpy(inet6_address_.buffer, output.src6.ip6.as_u8, IPV6_ADDR_LEN);
}

void VPPForwarderInterface::producerConnection() {
  // Producer connection will be set when we set the first route.
}

void VPPForwarderInterface::connect(bool is_consumer) {
  std::lock_guard<std::mutex> connection_lock(global_lock_);

  srand(time(NULL));
  int secret = rand() % (1 << 10);
  std::stringstream app_name;
  app_name << "Libtransport_" << secret;

  if (!VPPForwarderInterface::memif_api_) {
    VPPForwarderInterface::api_ = vpp_binary_api_init(app_name.str().c_str());
  }

  VPPForwarderInterface::memif_api_ =
      memif_binary_api_init(VPPForwarderInterface::api_);

  sw_if_index_ = getMemifConfiguration();

  VPPForwarderInterface::hicn_api_ =
      hicn_binary_api_init(VPPForwarderInterface::api_);
  if (is_consumer) {
    consumerConnection();
  }

  connector_.connect(memif_id_, 0);
}

void VPPForwarderInterface::registerRoute(Prefix &prefix) {
  auto &addr = prefix.toIpAddressStruct();

  if (face_id_ == uint32_t(~0)) {
    hicn_producer_input_params input;
    std::memset(&input, 0, sizeof(input));

    hicn_producer_output_params output;
    std::memset(&output, 0, sizeof(output));

    // Here we have to ask to the actual connector what is the
    // memif_id, since this function should be called after the
    // memif creation.
    input.swif = sw_if_index_;
    input.prefix.ip6.as_u64[0] = addr.as_u64[0];
    input.prefix.ip6.as_u64[1] = addr.as_u64[1];
    input.prefix.type = addr.family == AF_INET6 ? IP_TYPE_IP6 : IP_TYPE_IP4;
    input.prefix.prefix_length = addr.prefix_len;
    input.cs_reserved = content_store_reserved_;

    if (int ret = hicn_binary_api_register_prod_app(
                      VPPForwarderInterface::hicn_api_, &input, &output) < 0) {
      throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
    }

    if (addr.family == AF_INET6) {
      inet6_address_.prefix_len = output.prod_addr.prefix_length;
      std::memcpy(inet6_address_.buffer, output.prod_addr.ip6.as_u8,
                  IPV6_ADDR_LEN);
    } else {
      inet_address_.prefix_len = output.prod_addr.prefix_length;
      // The ipv4 is written in the last 4 bytes of the ipv6 address, so we need
      // to copy from the byte 12
      std::memcpy(inet_address_.buffer, output.prod_addr.ip6.as_u8 + 12,
                  IPV4_ADDR_LEN);
    }

    face_id_ = output.face_id;
  } else {
    hicn_producer_set_route_params params;
    params.prefix.ip6.as_u64[0] = addr.as_u64[0];
    params.prefix.ip6.as_u64[1] = addr.as_u64[1];
    params.prefix.type = addr.family == AF_INET6 ? IP_TYPE_IP6 : IP_TYPE_IP4;
    params.prefix.prefix_length = addr.prefix_len;
    params.face_id = face_id_;

    if (int ret = hicn_binary_api_register_route(
                      VPPForwarderInterface::hicn_api_, &params) < 0) {
      throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
    }
  }
}

}  // namespace core

}  // namespace transport

#endif