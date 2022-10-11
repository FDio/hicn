/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
#define WITH_TESTS
#include <hicn/base/loop.h>
#include <hicn/config/configuration.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/listener.h>
#include <hicn/core/address_pair.h>
#include <hicn/core/address.h>
#include <hicn/core/strategy.h>
#include <hicn/strategies/local_remote.h>
}

class StrategyLocalRemoteTest : public ::testing::Test {
 protected:
  StrategyLocalRemoteTest() {
    conf_ = configuration_create();
    MAIN_LOOP = loop_create();
    fwd_ = forwarder_create(conf_);

    /* Strategy and strategy entry */
    entry_ = {
        .type = STRATEGY_TYPE_LOCAL_REMOTE,
        .options =
            {
                .random = {},
            },
        .state = {.random = {}},
    };

    strategy_initialize(&entry_, fwd_);
  }

  virtual ~StrategyLocalRemoteTest() {
    INFO("loop stopped");
    forwarder_free(fwd_);
    loop_free(MAIN_LOOP);
    MAIN_LOOP = NULL;
    strategy_finalize(&entry_);
  }

  strategy_entry_t entry_;
  nexthops_t available_nexthops_;
  configuration_t* conf_;
  forwarder_t* fwd_;
  msgbuf_t msgbuf_;
};

TEST_F(StrategyLocalRemoteTest, InputLocalOutputLocal) {
  address_t listener_addr = ADDRESS4_LOCALHOST(9596);
  address_t prod_addr = ADDRESS4_LOCALHOST(12345);
  address_t cons_addr = ADDRESS4_LOCALHOST(54321);

  listener_t* listener = listener_create(FACE_TYPE_UDP_LISTENER, &listener_addr,
                                         "lo", "lo_udp4", fwd_);

  address_pair_t pair_conn_prod = {
      .local = listener_addr,
      .remote = prod_addr,
  };

  address_pair_t pair_conn_cons = {
      .local = listener_addr,
      .remote = cons_addr,
  };

  unsigned prod_conn_id =
      listener_create_connection(listener, "conp", &pair_conn_prod);
  unsigned cons_conn_id =
      listener_create_connection(listener, "conc", &pair_conn_cons);

  msgbuf_.connection_id = cons_conn_id;

  nexthops_add(&available_nexthops_, prod_conn_id);
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry_, &available_nexthops_, &msgbuf_);

  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)0);
}

TEST_F(StrategyLocalRemoteTest, InputRemoteOutputRemote) {
  const char prod_addr_str[] = "192.168.1.1";
  const char cons_addr_str[] = "192.168.1.2";
  in_addr_t prod_addr_int;
  in_addr_t cons_addr_int;
  inet_pton(AF_INET, prod_addr_str, &prod_addr_int);
  inet_pton(AF_INET, cons_addr_str, &cons_addr_int);

  address_t prod_addr = ADDRESS4(prod_addr_int, 12345);
  address_t cons_addr = ADDRESS4(cons_addr_int, 12345);
  address_t listener_addr = ADDRESS4_LOCALHOST(9596);

  listener_t* listener = listener_create(FACE_TYPE_UDP_LISTENER, &listener_addr,
                                         "lo", "lo_udp4", fwd_);

  address_pair_t pair_conn_prod = {
      .local = listener_addr,
      .remote = prod_addr,
  };

  address_pair_t pair_conn_cons = {
      .local = listener_addr,
      .remote = cons_addr,
  };

  connection_t* conn;
  unsigned prod_conn_id =
      listener_create_connection(listener, "conp", &pair_conn_prod);
  unsigned cons_conn_id =
      listener_create_connection(listener, "conc", &pair_conn_cons);

  // fake two remote connections
  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    prod_conn_id);
  conn->local = false;
  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    cons_conn_id);
  conn->local = false;

  msgbuf_.connection_id = cons_conn_id;

  nexthops_add(&available_nexthops_, prod_conn_id);
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry_, &available_nexthops_, &msgbuf_);

  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)0);
}

TEST_F(StrategyLocalRemoteTest, InputLocalOutputRemote) {
  const char prod_addr_str[] = "192.168.1.1";
  in_addr_t prod_addr_int;
  inet_pton(AF_INET, prod_addr_str, &prod_addr_int);

  address_t prod_addr = ADDRESS4(prod_addr_int, 12345);
  address_t cons_addr = ADDRESS4_LOCALHOST(12345);
  address_t listener_addr = ADDRESS4_LOCALHOST(9596);

  listener_t* listener = listener_create(FACE_TYPE_UDP_LISTENER, &listener_addr,
                                         "lo", "lo_udp4", fwd_);

  address_pair_t pair_conn_prod = {
      .local = listener_addr,
      .remote = prod_addr,
  };

  address_pair_t pair_conn_cons = {
      .local = listener_addr,
      .remote = cons_addr,
  };

  connection_t* conn;
  unsigned prod_conn_id =
      listener_create_connection(listener, "conp", &pair_conn_prod);
  unsigned cons_conn_id =
      listener_create_connection(listener, "conc", &pair_conn_cons);

  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    prod_conn_id);
  conn->local = false;
  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    cons_conn_id);
  conn->local = true;

  msgbuf_.connection_id = cons_conn_id;

  nexthops_add(&available_nexthops_, prod_conn_id);
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry_, &available_nexthops_, &msgbuf_);

  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)1);
}

TEST_F(StrategyLocalRemoteTest, InputRemoteOutputLocal) {
  const char cons_addr_str[] = "192.168.1.2";
  in_addr_t cons_addr_int;
  inet_pton(AF_INET, cons_addr_str, &cons_addr_int);

  address_t cons_addr = ADDRESS4(cons_addr_int, 12345);
  address_t prod_addr = ADDRESS4_LOCALHOST(12345);
  address_t listener_addr = ADDRESS4_LOCALHOST(9596);

  listener_t* listener = listener_create(FACE_TYPE_UDP_LISTENER, &listener_addr,
                                         "lo", "lo_udp4", fwd_);

  address_pair_t pair_conn_prod = {
      .local = listener_addr,
      .remote = prod_addr,
  };

  address_pair_t pair_conn_cons = {
      .local = listener_addr,
      .remote = cons_addr,
  };

  connection_t* conn;
  unsigned prod_conn_id =
      listener_create_connection(listener, "conp", &pair_conn_prod);
  unsigned cons_conn_id =
      listener_create_connection(listener, "conc", &pair_conn_cons);

  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    prod_conn_id);
  conn->local = true;
  conn = connection_table_get_by_id(forwarder_get_connection_table(fwd_),
                                    cons_conn_id);
  conn->local = false;

  msgbuf_.connection_id = cons_conn_id;

  nexthops_add(&available_nexthops_, prod_conn_id);
  nexthops_t* nexthops;
  nexthops = strategy_lookup_nexthops(&entry_, &available_nexthops_, &msgbuf_);

  EXPECT_EQ(nexthops_get_curlen(nexthops), (size_t)1);
}
