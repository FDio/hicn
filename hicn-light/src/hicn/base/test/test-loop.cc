/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#include <hicn/base/loop.h>
}

class LoopTest : public ::testing::Test {
  static constexpr uint16_t BUFFER_SIZE = 1024;
 protected:
  LoopTest()
      : server_port_(9191),
        loop_(nullptr),
        timer_tick_(2000),
        connection_socket_(-1) {
  }

  virtual ~LoopTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  static int onTimerExpiration(void *owner, int fd, void* arg) {
    // Create client socket
    struct sockaddr_in addr;
    int client_socket;
    LoopTest *test = (LoopTest *)(arg);

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("socket");
        return -1;
    }

    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test->server_port_);

    if (connect(client_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
        perror("connect");
        return -1;
    }

    if (send(client_socket, "Hello, world!\n", 14, 0) == -1){
        perror("send");
        return -1;
    }

    close(client_socket);

    return 0;
  }

  static int onNewConnection(void *owner, int fd, void* arg) {
    LoopTest *test = (LoopTest *)arg;
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_family = AF_INET;

    socklen_t addr_len = sizeof(struct sockaddr_in);
    int ret;

    int client_fd = accept(test->connection_socket_, (struct sockaddr*)(&addr), &addr_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "accept failed");
        }

        perror("accept");
        return -1;
    }

    // Read whatever data available and close connection.
    ret = read(client_fd, test->buffer, BUFFER_SIZE);
    if (ret < 0) {
        perror("read");
        return -1;
    }

    test->buffer[ret] = '\0';
    std::cout << "Received: " << (char*)test->buffer << std::endl;

    close(client_fd);
    loop_break(test->loop_);

    return 0;
  }

  void createTcpSocketServer() {
    struct sockaddr_in addr;
    int ret;

    /* Create local socket. */

    connection_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (connection_socket_ == -1) {
        perror("socket");
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port_);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(connection_socket_, (const struct sockaddr *) &addr,
                      sizeof(struct sockaddr_in));
    if (ret == -1) {
        perror("bind");
        return;
    }

    ret = listen(connection_socket_, 20);
    if (ret == -1) {
        perror("listen");
        return;
    }
}

  uint16_t server_port_;
  loop_t *loop_;
  unsigned timer_tick_;
  int connection_socket_;
  char buffer[BUFFER_SIZE];
};

TEST_F(LoopTest, LoopCreate)
{
    loop_ = loop_create();
    EXPECT_TRUE(loop_ != NULL);
}

TEST_F(LoopTest, LoopFree)
{
    loop_ = loop_create();
    loop_free (loop_);
    EXPECT_TRUE(loop_ != NULL);
}

TEST_F(LoopTest, EventCreateAndFree)
{
    event_t *event = nullptr;
    int ret;

    // Fake fd
    int fd = 17;
    loop_ = loop_create();

    ret = loop_fd_event_create(&event, loop_, fd, nullptr, &LoopTest::onNewConnection, this);
    EXPECT_TRUE(ret >= 0);
    EXPECT_TRUE(event);

    // Register the event
    ret = loop_fd_event_register(event);
    EXPECT_TRUE(ret >= 0);

    // Unregister the event
    ret = loop_fd_event_unregister(event);
    EXPECT_TRUE(ret >= 0);

    // Free event loop
    loop_free (loop_);
}

TEST_F(LoopTest, LoopDispatch)
{
    event_t *event = nullptr;
    event_t *timer = nullptr;
    int ret;

    // Create new unix socket
    createTcpSocketServer();
    loop_ = loop_create();

    ret = loop_fd_event_create(&event, loop_, connection_socket_, nullptr, &LoopTest::onNewConnection, this);
    EXPECT_TRUE(ret >= 0);
    EXPECT_TRUE(event);

    ret = loop_fd_event_register(event);
    EXPECT_TRUE(ret >= 0);

    // Create timer.
    ret = loop_timer_create(&timer, loop_, nullptr, &LoopTest::onTimerExpiration, this);
    EXPECT_TRUE(ret >= 0);
    EXPECT_TRUE(timer);

    ret = loop_timer_register(timer, timer_tick_);
    EXPECT_TRUE(ret >= 0);

    // Start event dispatching
    loop_dispatch(loop_);

    // Stop dispatching
    loop_undispatch(loop_);

    // Free event loop
    loop_free (loop_);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
