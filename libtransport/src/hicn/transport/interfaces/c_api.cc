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

#include <hicn/transport/interfaces/c_api.h>
#include <hicn/transport/interfaces/c_api_errors.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/spinlock.h>

#include <set>

namespace transport {
namespace interface {
namespace details {

enum class RC {
  ERROR = -1,
  NO_ERROR = 0,
};

/**
 * Integer pool for managing reusing of socket integers.
 */
class IntegerPool {
  static constexpr uint32_t max_socket_number = (1 << 10);

 public:
  IntegerPool() {
    for (int i = 10; i < 10 + max_socket_number; i++) {
      insert(i);
    }
  }

  void insert(int number) {
    utils::SpinLock::Acquire locked(lock_);
    integer_set_.emplace(number);
  }

  int get() {
    int ret = -1;

    {
      utils::SpinLock::Acquire locked(lock_);
      auto it = integer_set_.begin();
      if (it != integer_set_.end()) {
        ret = *it;
        integer_set_.erase(it);
      }
    }

    return ret;
  }

 private:
  utils::SpinLock lock_;
  std::set<int> integer_set_;
};

class ConsumerAdapter : public ConsumerSocket {
  ConsumerAdapter(int protocol) : ConsumerSocket(protocol) {}
};

class ProducerAdapter : public ProducerSocket {
  ProducerAdapter() : ProducerSocket() {}
};

}  // namespace details
}  // namespace interface
}  // namespace transport

extern "C" {

const char *C_API_ERROR_STRING[] = {
#define _(a, b, c) c,
    foreach_c_api_error
#undef _
};

int hicn_socket(int domain, int type, int protocol) {
  int ret = C_API_ERROR_NONE;

  if (TRANSPORT_EXPECT_FALSE(domain != AF_HICN)) {
    return C_API_ERROR_UNEXPECTED_DOMAIN;
  }

  if (TRANSPORT_EXPECT_FALSE(type != SOCK_PROD || type != SOCK_CONS)) {
    return C_API_ERROR_UNEXPECTED_SOCKET_TYPE;
  }

  if (TRANSPORT_EXPECT_FALSE(protocol < PROD_REL || protocol > CONS_CBR)) {
    return C_API_ERROR_UNEXPECTED_PROTOCOL;
  }
}
}