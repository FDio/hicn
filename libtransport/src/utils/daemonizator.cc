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

#ifndef _WIN32
#include <hicn/transport/errors/runtime_exception.h>
#include <hicn/transport/utils/daemonizator.h>
#include <hicn/transport/utils/log.h>

#include <sys/stat.h>
#include <unistd.h>

namespace utils {

void Daemonizator::daemonize(bool close_fds) {
  pid_t process_id = 0;
  pid_t sid = 0;

  // Create child process
  process_id = fork();

  // Indication of fork() failure
  if (process_id < 0) {
    throw errors::RuntimeException("Fork failed.");
  }

  // PARENT PROCESS. Need to kill it.
  if (process_id > 0) {
    TRANSPORT_LOGE("Process id of child process %d", process_id);
    // return success in exit status
    exit(EXIT_SUCCESS);
  }

  // unmask the file mode
  umask(0);

  // set new session
  sid = setsid();
  if (sid < 0) {
    // Return failure
    exit(EXIT_FAILURE);
  }

  // Change the current working directory to root.
  int ret = chdir("/");

  if (ret < 0) {
    throw errors::RuntimeException("Error changing working directory to root");
  }

  // Close stdin. Redirect stdout and stderr to file if possible

  if (close_fds) {
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
  }

  close(STDIN_FILENO);

  // Really start application
}

}  // namespace utils

#endif
