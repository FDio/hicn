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

#pragma once

#include <hicn/transport/utils/singleton.h>

#include <ostream>

#define foreach_log_level  \
  _(Info, LOG(INFO))       \
  _(Warning, LOG(WARNING)) \
  _(Error, LOG(ERROR))     \
  _(Fatal, LOG(FATAL))

#define CLASS_NAME(log_level) Log##log_level

namespace utils {

#define _(class_name, macro_name)                                           \
  class CLASS_NAME(class_name) : public Singleton<CLASS_NAME(class_name)> { \
    friend class Singleton<CLASS_NAME(class_name)>;                         \
                                                                            \
   public:                                                                  \
    std::ostream& getStream();                                              \
  };
foreach_log_level
#undef _

}  // namespace utils

#define TRANSPORT_LOG_INFO ::utils::LogInfo::getInstance().getStream()
#define TRANSPORT_LOG_WARNING ::utils::LogWarning::getInstance().getStream()
#define TRANSPORT_LOG_ERROR ::utils::LogError::getInstance().getStream()
#define TRANSPORT_LOG_FATAL ::utils::LogFatal::getInstance().getStream()
