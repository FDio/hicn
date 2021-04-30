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

#pragma once

namespace transport {
namespace auth {

/**
 * These policies allows the verifier to tell the transport what action to
 * perform after verification.
 */
enum class VerificationPolicy {
  ABORT,
  ACCEPT,
  DROP,
  UNKNOWN,
};

}  // namespace auth
}  // namespace transport
