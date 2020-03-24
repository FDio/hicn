/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <hicn_hs/error.h>

u8 *
quic_format_err (u8 * s, va_list * args)
{
  u64 code = va_arg (*args, u64);
  switch (code)
    {
    case 0:
      s = format (s, "no error");
      break;
    default:
      s = format (s, "unknown error 0x%lx", code);
      break;
    }
  return s;
}
