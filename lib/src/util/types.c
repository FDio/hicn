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

#include <hicn/util/types.h>

uint32_t
htonf (float f)
{
  uint32_t i;
  uint32_t sign = 0;

  if (f < 0)
    {
      sign = 1;
      f = -f;
    }

  // i[31] = sign bit
  i = sign << 31;

  // i[30 to 16] = int(f)[14 to 0]
  i |= (((uint32_t) f) & 0x7fff) << 16;

  // i[15 to 0] = fraction(f) bits [15 to 0]
  i |= (uint32_t) ((f - (uint32_t) f) * 65536.0f) & 0xffff;

  return i;
}

float
ntohf (uint32_t i)
{
  // integer part = i[14 to 0]
  float f = (i >> 16) & 0x7fff;

  // fraction part = i[15 to 0]
  f += (i & 0xffff) / 65536.0f;

  // sign = i[31]
  if ((i >> 31) & 1)
    f = -f;

  return f;
}
