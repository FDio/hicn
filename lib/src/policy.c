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

/**
 * \file policy.h
 * \brief Implementation of policy description
 */

#include <stdio.h>
#include <hicn/policy.h>

const char *policy_tag_str[] = {
#define _(x, y) [POLICY_TAG_##x] = STRINGIZE (x),
  foreach_policy_tag
#undef _
};

const char policy_tag_short_str[] = {
#define _(x, y) [POLICY_TAG_##x] = y,
  foreach_policy_tag
#undef _
};

const char *policy_state_str[] = {
#define _(x) [POLICY_STATE_##x] = STRINGIZE (x),
  foreach_policy_state
#undef _
};

policy_state_t
policy_state_from_str (const char *str)
{
#define _(x)                                                                  \
  if (strcasecmp (str, #x) == 0)                                              \
    return POLICY_STATE_##x;                                                  \
  else
  foreach_policy_state
#undef _
    return POLICY_STATE_N;
}

int
policy_tag_state_snprintf (char *s, size_t size,
			   const policy_tag_state_t *tag_state)
{
  char *cur = s;
  int rc;

  if (tag_state->disabled > 1)
    return -1;

  rc = snprintf (cur, s + size - cur, "%s%s",
		 (tag_state->disabled == 1) ? "!" : "",
		 policy_state_str[tag_state->state]);
  if (rc >= (int) (s + size - cur))
    return (int) (s + size - cur);
  if (rc < 0)
    return rc;
  cur += rc;
  return (int) (cur - s);
}
