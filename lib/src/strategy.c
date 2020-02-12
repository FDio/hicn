/*
 * copyright (c) 2017-2019 cisco and/or its affiliates.
 * licensed under the apache license, version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * you may obtain a copy of the license at:
 *
 *     http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 */

/**
 * \file strategy.c
 * \brief Implementation of forwarding strategy concept
 */
#include <strings.h>
#include <hicn/strategy.h>

const char * HICN_STRATEGY_STR[] = {
#define _(x) [HICN_STRATEGY_ ## x] = #x,
foreach_hicn_strategy_name
#undef _
};

int
hicn_strategy_get_by_name(const char * name, hicn_strategy_t * strategy)
{
    *strategy = HICN_STRATEGY_UNDEFINED;
#define _(x) if (strcasecmp(name,                               \
            HICN_STRATEGY_STR[HICN_STRATEGY_ ## x]) == 0) {     \
    *strategy = HICN_STRATEGY_ ## x;                            \
} else
    foreach_hicn_strategy_name
#undef _
        return -1;
    return HICN_STRATEGY_IS_VALID(*strategy);
}

