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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlib/vlib.h>

#include <vpp_plugins/hicn/error.h>

#include "network/hicn.h"
#include "network/params.h"
#include "network/infra.h"
#include "network/strategy_dpo_manager.h"
#include "network/mgmt.h"
#include "network/faces/app/address_mgr.h"
#include "network/face_db.h"
#include "network/udp_tunnels/udp_tunnel.h"
#include "network/route.h"
#include "host_stack/host_stack.h"

/*
 * Init entry-point for the icn plugin
 */
static clib_error_t *
hicn_init(vlib_main_t *vm)
{
  clib_error_t *error = 0;

  hicn_main_t *sm = &hicn_main;

  /* Init other elements in the 'main' struct */
  sm->is_enabled = 0;

  error = hicn_api_plugin_hookup(vm);

  /* Init the dpo module */
  hicn_dpos_init();

  /* Init the app manager */
  address_mgr_init();

  hicn_face_module_init(vm);

  /* Init the route module */
  hicn_route_init();

  udp_tunnel_init();

  /* Init the host stack module */
  // hicn_hs_init(vm);

  return error;
}

VLIB_INIT_FUNCTION(hicn_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER() =
    {
        .description = "hICN network/transport/session plugin"};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
