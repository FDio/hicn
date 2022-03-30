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

#include <vapi/vapi_safe.h>
#include <stdlib.h>
#include <stdio.h>

#define APP_NAME		 "hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE	 2

DEFINE_VAPI_MSG_IDS_HICN_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON
DEFINE_VAPI_MSG_IDS_UDP_API_JSON
DEFINE_VAPI_MSG_IDS_MEMIF_API_JSON

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
vapi_ctx_t g_vapi_ctx_instance = NULL;
u32 count = 0;

vapi_error_e
vapi_connect_safe (vapi_ctx_t *vapi_ctx_ret, int async)
{
  vapi_error_e rv = VAPI_OK;

  vapi_lock ();

  if (!g_vapi_ctx_instance)
    {
      rv = vapi_ctx_alloc (&g_vapi_ctx_instance);
      if (rv != VAPI_OK)
	goto err;
    }

  if (!count)
    {
      rv = vapi_connect (g_vapi_ctx_instance, APP_NAME, NULL,
			 MAX_OUTSTANDING_REQUESTS, RESPONSE_QUEUE_SIZE,
			 async ? VAPI_MODE_NONBLOCKING : VAPI_MODE_BLOCKING,
			 true);

      if (rv != VAPI_OK)
	goto err;
    }

  count++;
  *vapi_ctx_ret = g_vapi_ctx_instance;

  vapi_unlock ();
  return rv;

err:
  vapi_unlock ();
  return VAPI_ENOMEM;
}

vapi_error_e
vapi_disconnect_safe ()
{
  vapi_error_e rv = VAPI_OK;

  vapi_lock ();
  count--;
  if (count == 0)
    {
      rv = vapi_disconnect (g_vapi_ctx_instance);
      vapi_ctx_free (g_vapi_ctx_instance);
      g_vapi_ctx_instance = NULL;
    }
  vapi_unlock ();

  return rv;
}

void
vapi_lock ()
{
  pthread_mutex_lock (&mutex);
}

void
vapi_unlock ()
{
  pthread_mutex_unlock (&mutex);
}
