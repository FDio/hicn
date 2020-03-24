/*
 * hicn_hs_client.c - vpp built-in hicn client
 *
 * Copyright (c) 2017-2019 by Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include "hicn_hs_client.h"
#include <plugins/hicn_hs/hicn_hs.h>

hicn_client_main_t hicn_client_main;

#define HICN_CLIENT_DBG (0)
#define DBG(_fmt, _args...)			\
    if (HICN_CLIENT_DBG) 				\
      clib_warning (_fmt, ##_args)

#define ec_cli_output(_fmt, _args...) 			\
  if (!hcm->no_output)  				\
    vlib_cli_output(vm, _fmt, ##_args)

f64 t0;

static void
signal_evt_to_cli_i (int *code)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (hcm->vlib_main, hcm->cli_node_index, *code, 0);
}

static void
signal_evt_to_cli (int code)
{
  if (vlib_get_thread_index () != 0)
    vl_api_rpc_call_main_thread (signal_evt_to_cli_i, (u8 *) & code,
				 sizeof (code));
  else
    signal_evt_to_cli_i (&code);
}

static void
receive_data_chunk (hicn_client_main_t * hcm, eclient_session_t * s)
{
  svm_fifo_t *rx_fifo = s->data.rx_fifo;
  u32 thread_index = vlib_get_thread_index ();
  int n_read, i;

  if (hcm->test_bytes)
    {
      if (!hcm->is_dgram)
	n_read = app_recv_stream (&s->data, hcm->rx_buf[thread_index],
				  vec_len (hcm->rx_buf[thread_index]));
      else
	n_read = app_recv_dgram (&s->data, hcm->rx_buf[thread_index],
				 vec_len (hcm->rx_buf[thread_index]));
    }
  else
    {
      n_read = svm_fifo_max_dequeue_cons (rx_fifo);
      svm_fifo_dequeue_drop (rx_fifo, n_read);
    }

  if (n_read > 0)
    {
      if (HICN_CLIENT_DBG)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "rx-deq: %d bytes",
              .format_args = "i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 data[1];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = n_read;
	}

      if (hcm->test_bytes)
	{
	  for (i = 0; i < n_read; i++)
	    {
	      if (hcm->rx_buf[thread_index][i]
		  != ((s->bytes_received + i) & 0xff))
		{
		  clib_warning ("read %d error at byte %lld, 0x%x not 0x%x",
				n_read, s->bytes_received + i,
				hcm->rx_buf[thread_index][i],
				((s->bytes_received + i) & 0xff));
		  hcm->test_failed = 1;
		}
	    }
	}
      vlib_main_t *vm = vlib_get_main();
      hcm->test_end_time = vlib_time_now (vm);
      f64 delta = hcm->test_end_time - hcm->test_start_time;

      ec_cli_output ("Throughput (%d, %.20f): %.2f b/s", n_read, delta, ((f64)(n_read)) / delta);

      s->bytes_to_receive -= n_read;
      s->bytes_received += n_read;
    }
}

// static uword
// hicn_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
// 		     vlib_frame_t * frame)
// {
//   hicns_client_main_t *hcm = &hicn_client_main;
//   int my_thread_index = vlib_get_thread_index ();
//   eclient_session_t *sp;
//   int i;
//   int delete_session;
//   u32 *connection_indices;
//   u32 *connections_this_batch;
//   u32 nconnections_this_batch;

//   connection_indices = hcm->connection_index_by_thread[my_thread_index];
//   connections_this_batch =
//     hcm->connections_this_batch_by_thread[my_thread_index];

//   if ((hcm->run_test != HICN_CLIENT_RUNNING) ||
//       ((vec_len (connection_indices) == 0)
//        && vec_len (connections_this_batch) == 0))
//     return 0;

//   /* Grab another pile of connections */
//   if (PREDICT_FALSE (vec_len (connections_this_batch) == 0))
//     {
//       nconnections_this_batch =
// 	clib_min (hcm->connections_per_batch, vec_len (connection_indices));

//       ASSERT (nconnections_this_batch > 0);
//       vec_validate (connections_this_batch, nconnections_this_batch - 1);
//       clib_memcpy_fast (connections_this_batch,
// 			connection_indices + vec_len (connection_indices)
// 			- nconnections_this_batch,
// 			nconnections_this_batch * sizeof (u32));
//       _vec_len (connection_indices) -= nconnections_this_batch;
//     }

//   if (PREDICT_FALSE (hcm->prev_conns != hcm->connections_per_batch
// 		     && hcm->prev_conns == vec_len (connections_this_batch)))
//     {
//       hcm->repeats++;
//       hcm->prev_conns = vec_len (connections_this_batch);
//       if (hcm->repeats == 500000)
// 	{
// 	  clib_warning ("stuck clients");
// 	}
//     }
//   else
//     {
//       hcm->prev_conns = vec_len (connections_this_batch);
//       hcm->repeats = 0;
//     }

//   for (i = 0; i < vec_len (connections_this_batch); i++)
//     {
//       delete_session = 1;

//       sp = pool_elt_at_index (hcm->sessions, connections_this_batch[i]);

//       if (sp->bytes_to_send > 0)
// 	{
// 	  send_data_chunk (hcm, sp);
// 	  delete_session = 0;
// 	}
//       if (sp->bytes_to_receive > 0)
// 	{
// 	  delete_session = 0;
// 	}
//       if (PREDICT_FALSE (delete_session == 1))
// 	{
// 	  session_t *s;

// 	  clib_atomic_fetch_add (&hcm->tx_total, sp->bytes_sent);
// 	  clib_atomic_fetch_add (&hcm->rx_total, sp->bytes_received);
// 	  s = session_get_from_handle_if_valid (sp->vpp_session_handle);

// 	  if (s)
// 	    {
// 	      vnet_disconnect_args_t _a, *a = &_a;
// 	      a->handle = session_handle (s);
// 	      a->app_index = hcm->app_index;
// 	      vnet_disconnect_session (a);

// 	      vec_delete (connections_this_batch, 1, i);
// 	      i--;
// 	      clib_atomic_fetch_add (&hcm->ready_connections, -1);
// 	    }
// 	  else
// 	    {
// 	      clib_warning ("session AWOL?");
// 	      vec_delete (connections_this_batch, 1, i);
// 	    }

// 	  /* Kick the debug CLI process */
// 	  if (hcm->ready_connections == 0)
// 	    {
// 	      signal_evt_to_cli (2);
// 	    }
// 	}
//     }

//   hcm->connection_index_by_thread[my_thread_index] = connection_indices;
//   hcm->connections_this_batch_by_thread[my_thread_index] =
//     connections_this_batch;
//   return 0;
// }

// /* *INDENT-OFF* */
// VLIB_REGISTER_NODE (hicn_clients_node) =
// {
//   .function = hicn_client_node_fn,
//   .name = "hicn-client",
//   .type = VLIB_NODE_TYPE_INPUT,
//   .state = VLIB_NODE_STATE_DISABLED,
// };
// /* *INDENT-ON* */

static int
create_api_loopback (hicn_client_main_t * hcm)
{
  api_main_t *am = vlibapi_get_main ();
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  hcm->vl_input_queue = shmem_hdr->vl_input_queue;
  hcm->my_client_index = vl_api_memclnt_create_internal ("hicn_client",
							hcm->vl_input_queue);
  return 0;
}

static int
hicn_client_init (vlib_main_t * vm)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  int i;

  if (create_api_loopback (hcm))
    return -1;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  /* Init test data. Big buffer */
  vec_validate (hcm->connect_test_data, 4 * 1024 * 1024 - 1);
  for (i = 0; i < vec_len (hcm->connect_test_data); i++)
    hcm->connect_test_data[i] = i & 0xff;

  vec_validate (hcm->rx_buf, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    vec_validate (hcm->rx_buf[i], vec_len (hcm->connect_test_data) - 1);

  hcm->is_init = 1;

  vec_validate (hcm->connection_index_by_thread, vtm->n_vlib_mains);
  vec_validate (hcm->connections_this_batch_by_thread, vtm->n_vlib_mains);
  vec_validate (hcm->vpp_event_queue, vtm->n_vlib_mains);

  return 0;
}

static int
hicn_client_session_connected_callback (u32 app_wrk_index, u32 opaque,
					session_t * s, session_error_t code)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  eclient_session_t *session;
  u32 session_index;
  u8 thread_index;

  if (PREDICT_FALSE (hcm->run_test != HICN_CLIENT_STARTING))
    return -1;

  if (code)
    {
      clib_warning ("connection %d failed!", opaque);
      hcm->run_test = HICN_CLIENT_EXITING;
      signal_evt_to_cli (-1);
      return 0;
    }

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ()
	  || session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

  if (!hcm->vpp_event_queue[thread_index])
    hcm->vpp_event_queue[thread_index] =
      session_main_get_vpp_event_queue (thread_index);

  /*
   * Setup session
   */
  clib_spinlock_lock_if_init (&hcm->sessions_lock);
  pool_get (hcm->sessions, session);
  clib_spinlock_unlock_if_init (&hcm->sessions_lock);

  clib_memset (session, 0, sizeof (*session));
  session_index = session - hcm->sessions;
  session->bytes_to_send = hcm->bytes_to_send;
  session->bytes_to_receive = hcm->no_return ? 0ULL : hcm->bytes_to_send;
  session->data.rx_fifo = s->rx_fifo;
  session->data.rx_fifo->client_session_index = session_index;
  session->data.tx_fifo = s->tx_fifo;
  session->data.tx_fifo->client_session_index = session_index;
  session->data.vpp_evt_q = hcm->vpp_event_queue[thread_index];
  session->vpp_session_handle = session_handle (s);

  if (hcm->is_dgram)
    {
      transport_connection_t *tc;
      tc = session_get_transport (s);
      clib_memcpy_fast (&session->data.transport, tc,
			sizeof (session->data.transport));
      session->data.is_dgram = 1;
    }

  vec_add1 (hcm->connection_index_by_thread[thread_index], session_index);
  clib_atomic_fetch_add (&hcm->ready_connections, 1);
  if (hcm->ready_connections == hcm->expected_connections)
    {
      hcm->run_test = HICN_CLIENT_RUNNING;
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (1);
    }

  return 0;
}

static void
hicn_client_session_reset_callback (session_t * s)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (s->session_state == SESSION_STATE_READY)
    clib_warning ("Reset active connection %U", format_session, s, 2);

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
  return;
}

static int
hicn_client_session_create_callback (session_t * s)
{
  return 0;
}

static void
hicn_client_session_disconnect_callback (session_t * s)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
  return;
}

void
hicn_client_session_disconnect (session_t * s)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static int
hicn_client_rx_callback (session_t * s)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  eclient_session_t *sp;

  if (PREDICT_FALSE (hcm->run_test != HICN_CLIENT_RUNNING))
    {
      hicn_client_session_disconnect (s);
      return -1;
    }

  sp = pool_elt_at_index (hcm->sessions, s->rx_fifo->client_session_index);
  receive_data_chunk (hcm, sp);

  if (svm_fifo_max_dequeue_cons (s->rx_fifo))
    {
      if (svm_fifo_set_event (s->rx_fifo))
	session_send_io_evt_to_thread (s->rx_fifo, SESSION_IO_EVT_BUILTIN_RX);
    }
  return 0;
}

int
hicn_client_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* New heaps may be added */
  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t hicn_client = {
  .session_reset_callback = hicn_client_session_reset_callback,
  .session_connected_callback = hicn_client_session_connected_callback,
  .session_accept_callback = hicn_client_session_create_callback,
  .session_disconnect_callback = hicn_client_session_disconnect_callback,
  .builtin_app_rx_callback = hicn_client_rx_callback,
  .add_segment_callback = hicn_client_add_segment_callback
};
/* *INDENT-ON* */

static clib_error_t *
hicn_client_attach (u8 * appns_id, u64 appns_flags, u64 appns_secret)
{
  vnet_app_add_tls_cert_args_t _a_cert, *a_cert = &_a_cert;
  vnet_app_add_tls_key_args_t _a_key, *a_key = &_a_key;
  u32 prealloc_fifos, segment_size = 256 << 20;
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[17];
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = hcm->my_client_index;
  a->session_cb_vft = &hicn_client;

  prealloc_fifos = hcm->prealloc_fifos ? hcm->expected_connections : 1;

  if (hcm->private_segment_size)
    segment_size = hcm->private_segment_size;

  options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = hcm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = hcm->fifo_size;
  options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = hcm->private_segment_count;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_TLS_ENGINE] = hcm->tls_engine;
  options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  if (appns_id)
    {
      options[APP_OPTIONS_FLAGS] |= appns_flags;
      options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
    }
  a->options = options;
  a->namespace_id = appns_id;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned %d", rv);

  hcm->app_index = a->app_index;

  clib_memset (a_cert, 0, sizeof (*a_cert));
  a_cert->app_index = a->app_index;
  vec_validate (a_cert->cert, test_srv_crt_rsa_len);
  clib_memcpy_fast (a_cert->cert, test_srv_crt_rsa, test_srv_crt_rsa_len);
  vnet_app_add_tls_cert (a_cert);

  clib_memset (a_key, 0, sizeof (*a_key));
  a_key->app_index = a->app_index;
  vec_validate (a_key->key, test_srv_key_rsa_len);
  clib_memcpy_fast (a_key->key, test_srv_key_rsa, test_srv_key_rsa_len);
  vnet_app_add_tls_key (a_key);
  return 0;
}

static int
hicn_client_detach ()
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  da->app_index = hcm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  hcm->test_client_attached = 0;
  hcm->app_index = ~0;
  return rv;
}

static void *
hicn_client_thread_fn (void *arg)
{
  return 0;
}

/** Start a transmit thread */
int
hicn_client_start_tx_pthread (hicn_client_main_t * hcm)
{
  if (hcm->client_thread_handle == 0)
    {
      int rv = pthread_create (&hcm->client_thread_handle,
			       NULL /*attr */ ,
			       hicn_client_thread_fn, 0);
      if (rv)
	{
	  hcm->client_thread_handle = 0;
	  return -1;
	}
    }
  return 0;
}

clib_error_t *
hicn_client_connect (vlib_main_t * vm, u32 n_clients)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vnet_connect_args_t _a, *a = &_a;
  int i, rv;

  clib_memset (a, 0, sizeof (*a));

  for (i = 0; i < n_clients; i++)
    {
      a->uri = (char *) hcm->connect_uri;
      a->api_context = i;
      a->app_index = hcm->app_index;

      vlib_worker_thread_barrier_sync (vm);
      if ((rv = vnet_connect_uri (a)))
	{
	  vlib_worker_thread_barrier_release (vm);
	  return clib_error_return (0, "connect returned: %d", rv);
	}
      vlib_worker_thread_barrier_release (vm);

      /* Crude pacing for call setups  */
      if ((i % 16) == 0)
	vlib_process_suspend (vm, 100e-6);
      ASSERT (i + 1 >= hcm->ready_connections);
      while (i + 1 - hcm->ready_connections > 128)
	vlib_process_suspend (vm, 1e-3);
    }

  return 0;
}

static clib_error_t *
hicn_client_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  u64 total_bytes, appns_flags = 0, appns_secret = 0;
  f64 test_timeout = 20.0, syn_timeout = 20.0, delta;
  char *default_uri = "hicn://b001::1";
  uword *event_data = 0, event_type;
  f64 time_before_connects;
  u32 n_clients = 1;
  int preallocate_sessions = 0;
  char *transfer_type;
  clib_error_t *error = 0;
  u8 *appns_id = 0;
  int i;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  int rv;

  hcm->bytes_to_send = 8192;
  hcm->no_return = 0;
  hcm->fifo_size = 128 << 20;
  hcm->connections_per_batch = 1000;
  hcm->private_segment_count = 0;
  hcm->private_segment_size = 0;
  hcm->no_output = 0;
  hcm->test_bytes = 0;
  hcm->test_failed = 0;
  hcm->vlib_main = vm;
  hcm->tls_engine = CRYPTO_ENGINE_OPENSSL;
  hcm->no_copy = 0;
  hcm->run_test = HICN_CLIENT_STARTING;

  if (thread_main->n_vlib_mains > 1)
    clib_spinlock_init (&hcm->sessions_lock);
  vec_free (hcm->connect_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &hcm->connect_uri))
	;
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  /* Store cli process node index for signalling */
  hcm->cli_node_index =
    vlib_get_current_process (vm)->node_runtime.node_index;

  if (hcm->is_init == 0)
    {
      if (hicn_client_init (vm))
	return clib_error_return (0, "failed init");
    }


  hcm->ready_connections = 0;
  hcm->expected_connections = n_clients;
  hcm->rx_total = 0;
  hcm->tx_total = 0;

  if (!hcm->connect_uri)
    {
      clib_warning ("No uri provided. Using default: %s", default_uri);
      hcm->connect_uri = format (0, "%s%c", default_uri, 0);
    }

  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, 1 /* turn on session and transports */ );
  hicn_hs_enable_disable(vm, 1 /* enable hicn transport */);
  vlib_worker_thread_barrier_release (vm);

  if ((rv = parse_uri ((char *) hcm->connect_uri, &sep)))
    return clib_error_return (0, "Uri parse error: %d", rv);
  hcm->transport_proto = sep.transport_proto;
  hcm->is_dgram = (sep.transport_proto == TRANSPORT_PROTO_UDP);

#if HICN_CLIENT_PTHREAD
  hicn_client_start_tx_pthread ();
#endif

  if (hcm->test_client_attached == 0)
    {
      if ((error = hicn_client_attach (appns_id, appns_flags, appns_secret)))
	{
	  vec_free (appns_id);
	  clib_error_report (error);
	  return error;
	}
      vec_free (appns_id);
    }
  hcm->test_client_attached = 1;

  /* Turn on the builtin client input nodes */
  for (i = 0; i < thread_main->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], hicn_client_node.index,
			 VLIB_NODE_STATE_POLLING);

  if (preallocate_sessions)
    pool_init_fixed (hcm->sessions, 1.1 * n_clients);

  /* Fire off connect requests */
  time_before_connects = vlib_time_now (vm);
  if ((error = hicn_client_connect (vm, n_clients)))
    {
      goto cleanup;
    }

  /* Park until the sessions come up, or ten seconds elapse... */
  vlib_process_wait_for_event_or_clock (vm, syn_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli_output ("Timeout with only %d sessions active...",
		     hcm->ready_connections);
      error = clib_error_return (0, "failed: syn timeout with %d sessions",
				 hcm->ready_connections);
      goto cleanup;

    case 1:
      delta = vlib_time_now (vm) - time_before_connects;
      if (delta != 0.0)
	ec_cli_output ("%d three-way handshakes in %.2f seconds %.2f/s",
		       n_clients, delta, ((f64) n_clients) / delta);

      hcm->test_start_time = vlib_time_now (hcm->vlib_main);
      break;

    default:
      ec_cli_output ("unexpected event(1): %d", event_type);
      error = clib_error_return (0, "failed: unexpected event(1): %d",
				 event_type);
      goto cleanup;
    }

  /* Now wait for the sessions to finish... */
  vlib_process_wait_for_event_or_clock (vm, test_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli_output ("Timeout with %d sessions still active...",
		     hcm->ready_connections);
      error = clib_error_return (0, "failed: timeout with %d sessions",
				 hcm->ready_connections);
      goto cleanup;

    case 2:
      hcm->test_end_time = vlib_time_now (vm);
      ec_cli_output ("Test finished at %.6f", hcm->test_end_time);
      break;

    default:
      ec_cli_output ("unexpected event(2): %d", event_type);
      error = clib_error_return (0, "failed: unexpected event(2): %d",
				 event_type);
      goto cleanup;
    }

  delta = hcm->test_end_time - hcm->test_start_time;
  if (delta != 0.0)
    {
      total_bytes = (hcm->no_return ? hcm->tx_total : hcm->rx_total);
      transfer_type = hcm->no_return ? "half-duplex" : "full-duplex";
      ec_cli_output ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds",
		     total_bytes, total_bytes / (1ULL << 20),
		     total_bytes / (1ULL << 30), delta);
      ec_cli_output ("%.2f bytes/second %s", ((f64) total_bytes) / (delta),
		     transfer_type);
      ec_cli_output ("%.4f gbit/second %s",
		     (((f64) total_bytes * 8.0) / delta / 1e9),
		     transfer_type);
    }
  else
    {
      ec_cli_output ("zero delta-t?");
      error = clib_error_return (0, "failed: zero delta-t");
      goto cleanup;
    }

  if (hcm->test_bytes && hcm->test_failed)
    error = clib_error_return (0, "failed: test bytes");

cleanup:
  hcm->run_test = HICN_CLIENT_EXITING;
  vlib_process_wait_for_event_or_clock (vm, 10e-3);
  for (i = 0; i < vec_len (hcm->connection_index_by_thread); i++)
    {
      vec_reset_length (hcm->connection_index_by_thread[i]);
      vec_reset_length (hcm->connections_this_batch_by_thread[i]);
    }

  pool_free (hcm->sessions);

  /* Detach the application, so we can use different fifo sizes next time */
  if (hcm->test_client_attached)
    {
      if (hicn_client_detach ())
	{
	  error = clib_error_return (0, "failed: app detach");
	  ec_cli_output ("WARNING: app detach failed...");
	}
    }
  if (error)
    ec_cli_output ("test failed");
  vec_free (hcm->connect_uri);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hicn_client_command, static) =
{
  .path = "test hicn hs client",
  .short_help = "test hicn hs client [uri <hicn://ip6_address/port>]",
  .function = hicn_client_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
hicn_client_main_init (vlib_main_t * vm)
{
  hicn_client_main_t *hcm = &hicn_client_main;
  hcm->is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (hicn_client_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
