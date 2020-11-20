#include <vapi/vapi_safe.h>
#include <stdlib.h>
#include <stdio.h>

#define APP_NAME "hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE 2

pthread_mutex_t *mutex = NULL;
vapi_ctx_t g_vapi_ctx_instance = NULL;
u32 count = 0;
int lock = 0;

vapi_error_e vapi_connect_safe(vapi_ctx_t *vapi_ctx_ret, int async) {
  vapi_error_e rv = VAPI_OK;

  while (!__sync_bool_compare_and_swap(&lock, 0, 1));

  if (!g_vapi_ctx_instance && !mutex)
    {
      rv = vapi_ctx_alloc(&g_vapi_ctx_instance);
      if (rv != VAPI_OK)
	goto err;

      mutex = malloc(sizeof(pthread_mutex_t));
      if (!mutex)
	goto err_mutex_alloc;

      if (pthread_mutex_init(mutex, NULL) != 0) {
	printf("Mutex init failed\n");
	goto err_mutex_init;
      }
    }

  if (!count)
    {
      rv = vapi_connect(g_vapi_ctx_instance, APP_NAME, NULL,
			MAX_OUTSTANDING_REQUESTS, RESPONSE_QUEUE_SIZE,
			async ? VAPI_MODE_NONBLOCKING : VAPI_MODE_BLOCKING, true);

      if (rv != VAPI_OK)
	goto err;

      count++;
    }

  *vapi_ctx_ret = g_vapi_ctx_instance;

  while (!__sync_bool_compare_and_swap(&lock, 1, 0));
  return rv;

 err_mutex_init:
  free(mutex);
 err_mutex_alloc:
 err:
  while (!__sync_bool_compare_and_swap(&lock, 1, 0));
  return VAPI_ENOMEM;
}

vapi_error_e vapi_disconnect_safe() {
  pthread_mutex_lock(mutex);
  vapi_error_e rv = VAPI_OK;
  pthread_mutex_unlock(mutex);
  return rv;
}

void vapi_lock() {
  pthread_mutex_lock(mutex);
}

void vapi_unlock() {
  pthread_mutex_unlock(mutex);
}
