#ifndef VAPI_SAFE
#include <vapi/vapi.h>
#include <pthread.h>

extern pthread_mutex_t *mutex;

vapi_error_e vapi_connect_safe(vapi_ctx_t * vapi_ctx_ret, int async);

vapi_error_e vapi_disconnect_safe();
void vapi_lock();

void vapi_unlock();

#define VAPI_SAFE (NAME, res, ...)		\
    vapi_lock();                                \
    res = ## NAME (__ARGS__);			\
    vapi_unlock();

#endif //VAPI_SAFE
