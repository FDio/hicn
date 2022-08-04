#ifndef HICNCTRL_CALLBACK_H
#define HICNCTRL_CALLBACK_H

#include <stdbool.h>

#include <hicn/ctrl/data.h>

typedef int (*hc_enable_callback_t)(bool enable);
typedef void (*hc_state_callback_t)(bool enable, void *user_data);
typedef void (*hc_result_callback_t)(hc_data_t *data, void *user_data);
typedef void (*hc_notification_callback_t)(hc_data_t *data, void *user_data);

#endif /* HICNCTRL_CALLBACK_H */
