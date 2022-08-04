#ifndef HICNCTRL_MODULES_OBJECT_H
#define HICNCTRL_MODULES_OBJECT_H

ssize_t hc_object_serialize(hc_action_t action, hc_object_type_t object_type,
                            hc_object_t *object, hc_msg_t *msg);

int hc_object_parse(hc_object_type_t object_type, uint8_t *buffer,
                    hc_object_t *object);

#endif /* HICNCTRL_MODULES_OBJECT_H */
