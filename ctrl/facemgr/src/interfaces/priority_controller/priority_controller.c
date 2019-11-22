#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hicn/facemgr.h>

#include "../../common.h"
#include "../../interface.h"

typedef struct {
    int fd;
} pc_data_t;

int priority_controller_initialize(interface_t * interface, void * cfg)
{
    INFO("Initializing priority controller");
    struct sockaddr_in addr;

    pc_data_t * data = malloc(sizeof(pc_data_t));
    if (!data) {
        INFO("Priority controller data memory allocation error");
        return -1;
    }

    interface->data = data;

    data->fd = socket(AF_INET, SOCK_DGRAM, 0);
    //data->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (data->fd < 0) {
        INFO("Priority controller socket error");
        perror("socket error");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9533);

    if (bind(data->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        INFO("Priority controller socket bind error");
        perror("bind error");
        return -1;
    }
	interface_register_fd(interface, data->fd, NULL);
    /*
    if (connect(data->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        INFO("Priority controller socket connection error");
        perror("connect error");
        return -1;
    }
    */

    INFO("Priority controller successfully initialized");
    return data->fd;
}

int priority_controller_finalize(interface_t * interface)
{
    pc_data_t * data = (pc_data_t*)interface->data;

    if (data->fd > 0) {close(data->fd);}
    free(data);

    return 0;
}

//int priority_controller_callback(interface_t * interface, int fd, void * unused)
//int priority_controller_callback(interface_t * interface)
int priority_controller_callback(interface_t * interface, int fd, void * unused)
{
    pc_data_t * data = (pc_data_t*)interface->data;
    char buf[100];
    int rc;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9533);

    INFO("Priority controller receiving command");

    rc = recv(data->fd, buf, 100, 0);
    /*
    rc = read(data->fd, buf, sizeof(buf));
    */
    if (rc < 0) {
        INFO("Priority controller read error");
        return -1;
    }

    INFO("Priority controller received command: %02X", buf[0]);
    
    facelet_t * facelet_w = facelet_create();
    facelet_t * facelet_c = facelet_create();
    facelet_set_netdevice_type(facelet_w, NETDEVICE_TYPE_WIFI);
    facelet_set_netdevice_type(facelet_c, NETDEVICE_TYPE_CELLULAR);
    facelet_set_status(facelet_w, FACELET_STATUS_CLEAN);
    facelet_set_status(facelet_c, FACELET_STATUS_CLEAN);
    switch(buf[0]) {
        case '\0':
            //facelet_set_admin_state(facelet_w, FACE_STATE_DOWN);
            //facelet_set_admin_state(facelet_c, FACE_STATE_UP);
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 10);
            INFO("Priority controller configuring Cellular preferred");
            break;
        case '\1':
            //facelet_set_admin_state(facelet_w, FACE_STATE_UP);
            //facelet_set_admin_state(facelet_c, FACE_STATE_DOWN);
            facelet_set_priority(facelet_w, 10);
            facelet_set_priority(facelet_c, 0);
            INFO("Priority controller configuring Wi-Fi preferred");
            break;
        case '\2':
            //facelet_set_admin_state(facelet_w, FACE_STATE_UP);
            //facelet_set_admin_state(facelet_c, FACE_STATE_UP);
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 0);
            INFO("Priority controller configuring both Cellular and Wi-Fi preferred");
            break;
        default:
            INFO("Priority cntroller invalid data received from updown server. Ignoring...");
            facelet_free(facelet_w);
            facelet_free(facelet_c);
            return -1;
    }

    facelet_set_event(facelet_w, FACELET_EVENT_UPDATE);
    facelet_set_event(facelet_c, FACELET_EVENT_UPDATE);

    //facelet_raise_event(facelet_w, interface);
    //facelet_raise_event(facelet_c, interface);
    interface_raise_event(interface, facelet_w);
    interface_raise_event(interface, facelet_c);
    
    facelet_free(facelet_w);
    facelet_free(facelet_c);
    return 0;
}

interface_ops_t priority_controller_ops = {
    .type = "priority_controller",
    .initialize = priority_controller_initialize,
    .finalize = priority_controller_finalize,
    .callback = priority_controller_callback,
};
