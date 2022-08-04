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
 * \file interfaces/android/android.c
 * \brief Netlink interface
 */

#include <assert.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>  // close

#include <hicn/facemgr.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>

#include "../../common.h"
#include "../../interface.h"
#include "../../facelet_array.h"

#include "android.h"

/*
 * aar_modules/FaceMgrLibrary/facemgrLibrary/src/main/java/com/cisco/hicn/facemgrlibrary/supportlibrary/FacemgrUtility.java
 */
#define FACEMGR_ANDROID_CLASS \
  "com/cisco/hicn/facemgrlibrary/supportlibrary/FacemgrUtility"

/* Internal data storage */
typedef struct {
  int fd;
  android_cfg_t cfg;
  JNIEnv *env;
  jclass cls;
  bool attached_to_vm;
  facelet_array_t *facelets;
  pthread_mutex_t mutex;
} android_data_t;

// might replace android utility

jclass find_class_global(JNIEnv *env, const char *name) {
  jclass c = (*env)->FindClass(env, name);
  jclass c_global = 0;
  if (c) {
    c_global = (jclass)(*env)->NewGlobalRef(env, c);
    (*env)->DeleteLocalRef(env, c);
  }
  return c_global;
}

int android_on_network_event(interface_t *interface, const char *interface_name,
                             netdevice_type_t netdevice_type, bool up,
                             int family, const char *ip_address) {
  android_data_t *data = (android_data_t *)interface->data;

  netdevice_t *netdevice = netdevice_create_from_name(interface_name);
  if (!netdevice) {
    ERROR("[android_on_network_event] error creating netdevice '%s'",
          interface_name);
    goto ERR_ND;
  }

  hicn_ip_address_t local_addr = IP_ADDRESS_EMPTY;
  if (ip_address) {
    if (hicn_ip_address_pton(ip_address, &local_addr) < 0) {
      ERROR("[android_on_network_event] error processing IP address");
      goto ERR_IP_ADDRESS;
    }
  }

  facelet_t *facelet = facelet_create();
  if (!facelet) {
    ERROR("[android_on_network_event] error creating facelet");
    goto ERR_FACELET;
  }

  if (facelet_set_netdevice(facelet, *netdevice) < 0) {
    ERROR("[android_on_network_event] error setting netdevice");
    goto ERR;
  }

  if (netdevice_type != NETDEVICE_TYPE_UNDEFINED) {
    if (facelet_set_netdevice_type(facelet, netdevice_type) < 0) {
      ERROR("[android_on_network_event] error setting netdevice type");
      goto ERR;
    }
  }

  if (facelet_set_family(facelet, family) < 0) {
    ERROR("[android_on_network_event] error setting family");
    goto ERR;
  }

  if (ip_address) {
    if (facelet_set_local_addr(facelet, local_addr) < 0) {
      ERROR("[android_on_network_event] error setting local address");
      goto ERR;
    }
  }
  netdevice_free(netdevice);

  facelet_set_event(facelet, up ? FACELET_EVENT_CREATE : FACELET_EVENT_DELETE);
  // FACELET_EVENT_UPDATE, FACELET_EVENT_SET_DOWN
  facelet_set_attr_clean(facelet);

  pthread_mutex_lock(&data->mutex);
  if (facelet_array_add(data->facelets, facelet)) {
    ERROR("[android_on_network_event] Could not add facelet to buffer");
    goto ERR_ADD;
  }

  pthread_mutex_unlock(&data->mutex);

  eventfd_write(data->fd, 1);
  return 0;

ERR_ADD:
  pthread_mutex_unlock(&data->mutex);
ERR:
  facelet_free(facelet);
ERR_FACELET:
ERR_IP_ADDRESS:
  netdevice_free(netdevice);
ERR_ND:
  return -1;
}

bool get_jni_env(JavaVM *jvm, JNIEnv **env) {
  bool did_attach_thread = false;
  INFO("initialize: get_jni_env");
  *env = NULL;
  // Check if the current thread is attached to the VM
  int get_env_result = (*jvm)->GetEnv(jvm, (void **)env, JNI_VERSION_1_6);
  if (get_env_result == JNI_EDETACHED) {
    INFO("initialize: detached!");
    if ((*jvm)->AttachCurrentThread(jvm, env, NULL) == JNI_OK) {
      INFO("initialize: attached...");
      did_attach_thread = true;
    } else {
      INFO("initialize: failed to attach");
      // Failed to attach thread. Throw an exception if you want to.
    }
  } else if (get_env_result == JNI_EVERSION) {
    // Unsupported JNI version. Throw an exception if you want to.
    INFO("initialize: unsupported");
  }
  return did_attach_thread;
}

int android_initialize(interface_t *interface, void *cfg) {
  android_data_t *data = malloc(sizeof(android_data_t));
  if (!data) goto ERR_MALLOC;
  interface->data = data;

  if (!cfg) goto ERR_CFG;
  data->cfg = *(android_cfg_t *)cfg;

  JavaVM *jvm = data->cfg.jvm;
  if (!jvm) goto ERR_JVM;

  data->facelets = facelet_array_create();
  if (!data->facelets) goto ERR_FACELETS;

  if ((data->fd = eventfd(0, EFD_SEMAPHORE)) == -1) goto ERR_EVENTFD;

  if (interface_register_fd(interface, data->fd, NULL) < 0) {
    ERROR("[android_initialize] Error registering fd");
    goto ERR_REGISTER_FD;
  }

  pthread_mutex_init(&data->mutex, NULL);

  data->attached_to_vm = get_jni_env(jvm, &data->env);

  if (!data->env) goto ERR_ENV;

  data->cls = find_class_global(data->env, FACEMGR_ANDROID_CLASS);
  if (data->cls == 0) goto ERR_CLS;

  jmethodID mid_initialize =
      (*data->env)
          ->GetStaticMethodID(data->env, data->cls, "initialize", "()I");
  if (!mid_initialize) goto ERR_MID;

  (*data->env)
      ->CallStaticIntMethod(data->env, data->cls, mid_initialize,
                            &android_on_network_event, interface);

  return 0;

ERR_MID:
  (*data->env)->DeleteGlobalRef(data->env, data->cls);
ERR_CLS:
  if (data->attached_to_vm) {
    (*jvm)->DetachCurrentThread(jvm);
    data->attached_to_vm = false;
  }
  data->env = NULL;
ERR_ENV:
  interface_unregister_fd(interface, data->fd);
ERR_REGISTER_FD:
  close(data->fd);
ERR_EVENTFD:
  facelet_array_free(data->facelets);
ERR_FACELETS:
ERR_JVM:
ERR_CFG:
  free(data);
ERR_MALLOC:
  return -1;
}

int android_finalize(interface_t *interface) {
  android_data_t *data = (android_data_t *)interface->data;

  jmethodID mid_terminate =
      (*data->env)->GetStaticMethodID(data->env, data->cls, "terminate", "()I");
  if (mid_terminate) {
    (*data->env)
        ->CallStaticIntMethod(data->env, data->cls, mid_terminate,
                              &android_on_network_event, interface);
  }

  (*data->env)->DeleteGlobalRef(data->env, data->cls);

  JavaVM *jvm = data->cfg.jvm;
  if (data->attached_to_vm) {
    (*jvm)->DetachCurrentThread(jvm);
    data->attached_to_vm = false;
  }
  data->env = NULL;

  pthread_mutex_destroy(&data->mutex);

  // interface_unregister_fd(interface, data->fd); // XXX done in
  // facemgr_delete_interface...
  close(data->fd);
  facelet_array_free(data->facelets);

  free(data);

  return 0;
}

int android_callback(interface_t *interface, int fd, void *unused) {
  android_data_t *data = (android_data_t *)interface->data;

  uint64_t ret;
  if (read(data->fd, &ret, sizeof(ret)) < 0) return -1;
  if (ret == 0)  // EOF
    return 0;

  pthread_mutex_lock(&data->mutex);
  for (unsigned i = 0; i < facelet_array_len(data->facelets); i++) {
    facelet_t *facelet;
    if (facelet_array_get_index(data->facelets, i, &facelet) < 0) {
      ERROR("[android_callback] Error getting facelet in array");
      continue;
    }

    interface_raise_event(interface, facelet);
  }

  for (unsigned i = 0; i < facelet_array_len(data->facelets); i++) {
    if (facelet_array_remove_index(data->facelets, i, NULL) < 0) {
      ERROR("[android_callback] Could not purge facelet from array");
    }
  }
  pthread_mutex_unlock(&data->mutex);

  return 0;
}

const interface_ops_t android_ops = {
    .type = "android",
    .initialize = android_initialize,
    .callback = android_callback,
    .finalize = android_finalize,
    .on_event = NULL,
};
