#include <vapi/vapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>

#include <vapi/hicn.api.vapi.h>

DEFINE_VAPI_MSG_IDS_HICN_API_JSON;

vapi_ctx_t g_vapi_ctx_instance;

#define APP_NAME "test_hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE 2

vapi_ctx_t g_vapi_ctx_instance = NULL;

void usage() {
  printf(
      "choose the test [route_add [4|6], punt_add [4|6], face_add [4|6], "
      "route_dump, face_dump]\n");
}

static vapi_error_e call_hicn_api_punting_add(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_punting_add_reply *reply) {
  if (!reply->retval) {
    printf("Successfully done");
    return VAPI_OK;
  } else
    return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_face_ip_add(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_face_ip_add_reply *reply) {
  if (!reply->retval) {
    printf("Successfully done");
    return VAPI_OK;
  } else
    return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_route_nhops_add(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_route_nhops_add_reply *reply) {
  if (!reply->retval) {
    printf("Successfully done");
    return VAPI_OK;
  } else
    return VAPI_EUSER;
}

static vapi_error_e hicn_api_routes_dump_cb(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_routes_details *reply) {
  char buf[20];
  if (reply != NULL) {
    memset(buf, 0x00, 20);
    if (reply->prefix.address.af == ADDRESS_IP4) {
      struct sockaddr_in sa;
      memcpy(&sa.sin_addr.s_addr, reply->prefix.address.un.ip4, 4);
      inet_ntop(AF_INET, &(sa.sin_addr.s_addr), buf, INET_ADDRSTRLEN);
      printf("Prefix:%s\n", buf);
    } else {
      struct sockaddr_in6 sa;
      memcpy(&sa.sin6_addr, reply->prefix.address.un.ip6, 6);
      inet_ntop(AF_INET6, &(sa.sin6_addr), buf, INET6_ADDRSTRLEN);
      printf("Prefix:%s\n", buf);
    }
  } else {
    printf("---------Routes------- \n");
  }
  return 0;
}

static vapi_error_e hicn_api_face_stats_dump_cb(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_face_stats_details *reply) {
  if (reply != NULL) {
    printf("face_id:%d \n", reply->faceid);
    printf("irx_packets:%" PRId64 "\n", reply->irx_packets);
    printf("irx_bytes:%" PRId64 "\n", reply->irx_bytes);
    printf("itx_packets:%" PRId64 "\n", reply->itx_packets);
    printf("itx_bytes:%" PRId64 "\n", reply->itx_bytes);
    printf("drx_packets:%" PRId64 "\n", reply->drx_packets);
    printf("drx_bytes:%" PRId64 "\n", reply->drx_bytes);
    printf("dtx_packets:%" PRId64 "\n", reply->dtx_packets);
    printf("dtx_bytes:%" PRId64 "\n", reply->dtx_bytes);

  } else {
    printf("---------Facees------- \n");
  }
  return 0;
}

int hicn_connect_vpp() {
  if (g_vapi_ctx_instance == NULL) {
    vapi_error_e rv = vapi_ctx_alloc(&g_vapi_ctx_instance);
    rv = vapi_connect(g_vapi_ctx_instance, APP_NAME, NULL,
                      MAX_OUTSTANDING_REQUESTS, RESPONSE_QUEUE_SIZE,
                      VAPI_MODE_BLOCKING, true);
    if (rv != VAPI_OK) {
      vapi_ctx_free(g_vapi_ctx_instance);
      return -1;
    }
  } else {
  }
  return 0;
}

int hicn_disconnect_vpp() {
  if (NULL != g_vapi_ctx_instance) {
    vapi_disconnect(g_vapi_ctx_instance);
    vapi_ctx_free(g_vapi_ctx_instance);
    g_vapi_ctx_instance = NULL;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    return 1;
  }

  /* connect to vpp */
  int rc = hicn_connect_vpp();
  if (-1 == rc) {
    perror("vpp connect error");
    return -1;
  }

  if (!strcmp(argv[1], "route_add")) {
    vapi_msg_hicn_api_route_nhops_add *msg;
    msg = vapi_alloc_hicn_api_route_nhops_add(g_vapi_ctx_instance);

    if (!strcmp(argv[2], "4")) {
      struct sockaddr_in sa;
      inet_pton(AF_INET, "192.168.10.10", &(sa.sin_addr));
      unsigned char *tmp = (unsigned char *)&sa.sin_addr.s_addr;
      memcpy(&msg->payload.prefix.address.un.ip4[0], tmp, 4);
      msg->payload.prefix.address.af = ADDRESS_IP4;
    } else {
      void *dst = malloc(sizeof(struct in6_addr));
      inet_pton(AF_INET6, "2001::1", dst);
      unsigned char *tmp = (unsigned char *)((struct in6_addr *)dst)->s6_addr;
      memcpy(&msg->payload.prefix.address.un.ip6[0], tmp, 16);
      msg->payload.prefix.address.af = ADDRESS_IP6;
    }

    msg->payload.prefix.len = 24;
    msg->payload.face_ids[0] = 0;
    msg->payload.face_ids[1] = 0;
    msg->payload.face_ids[2] = 0;
    msg->payload.face_ids[3] = 0;
    msg->payload.face_ids[4] = 0;
    msg->payload.face_ids[5] = 0;
    msg->payload.face_ids[6] = 0;
    msg->payload.n_faces = 1;

    if (vapi_hicn_api_route_nhops_add(g_vapi_ctx_instance, msg,
                                      call_hicn_api_route_nhops_add,
                                      NULL) != VAPI_OK) {
      perror("Operation failed");
      return -1;
    }
  } else if (!strcmp(argv[1], "face_add")) {
    vapi_msg_hicn_api_face_ip_add *fmsg;
    fmsg = vapi_alloc_hicn_api_face_ip_add(g_vapi_ctx_instance);

    if (!strcmp(argv[2], "4")) {
      struct sockaddr_in sa;
      inet_pton(AF_INET, "192.168.50.19", &(sa.sin_addr));
      unsigned char *tmp = (unsigned char *)&sa.sin_addr.s_addr;
      memcpy(&fmsg->payload.face.local_addr.un.ip4[0], tmp, 4);
      fmsg->payload.face.local_addr.af = ADDRESS_IP4;

      inet_pton(AF_INET, "192.168.60.10", &(sa.sin_addr));
      tmp = (unsigned char *)&sa.sin_addr.s_addr;
      memcpy(&fmsg->payload.face.remote_addr.un.ip4[0], tmp, 4);
      fmsg->payload.face.remote_addr.af = ADDRESS_IP4;

    } else {
      void *dst = malloc(sizeof(struct in6_addr));
      inet_pton(AF_INET6, "2001::1", dst);
      unsigned char *tmp = (unsigned char *)((struct in6_addr *)dst)->s6_addr;
      memcpy(&fmsg->payload.face.local_addr.un.ip6[0], tmp, 16);
      fmsg->payload.face.local_addr.af = ADDRESS_IP6;

      inet_pton(AF_INET6, "3001::1", dst);
      tmp = (unsigned char *)((struct in6_addr *)dst)->s6_addr;
      memcpy(&fmsg->payload.face.remote_addr.un.ip6[0], tmp, 16);
      fmsg->payload.face.remote_addr.af = ADDRESS_IP6;
    }

    fmsg->payload.face.swif = 0;  // This is the idx number of interface

    if (vapi_hicn_api_face_ip_add(g_vapi_ctx_instance, fmsg,
                                  call_hicn_api_face_ip_add, NULL) != VAPI_OK) {
      perror("Operation failed");
      return -1;
    }
  } else if (!strcmp(argv[1], "route_dump")) {
    // routes dump
    vapi_msg_hicn_api_routes_dump *rmsg;
    rmsg = vapi_alloc_hicn_api_routes_dump(g_vapi_ctx_instance);
    vapi_hicn_api_routes_dump(g_vapi_ctx_instance, rmsg,
                              hicn_api_routes_dump_cb, NULL);

  } else if (!strcmp(argv[1], "face_dump")) {
    // faces dump
    vapi_msg_hicn_api_face_stats_dump *fmsg;
    fmsg = vapi_alloc_hicn_api_face_stats_dump(g_vapi_ctx_instance);
    vapi_hicn_api_face_stats_dump(g_vapi_ctx_instance, fmsg,
                                  hicn_api_face_stats_dump_cb, NULL);
  } else if (!strcmp(argv[1], "punt_add")) {
    vapi_msg_hicn_api_punting_add *pmsg;

    pmsg = vapi_alloc_hicn_api_punting_add(g_vapi_ctx_instance);

    pmsg->payload.type = IP_PUNT;

    if (!strcmp(argv[2], "4")) {
      struct sockaddr_in sa;
      // store this IP address in sa:
      inet_pton(AF_INET, "192.168.10.20", &(sa.sin_addr));
      unsigned char *tmp = (unsigned char *)&sa.sin_addr.s_addr;
      memcpy(&pmsg->payload.rule.ip.prefix.address.un.ip4[0], tmp, 4);
      pmsg->payload.rule.ip.prefix.address.af = ADDRESS_IP4;

    } else {
      void *dst = malloc(sizeof(struct in6_addr));
      inet_pton(AF_INET6, "3001::1", dst);
      unsigned char *tmp = (unsigned char *)((struct in6_addr *)dst)->s6_addr;
      memcpy(&pmsg->payload.rule.ip.prefix.address.un.ip6[0], tmp, 16);
      pmsg->payload.rule.ip.prefix.address.af = ADDRESS_IP6;
    }

    pmsg->payload.rule.ip.prefix.len = 24;
    pmsg->payload.rule.ip.swif = 0;

    if (vapi_hicn_api_punting_add(g_vapi_ctx_instance, pmsg,
                                  call_hicn_api_punting_add, NULL) != VAPI_OK) {
      perror("Operation failed");
      return -1;
    }
  } else {
    usage();
    return 1;
  }

  hicn_disconnect_vpp();

  return rc;
}
