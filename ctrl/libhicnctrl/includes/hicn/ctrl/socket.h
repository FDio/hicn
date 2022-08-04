/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file socket.h
 * \brief Control socket
 */

#ifndef HICNCTRL_SOCKET_H
#define HICNCTRL_SOCKET_H

#include <hicn/ctrl/data.h>

/* With UDP, the buffer should be able to receieve a full packet, and thus MTU
 * (max 9000) is sufficient. Messages will be received fully one by one.
 * With TCP, the buffer should be at least able to receive a message header and
 * the maximum size of a data element, so any reasonable size will be correct,
 * it might just optimize performance. Messages might arrive in chunks that the
 * library is able to parse.
 */
#define JUMBO_MTU 9000
#define RECV_BUFLEN 65535

#define foreach_forwarder_type \
  _(UNDEFINED)                 \
  _(HICNLIGHT)                 \
  _(VPP)                       \
  _(N)

typedef enum {
#define _(x) FORWARDER_TYPE_##x,
  foreach_forwarder_type
#undef _
} forwarder_type_t;

extern const char *forwarder_type_str[];

#define forwarder_type_str(x) forwarder_type_str[x]

forwarder_type_t forwarder_type_from_str(const char *str);

/**
 * \brief Holds the state of an hICN control socket
 */
typedef struct hc_sock_s hc_sock_t;

/**
 * \brief Create an hICN control socket using the specified URL.
 * \param [in] url - The URL to connect to.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create_url(const char *url);

/**
 * \brief Create an hICN control socket using the provided forwarder.
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create_forwarder(forwarder_type_t forwarder);

/**
 * \brief Create an hICN control socket using the provided forwarder and a
 * URL. \return an hICN control socket
 */
hc_sock_t *hc_sock_create_forwarder_url(forwarder_type_t forwarder,
                                        const char *url);

/**
 * \brief Create an hICN control socket using the default connection type.
 * XXX doc
 * \return an hICN control socket
 */
hc_sock_t *hc_sock_create(forwarder_type_t forwarder, const char *url);

/**
 * \brief Frees an hICN control socket
 * \param [in] s - hICN control socket
 */
void hc_sock_free(hc_sock_t *s);

/**
 * \brief Returns the next available sequence number to use for requests to
 * the API. \param [in] s - hICN control socket
 */
int hc_sock_get_next_seq(hc_sock_t *s);

/**
 * \brief Sets the socket as non-blocking
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_set_nonblocking(hc_sock_t *s);

/**
 * \brief Return the file descriptor associated to the hICN contorl sock
 * \param [in] s - hICN control socket
 * \return The file descriptor (positive value), or a negative integer in case
 * of error
 */
int hc_sock_get_fd(hc_sock_t *s);

/**
 * \brief Connect the socket
 * \return Error code
 */
int hc_sock_connect(hc_sock_t *s);

/**
 * \brief Return the offset and size of available buffer space
 * \param [in] s - hICN control socket
 * \param [out] buffer - Offset in buffer
 * \param [out] size - Remaining size
 * \return Error code
 */
int hc_sock_get_recv_buffer(hc_sock_t *s, uint8_t **buffer, size_t *size);

#if 0
/**
 * \brief Write/read iexchance on the control socket (internal helper
 * function) \param [in] s - hICN control socket \param [in] msg - Message to
 * send \param [in] msglen - Length of the message to send \return Error code
 */
int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, uint32_t seq);
#endif

/**
 * \brief Processing data received by socket
 * \param [in] s - hICN control socket
 * \param [in] parse - Parse function to convert remote types into lib native
 *      types, or NULL not to perform any translation.
 * \return Error code
 */
int hc_sock_process(hc_sock_t *s, hc_data_t **data);

int hc_sock_receive(hc_sock_t *s, hc_data_t **data);
int hc_sock_receive_all(hc_sock_t *s, hc_data_t **data);

#if 0
/**
 * \brief Callback used in async mode when data is available on the socket
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_callback(hc_sock_t *s, hc_data_t **data);
#endif

/**
 * \brief Reset the state of the sock (eg. to handle a reconnecton)
 * \param [in] s - hICN control socket
 * \return Error code
 */
int hc_sock_reset(hc_sock_t *s);

void hc_sock_increment_woff(hc_sock_t *s, size_t bytes);

#if 0
int hc_sock_prepare_send(hc_sock_t *s, hc_result_t *result,
                         data_callback_t complete_cb, void *complete_cb_data);

#endif

int hc_sock_set_recv_timeout_ms(hc_sock_t *s, long timeout_ms);

int hc_sock_set_async(hc_sock_t *s);

int hc_sock_is_async(hc_sock_t *s);

int hc_sock_on_receive(hc_sock_t *s, size_t count);

#endif /* HICNCTRL_SOCKET_H */
