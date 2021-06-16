/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * @file base.h
 * #brief Base IO functions.
 */

#ifndef HICNLIGHT_IO_BASE
#define HICNLIGHT_IO_BASE

#include "../core/address_pair.h"
#include "../core/msgbuf.h"

#define MAX_MSG 64 //16 //32

ssize_t io_read_single_fd(int fd, msgbuf_t * msgbuf,
        address_t * address);

ssize_t io_read_single_socket(int fd, msgbuf_t * msgbuf,
        address_t * address);

ssize_t io_read_batch_socket(int fd, msgbuf_t ** msgbuf,
        address_t ** address, size_t n);

#endif /* HICNLIGHT_IO_BASE */
