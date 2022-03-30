/*
 * Copyright (c) 2021 HUACHENTEL and/or its affiliates.
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

#ifndef __IETF_INTERFACE_H__
#define __IETF_INTERFACE_H__

int ietf_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription);

#endif /* __IETF_INTERFACE_H__ */
