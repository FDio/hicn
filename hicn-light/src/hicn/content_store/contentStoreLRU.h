/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef contentStoreLRU_h
#define contentStoreLRU_h

#include <hicn/content_store/contentStoreInterface.h>
#include <hicn/core/logger.h>
#include <stdio.h>

/**
 * Create and Initialize an instance of contentStoreLRU. A newly allocated
 * {@link ContentStoreInterface} object is initialized and returned. It must
 * eventually be released by calling {@link contentStoreInterface_Release}.
 *
 *
 * @param config An instance of `ContentStoreConfig`, specifying options to be
 * applied by the underlying contentStoreLRU instance.
 * @param logger An instance of a {@link Logger} to use for logging content
 * store events.
 *
 * @return a newly created contentStoreLRU instance.
 *
 */
ContentStoreInterface *contentStoreLRU_Create(ContentStoreConfig *config,
                                              Logger *logger);
#endif  // contentStoreLRU_h
