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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/assert/parc_Assert.h>

#include <hicn/core/streamBuffer.h>

void streamBuffer_Destroy(PARCEventQueue **bufferPtr) {
  parcAssertNotNull(bufferPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*bufferPtr,
                    "Parameter must dereference to non-null pointer");
  parcEventQueue_Destroy(bufferPtr);
  *bufferPtr = NULL;
}

void streamBuffer_SetWatermark(PARCEventQueue *buffer, bool setRead,
                               bool setWrite, size_t low, size_t high) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");

  short flags = 0;
  if (setRead) {
    flags |= PARCEventType_Read;
  }

  if (setWrite) {
    flags |= PARCEventType_Write;
  }

  parcEventQueue_SetWatermark(buffer, flags, low, high);
}

int streamBuffer_Flush(PARCEventQueue *buffer, bool flushRead,
                       bool flushWrite) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");

  short flags = 0;
  if (flushRead) {
    flags |= PARCEventType_Read;
  }

  if (flushWrite) {
    flags |= PARCEventType_Write;
  }

  return parcEventQueue_Flush(buffer, flags);
}

int streamBuffer_FlushCheckpoint(PARCEventQueue *buffer, bool flushRead,
                                 bool flushWrite) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");

  short flags = 0;
  if (flushRead) {
    flags |= PARCEventType_Read;
  }

  if (flushWrite) {
    flags |= PARCEventType_Write;
  }

  return parcEventQueue_Flush(buffer, flags);
}

int streamBuffer_FlushFinished(PARCEventQueue *buffer, bool flushRead,
                               bool flushWrite) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");

  short flags = 0;
  if (flushRead) {
    flags |= PARCEventType_Read;
  }

  if (flushWrite) {
    flags |= PARCEventType_Write;
  }

  return parcEventQueue_Flush(buffer, flags);
}

void streamBuffer_SetCallbacks(PARCEventQueue *buffer,
                               PARCEventQueue_Callback *readCallback,
                               PARCEventQueue_Callback *writeCallback,
                               PARCEventQueue_EventCallback *eventCallback,
                               void *user_data) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");

  parcEventQueue_SetCallbacks(buffer, readCallback, writeCallback,
                              eventCallback, user_data);
}

void streamBuffer_EnableCallbacks(PARCEventQueue *buffer, bool enableRead,
                                  bool enableWrite) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");
  short flags = 0;
  if (enableRead) {
    flags |= PARCEventType_Read;
  }
  if (enableWrite) {
    flags |= PARCEventType_Write;
  }

  parcEventQueue_Enable(buffer, flags);
}

/**
 * @function StreamBuffer_DisableCallbacks
 * @abstract Disables specified callbacks.  Does not affect others.
 * @discussion
 *   Disables enabled callbacks.  If a callback is already disabled, has no
 * effect. A "false" value does not enable it.
 *
 * @param <#param1#>
 * @return <#return#>
 */
void streamBuffer_DisableCallbacks(PARCEventQueue *buffer, bool disableRead,
                                   bool disableWrite) {
  parcAssertNotNull(buffer, "Parameter buffer must be non-null");
  short flags = 0;
  if (disableRead) {
    flags |= PARCEventType_Read;
  }
  if (disableWrite) {
    flags |= PARCEventType_Write;
  }

  parcEventQueue_Disable(buffer, flags);
}
