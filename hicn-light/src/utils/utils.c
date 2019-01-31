// Utility function for commands

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>
#include <pthread.h>
#include <src/utils/utils.h>

// This is the unique sequence number used by all messages and its thread locks
static pthread_mutex_t nextSequenceNumberMutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t nextSequenceNumber = 1;

uint32_t utils_GetNextSequenceNumber(void) {
  uint32_t seqnum;

  int result = pthread_mutex_lock(&nextSequenceNumberMutex);
  parcAssertTrue(result == 0, "Got error from pthread_mutex_lock: %d", result);

  seqnum = nextSequenceNumber++;

  result = pthread_mutex_unlock(&nextSequenceNumberMutex);
  parcAssertTrue(result == 0, "Got error from pthread_mutex_unlock: %d",
                 result);

  return seqnum;
}

/**
 * Return true if string is purely an integer
 */
bool utils_IsNumber(const char *string) {
  size_t len = strlen(string);
  for (size_t i = 0; i < len; i++) {
    if (!isdigit(string[i])) {
      return false;
    }
  }
  return true;
}

/**
 * A symbolic name must be at least 1 character and must begin with an alpha.
 * The remainder must be an alphanum.
 */
bool utils_ValidateSymbolicName(const char *symbolic) {
  bool success = false;
  size_t len = strlen(symbolic);
  if (len > 0) {
    if (isalpha(symbolic[0])) {
      success = true;
      for (size_t i = 1; i < len; i++) {
        if (!isalnum(symbolic[i])) {
          success = false;
          break;
        }
      }
    }
  }
  return success;
}

Address *utils_AddressFromInet(in_addr_t *addr4, in_port_t *port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = *port;
  addr.sin_addr.s_addr = *addr4;

  Address *result = addressCreateFromInet(&addr);
  return result;
}

Address *utils_AddressFromInet6(struct in6_addr *addr6, in_port_t *port) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = *port;
  addr.sin6_addr = *addr6;
  addr.sin6_scope_id = 0;
  // Other 2 fields: scope_id and flowinfo, do not know what to put inside.

  Address *result = addressCreateFromInet6(&addr);
  return result;
}

struct iovec *utils_CreateAck(header_control_message *header, void *payload,
                              size_t payloadLen) {
  struct iovec *response =
      parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

  header->messageType = ACK_LIGHT;

  response[0].iov_base = header;
  response[0].iov_len = sizeof(header_control_message);
  response[1].iov_base = payload;
  response[1].iov_len = payloadLen;

  return response;
}

struct iovec *utils_CreateNack(header_control_message *header, void *payload,
                               size_t payloadLen) {
  struct iovec *response =
      parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

  header->messageType = NACK_LIGHT;

  response[0].iov_base = header;
  response[0].iov_len = sizeof(header_control_message);
  response[1].iov_base = payload;
  response[1].iov_len = payloadLen;

  return response;
}

char *utils_BuildStringFromInet(in_addr_t *addr4, in_port_t *port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = *port;
  addr.sin_addr.s_addr = *addr4;

  PARCBufferComposer *composer = parcBufferComposer_Create();
  PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
      parcNetwork_SockInet4Address_BuildString(&addr, composer));
  char *result = parcBuffer_ToString(tempBuffer);
  parcBuffer_Release(&tempBuffer);
  parcBufferComposer_Release(&composer);
  return result;
}

char *utils_BuildStringFromInet6(struct in6_addr *addr6, in_port_t *port) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = *port;
  addr.sin6_addr = *addr6;

  PARCBufferComposer *composer = parcBufferComposer_Create();
  PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
      parcNetwork_SockInet6Address_BuildString(&addr, composer));
  char *result = parcBuffer_ToString(tempBuffer);
  parcBuffer_Release(&tempBuffer);
  parcBufferComposer_Release(&composer);
  return result;
}

char *utils_CommandAddressToString(address_type addressType,
                                   union commandAddr *address,
                                   in_port_t *port) {
  char *result;

  switch (addressType) {
    case ADDR_INET: {
      result = utils_BuildStringFromInet(&address->ipv4, port);
      break;
    }

    case ADDR_INET6: {
      result = utils_BuildStringFromInet6(&address->ipv6, port);
      break;
    }

    default: {
      char *addrStr = (char *)parcMemory_Allocate(sizeof(char) * 32);
      sprintf(addrStr, "Error: UNKNOWN address type = %d", addressType);
      result = addrStr;
      break;
    }
  }
  return result;
}

struct iovec *utils_SendRequest(ControlState *state, command_id command,
                                void *payload, size_t payloadLen) {
  bool success = false;

  // get sequence number for the header
  uint32_t currentSeqNum = utils_GetNextSequenceNumber();

  // Allocate and fill the header
  header_control_message *headerControlMessage =
      parcMemory_AllocateAndClear(sizeof(header_control_message));
  headerControlMessage->messageType = REQUEST_LIGHT;
  headerControlMessage->commandID = command;
  headerControlMessage->seqNum = currentSeqNum;
  if (payloadLen > 0) {
    headerControlMessage->length = 1;
  }

  struct iovec msg[2];
  msg[0].iov_base = headerControlMessage;
  msg[0].iov_len = sizeof(header_control_message);
  msg[1].iov_base = payload;
  msg[1].iov_len = payloadLen;

  struct iovec *response = controlState_WriteRead(state, msg);

  header_control_message *receivedHeader =
      (header_control_message *)response[0].iov_base;
  if (receivedHeader->seqNum != currentSeqNum) {
    printf("Seq number is NOT correct: expected %d got %d  \n", currentSeqNum,
           receivedHeader->seqNum);
    // failure
  } else {
    if (receivedHeader->messageType == RESPONSE_LIGHT) {
      return response;  // command needs both payload and header
    } else {
      if (receivedHeader->messageType == ACK_LIGHT) {
        success = true;
      } else if (receivedHeader->messageType == NACK_LIGHT) {
        success = true;
      } else {
        printf("Error: unrecognized message type");  // failure
      }
    }
  }

  // deallocate when payload & header of the response are not needed
  if (receivedHeader->length > 0) {
    parcMemory_Deallocate(&response[1].iov_base);  // free received payload
  }
  parcMemory_Deallocate(&response[0].iov_base);  // free receivedHeader

  // return response
  if (success) {
    return response;
  } else {
    parcMemory_Deallocate(&response);  // free iovec pointer
    return NULL;                       // will generate a failure
  }
}

const char *utils_PrefixLenToString(address_type addressType,
                                    union commandAddr *address,
                                    uint8_t *prefixLen) {
  char len[4];  // max size + 1
  sprintf(len, "%u", (unsigned)*prefixLen);
  in_port_t port = htons(1234);  // this is a random port number that is ignored

  char *prefix = utils_CommandAddressToString(addressType, address, &port);
  char *prefixStr = malloc(strlen(prefix) + strlen(len) + 2);
  strcpy(prefixStr, prefix);
  strcat(prefixStr, "/");
  strcat(prefixStr, len);

  free(prefix);

  return prefixStr;
}
