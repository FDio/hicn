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
#include <hicn/utils/utils.h>

//// This is the unique sequence number used by all messages and its thread locks
//static pthread_mutex_t nextSequenceNumberMutex = PTHREAD_MUTEX_INITIALIZER;
//static uint32_t nextSequenceNumber = 1;
//
//uint32_t utils_GetNextSequenceNumber(void) {
//  uint32_t seqnum;
//
//  int result = pthread_mutex_lock(&nextSequenceNumberMutex);
//  parcAssertTrue(result == 0, "Got error from pthread_mutex_lock: %d", result);
//
//  seqnum = nextSequenceNumber++;
//
//  result = pthread_mutex_unlock(&nextSequenceNumberMutex);
//  parcAssertTrue(result == 0, "Got error from pthread_mutex_unlock: %d",
//                 result);
//
//  return seqnum;
//}

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

///**
// * A symbolic name must be at least 1 character and must begin with an alpha.
// * The remainder must be an alphanum.
// */
//bool utils_ValidateSymbolicName(const char *symbolic) {
//  bool success = false;
//  size_t len = strlen(symbolic);
//  if (len > 0) {
//    if (isalpha(symbolic[0])) {
//      success = true;
//      for (size_t i = 1; i < len; i++) {
//        if (!isalnum(symbolic[i])) {
//          success = false;
//          break;
//        }
//      }
//    }
//  }
//  return success;
//}
//
//char *utils_BuildStringFromInet(in_addr_t *addr4, in_port_t *port) {
//  struct sockaddr_in addr;
//  memset(&addr, 0, sizeof(addr));
//  addr.sin_family = AF_INET;
//  addr.sin_port = *port;
//  addr.sin_addr.s_addr = *addr4;
//
//  PARCBufferComposer *composer = parcBufferComposer_Create();
//  PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
//      parcNetwork_SockInet4Address_BuildString(&addr, composer));
//  char *result = parcBuffer_ToString(tempBuffer);
//  parcBuffer_Release(&tempBuffer);
//  parcBufferComposer_Release(&composer);
//  return result;
//}
//
//char *utils_BuildStringFromInet6(struct in6_addr *addr6, in_port_t *port) {
//  struct sockaddr_in6 addr;
//  memset(&addr, 0, sizeof(addr));
//  addr.sin6_family = AF_INET6;
//  addr.sin6_port = *port;
//  addr.sin6_addr = *addr6;
//
//  PARCBufferComposer *composer = parcBufferComposer_Create();
//  PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
//      parcNetwork_SockInet6Address_BuildString(&addr, composer));
//char *result = parcBuffer_ToString(tempBuffer);
//parcBuffer_Release(&tempBuffer);
//parcBufferComposer_Release(&composer);
//return result;
//}
//
//char *
//utils_CommandAddressToString(int family, ip_address_t *address, in_port_t *port)
//{
//  char *result, *addrStr;
//  switch (family) {
//    case AF_INET:
//      result = utils_BuildStringFromInet(&address->v4.as_u32, port);
//      break;
//
//    case AF_INET6:
//      result = utils_BuildStringFromInet6(&address->v6.as_in6addr, port);
//      break;
//
//    default:
//      addrStr = (char *)parcMemory_Allocate(sizeof(char) * 32);
//      snprintf(addrStr, 32, "Error: UNKNOWN family = %d", family);
//      result = addrStr;
//      break;
//  }
//  return result;
//}
//
//struct iovec *utils_SendRequest(ControlState *state, command_type_t command,
//                            void *payload, size_t payloadLen) {
//bool success = false;
//
//// get sequence number for the header
//uint32_t currentSeqNum = utils_GetNextSequenceNumber();
//
//// Allocate and fill the header
//header_control_message *headerControlMessage =
//  parcMemory_AllocateAndClear(sizeof(header_control_message));
//headerControlMessage->messageType = REQUEST_LIGHT;
//headerControlMessage->commandID = command;
//headerControlMessage->seqNum = currentSeqNum;
//if (payloadLen > 0) {
//headerControlMessage->length = 1;
//}
//
//struct iovec msg[2];
//msg[0].iov_base = headerControlMessage;
//msg[0].iov_len = sizeof(header_control_message);
//msg[1].iov_base = payload;
//msg[1].iov_len = payloadLen;
//
//struct iovec *response = controlState_WriteRead(state, msg);
//
//header_control_message *receivedHeader =
//  (header_control_message *)response[0].iov_base;
//if (receivedHeader->seqNum != currentSeqNum) {
//printf("Seq number is NOT correct: expected %d got %d  \n", currentSeqNum,
//       receivedHeader->seqNum);
//// failure
//} else {
//if (receivedHeader->messageType == RESPONSE_LIGHT) {
//  return response;  // command needs both payload and header
//} else {
//  if (receivedHeader->messageType == ACK_LIGHT) {
//    success = true;
//  } else if (receivedHeader->messageType == NACK_LIGHT) {
//    success = true;
//  } else {
//    printf("Error: unrecognized message type");  // failure
//  }
//}
//}
//
//// deallocate when payload & header of the response are not needed
//if (receivedHeader->length > 0) {
//parcMemory_Deallocate(&response[1].iov_base);  // free received payload
//}
//parcMemory_Deallocate(&response[0].iov_base);  // free receivedHeader
//
//// return response
//if (success) {
//return response;
//} else {
//parcMemory_Deallocate(&response);  // free iovec pointer
//return NULL;                       // will generate a failure
//}
//}
