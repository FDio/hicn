/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * @file tlock.h
 * @brief This file contains ticket lock APIs.
 */

#ifndef __TLOCK_H__
#define __TLOCK_H__


/**

 * @brief limit the number of locks: it shoud be matched with the
 * number of hicn-state leaves
 */
#define MAX_LOCK_SIZE  5

/**
 * @brief Ticket lock counters
 */
volatile long int  En[MAX_LOCK_SIZE] ;

/**
 * @brief Ticket lock counters
 */
volatile long int De[MAX_LOCK_SIZE] ;


/**
 * @brief This function initialize the ticket lock
 * @param Lock_Number describes the number of locks need to be initialized
 * @param init describes the init number
 */
void ticket_init ( int Lock_Number , long int init );
/**
 * @brief this function acquire the lock
 * Description of what the function does. This part may refer to the parameters
 * @param Lock_Number pass the lock
 */
void tlock(int Lock_Number );
/**
 * @briefthis function release the lock
 * @param Lock_Number lock number

 */
void tunlock(int Lock_Number );

#endif /* __IETF_HICN_H__ */