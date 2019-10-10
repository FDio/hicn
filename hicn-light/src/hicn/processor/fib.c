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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/core/forwarder.h>
#include <hicn/processor/fib.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <parc/assert/parc_Assert.h>

struct node;
typedef struct node FibNode;

struct node {
  FibNode *left;
  FibNode *right;
  FibEntry *entry;
  bool is_used;
};

struct fib {
  Forwarder *forwarder;
  FibNode *root;
  unsigned size;
};

// =====================================================
// Public API

FibNode *_createNode(FibNode *left, FibNode *right, FibEntry *entry,
                     bool is_used) {
  FibNode *n = parcMemory_AllocateAndClear(sizeof(FibNode));
  parcAssertNotNull(n, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FibNode));

  n->left = left;
  n->right = right;
  n->entry = entry;
  n->is_used = is_used;

  return n;
}

FIB *fib_Create(Forwarder *forwarder) {
  FIB *hicnFib = parcMemory_AllocateAndClear(sizeof(FIB));
  parcAssertNotNull(hicnFib, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FIB));

  hicnFib->forwarder = forwarder;
  hicnFib->root = NULL;
  hicnFib->size = 0;

  return hicnFib;
}

void _destroyNode(FibNode *n) {
  fibEntry_Release(&n->entry);
  parcMemory_Deallocate((void **)&n);
  n = NULL;
}

void _destroyFib(FibNode *n) {
  if(n != NULL){
    _destroyFib(n->right);
    _destroyFib(n->left);
    _destroyNode(n);
  }
}

void fib_Destroy(FIB **fibPtr) {
  parcAssertNotNull(fibPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*fibPtr, "Parameter must dereference to non-null pointer");

  FIB *fib = *fibPtr;
  _destroyFib(fib->root);

  parcMemory_Deallocate((void **)&fib);
  *fibPtr = NULL;
}

void fib_Add(FIB *fib, FibEntry *entry) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(entry, "Parameter must be non-null");

  NameBitvector *new_prefix = name_GetContentName(fibEntry_GetPrefix(entry));
  uint32_t new_prefix_len = nameBitvector_GetLength(new_prefix);
  FibNode * curr =  fib->root;
  FibNode * last =  NULL;

  NameBitvector *curr_name;
  uint32_t curr_prefix_len;
  uint32_t match_len;

  while(curr != NULL){
    curr_name = name_GetContentName(fibEntry_GetPrefix(curr->entry));

    match_len =  nameBitvector_lpm(new_prefix, curr_name);
    curr_prefix_len = nameBitvector_GetLength(curr_name);

    if(curr_prefix_len != match_len || //the new entry does not match the curr
        curr_prefix_len >= new_prefix_len) //in this case we cannot procede anymore
          break;

    last = curr;
    bool bit;
    int res = nameBitvector_testBit(new_prefix, curr_prefix_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (fib_add)");
    if(bit)
      curr = curr->right;
    else
      curr = curr->left;
  }

  //this is the root (empty trie) or an empty child
  if(curr == NULL){
    FibNode * new_node = _createNode(NULL, NULL, entry, true);
    if(last == NULL){
      fib->root =  new_node;
    }else{
      uint32_t last_prefix_len = nameBitvector_GetLength(
                      name_GetContentName(fibEntry_GetPrefix(last->entry)));
      bool bit;
      int res = nameBitvector_testBit(new_prefix, last_prefix_len, &bit);
      parcAssertFalse(res < 0, "error testing name bit (fib_add)");
      if(bit)
        last->right = new_node;
      else
        last->left = new_node;
    }
    fib->size++;
    return;
  }

  //curr is not null

  //the node already exist
  //if is not in use we turn it on and we set the rigth fib entry
  if(curr_prefix_len == match_len && new_prefix_len == match_len){
    if(!curr->is_used){
      curr->is_used = true;
      curr->entry = entry;
      fib->size++;
      return;
    }else{
      //this case should never happen beacuse of the way we add
      //entries in the fib
      const NumberSet * next_hops = fibEntry_GetNexthops(entry);
      unsigned size = (unsigned)fibEntry_NexthopCount(entry);
      for(unsigned i = 0; i < size; i++)
        fibEntry_AddNexthop(curr->entry,numberSet_GetItem(next_hops, i));
    }
  }

  //key is prefix of the curr node (so new_prefix_len < curr_prefix_len)
  if(new_prefix_len == match_len){
    FibNode * new_node = _createNode(NULL, NULL, entry, true);
    if(last == NULL){
      fib->root = new_node;
    }else{
      uint32_t last_prefix_len = nameBitvector_GetLength(
                      name_GetContentName(fibEntry_GetPrefix(last->entry)));

      bool bit;
      int res = nameBitvector_testBit(new_prefix, last_prefix_len, &bit);
      parcAssertFalse(res < 0, "error testing name bit (fib_add)");
      if(bit)
        last->right =  new_node;
      else
        last->left = new_node;
    }
    bool bit;
    int res = nameBitvector_testBit(curr_name, match_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (fib_add)");
    if(bit)
      new_node->right = curr;
    else
      new_node->left = curr;
    fib->size++;
    return;
  }

  //in the last case we need to add an inner node
  Name * inner_prefix = name_Copy(fibEntry_GetPrefix(entry));
  nameBitvector_clear(name_GetContentName(inner_prefix), match_len);
  name_setLen(inner_prefix,  match_len);

  FibEntry * inner_entry = fibEntry_Create(inner_prefix, SET_STRATEGY_LOADBALANCER,
            fib->forwarder);

  FibNode * inner_node = _createNode(NULL, NULL, inner_entry, false);
  FibNode * new_node = _createNode(NULL, NULL, entry, true);

  if(last == NULL){
    //we need to place the inner_node at the root
    fib->root = inner_node;
  }else{
    uint32_t last_prefix_len = nameBitvector_GetLength(
                      name_GetContentName(fibEntry_GetPrefix(last->entry)));
    bool bit;
    int res = nameBitvector_testBit(name_GetContentName(inner_prefix),
                                                last_prefix_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (fib_add)");
    if(bit)
      last->right =  inner_node;
    else
      last->left = inner_node;
  }

  bool bit;
  int res = nameBitvector_testBit(new_prefix, match_len, &bit);
  parcAssertFalse(res < 0, "error testing name bit (fib_add)");

  if(bit){
    inner_node -> left = curr;
    inner_node ->right = new_node;
  }else{
    inner_node -> left = new_node;
    inner_node ->right = curr;
  }
  fib->size ++;
}

FibEntry *fib_Contains(const FIB *fib, const Name *prefix) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(prefix, "Parameter must be non-null");

  NameBitvector *key_name = name_GetContentName(prefix);
  uint32_t key_prefix_len = nameBitvector_GetLength(key_name);

  FibNode * curr = fib->root;

  while(curr != NULL){
    NameBitvector *curr_name =
          name_GetContentName(fibEntry_GetPrefix(curr->entry));
    uint32_t match_len = nameBitvector_lpm(key_name, curr_name);
    uint32_t curr_prefix_len = nameBitvector_GetLength(curr_name);

    if(match_len < curr_prefix_len){
      //the current node does not match completelly the key, so
      //the key is not in the trie
      //this implies curr_prefix_len > key_prefix_len
      return NULL;
    }

    if(curr_prefix_len == key_prefix_len){ //== match_len
        //this is an exact match
        if(curr->is_used){
          //we found the key
          return curr->entry;
        }else{
          //the key does not exists
          return NULL;
        }
    }

    bool bit;
    int res = nameBitvector_testBit(key_name, curr_prefix_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (fib_contains)");

    if(bit)
      curr = curr->right;
    else
      curr = curr->left;
  }

  return NULL;
}

void _removeNode(FIB *fib, const Name *prefix){
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(prefix, "Parameter must be non-null");

  NameBitvector *key_name = name_GetContentName(prefix);
  uint32_t key_prefix_len = nameBitvector_GetLength(key_name);

  FibNode * curr = fib->root;
  FibNode * parent = NULL;
  FibNode * grandpa = NULL;

  uint32_t match_len;
  uint32_t curr_prefix_len;
  while(curr != NULL){
    NameBitvector *curr_name =
          name_GetContentName(fibEntry_GetPrefix(curr->entry));
    match_len = nameBitvector_lpm(key_name, curr_name);
    curr_prefix_len = nameBitvector_GetLength(curr_name);

    if(match_len < curr_prefix_len ||
        curr_prefix_len == key_prefix_len){
      break;
    }

    grandpa = parent;
    parent = curr;

    bool bit;
    int res = nameBitvector_testBit(key_name, curr_prefix_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (_removeNode)");

    if(bit)
      curr = curr->right;
    else
      curr = curr->left;
  }

  if(curr == NULL ||
     !curr->is_used ||
     (curr_prefix_len != key_prefix_len)){
     //the node does not exists
    return;
  }

  //curr has 2 children, leave it there and mark it as inner
  if(curr->right != NULL && curr->left != NULL){
    curr->is_used = false;
    fib->size--;
    return;
  }

  //curr has no children
  if(curr->right == NULL && curr->left == NULL){
    if (parent == NULL){
      //curr is the root and is the only node in the fib
      fib->root = NULL;
      fib->size--;
      _destroyNode(curr);
      return;
    }
    if(grandpa == NULL){
      //parent is the root
      if(fib->root->left == curr)
        fib->root->left = NULL;
      else
        fib->root->right = NULL;
      fib->size--;
      _destroyNode(curr);
      return;
    }
    if(!parent->is_used){
      //parent is an inner node
      //remove curr and inner_node (parent), connect the other child
      //of the parent to the grandpa
      FibNode * tmp;
      if(parent->right == curr)
        tmp = parent->left;
      else
        tmp = parent->right;

      if(grandpa->right == parent)
        grandpa->right = tmp;
      else
        grandpa->left = tmp;

      fib->size--;
      _destroyNode(curr);
      _destroyNode(parent);
      return;
    }
    //parent is node not an inner_node
    //just remove curr the node
    if(parent->right == curr)
      parent->right = NULL;
    else
       parent->left = NULL;
    fib->size--;
    _destroyNode(curr);
    return;
  }

  //curr has one child
  if(curr->right != NULL || curr->left != NULL){
    if(parent == NULL){
      //curr is the root
      if(fib->root->right != NULL)
        fib->root = fib->root->right;
      else
        fib->root = fib->root->left;
      fib->size--;
      _destroyNode(curr);
      return;
    }
    //attach the child of curr to parent
    FibNode * tmp;
    if(curr->right != NULL)
      tmp = curr->right;
    else
      tmp = curr->left;

    if(parent->right == curr)
      parent->right = tmp;
    else
      parent->left = tmp;

    fib->size--;
    _destroyNode(curr);
    return;
  }
}

void fib_Remove(FIB *fib, const Name *name, unsigned connId) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(name, "Parameter must be non-null");

  FibEntry *entry = fib_Contains(fib, name);

  if (entry == NULL) {
    return;
  }

  fibEntry_RemoveNexthopByConnectionId(entry, connId);
  if (fibEntry_NexthopCount(entry) == 0)
    _removeNode(fib, name);

}

void _removeConnectionId(FibNode *n, unsigned connectionId,
                         FibEntryList *list) {
  if(n != NULL){
    if(n->is_used){
      fibEntry_RemoveNexthopByConnectionId(n->entry, connectionId);
      if (fibEntry_NexthopCount(n->entry) == 0) {
        fibEntryList_Append(list, n->entry);
      }
    }
    _removeConnectionId(n->right, connectionId, list);
    _removeConnectionId(n->left, connectionId, list);
  }
}

void fib_RemoveConnectionId(FIB *fib, unsigned connectionId) {
  parcAssertNotNull(fib, "Parameter must be non-null");

   FibEntryList *list = fibEntryList_Create();
   _removeConnectionId(fib->root, connectionId, list);

  for (int i = 0; i < fibEntryList_Length(list); i++) {
    _removeNode(fib, fibEntry_GetPrefix(fibEntryList_Get(list, i)));
  }

  fibEntryList_Destroy(&list);
}

size_t fib_Length(const FIB *fib) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  return fib->size;
}

FibEntry *fib_MatchMessage(const FIB *fib, const Message *interestMessage) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(interestMessage, "Parameter must be non-null");
  return fib_MatchBitvector(fib, name_GetContentName(
                  message_GetName(interestMessage)));
}

FibEntry *fib_MatchName(const FIB *fib, const Name *name) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(name, "Parameter must be non-null");
  return fib_MatchBitvector(fib, name_GetContentName(name));
}


FibEntry *fib_MatchBitvector(const FIB *fib, const NameBitvector *name){
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(name, "Parameter must be non-null");

  uint32_t key_prefix_len = nameBitvector_GetLength(name);

  FibNode * curr = fib->root;
  FibNode * candidate = NULL;

  while(curr != NULL){
    NameBitvector *curr_name =
          name_GetContentName(fibEntry_GetPrefix(curr->entry));
    uint32_t match_len = nameBitvector_lpm(name, curr_name);
    uint32_t curr_prefix_len = nameBitvector_GetLength(curr_name);

    if(match_len < curr_prefix_len){
      //the current node does not match completelly the key, so
      //return the parent of this node (saved in candidate)
      break;
    }

    if(curr->is_used)
      candidate = curr;

    //if we are here match_len == curr_prefix_len (can't be larger)
    //so this node is actually a good candidate for a match
    if(curr_prefix_len == key_prefix_len){
      //this an exact match, do not continue
      break;
    }

    bool bit;
    int res = nameBitvector_testBit(name, curr_prefix_len, &bit);
    parcAssertFalse(res < 0, "error testing name bit (fib_MatchBitvector)");

    if(bit)
      curr = curr->right;
    else
      curr = curr->left;
  }

  if(candidate != NULL){
    return candidate->entry;
  }

  return NULL;
}

void _collectFibEntries(FibNode *n, FibEntryList *list){
  if(n != NULL){
    if(n->is_used)
      fibEntryList_Append(list, n->entry);
    _collectFibEntries(n->right, list);
    _collectFibEntries(n->left, list);
  }
}

FibEntryList *fib_GetEntries(const FIB *fib) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  FibEntryList *list = fibEntryList_Create();

  _collectFibEntries(fib->root, list);

  return list;
}
