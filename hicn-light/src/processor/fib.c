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

#include <src/config.h>
#include <stdio.h>

#include <src/processor/fib.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <parc/assert/parc_Assert.h>

#define NULL_POS 128
#define MSB_POS 127

struct node;
typedef struct node FibNode;

struct node {
  FibNode *left;
  FibNode *right;
  FibEntry *entry;
  unsigned pos;
};

struct fib {
  FibNode *root;
  unsigned size;
};

// =====================================================
// Public API

FibNode *_createNode(FibNode *left, FibNode *right, FibEntry *entry,
                     unsigned pos) {
  FibNode *n = parcMemory_AllocateAndClear(sizeof(FibNode));
  parcAssertNotNull(n, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FibNode));

  n->left = left;
  n->right = right;
  n->entry = entry;
  n->pos = pos;

  return n;
}

FIB *fib_Create() {
  FIB *hicnFib = parcMemory_AllocateAndClear(sizeof(FIB));
  parcAssertNotNull(hicnFib, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FIB));

  hicnFib->root =
      _createNode(NULL, NULL, NULL,
                  NULL_POS);  // the pos will decrease going down in the trie
  hicnFib->root->left = hicnFib->root;
  hicnFib->root->right = hicnFib->root;

  hicnFib->size = 0;

  return hicnFib;
}

void _destroyNode(FibNode *n) {
  fibEntry_Release(&n->entry);
  parcMemory_Deallocate((void **)&n);
  n = NULL;
}

void _destroyFib(FIB *fib) {
  // XXX
  // to be done
  return;
}

void fib_Destroy(FIB **fibPtr) {
  parcAssertNotNull(fibPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*fibPtr, "Parameter must dereference to non-null pointer");

  FIB *fib = *fibPtr;

  _destroyFib(fib);
  parcMemory_Deallocate((void **)&fib);
  *fibPtr = NULL;
}

void fib_Add(FIB *fib, FibEntry *entry) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(entry, "Parameter must be non-null");

  NameBitvector *name = name_GetContentName(fibEntry_GetPrefix(entry));

  // search the name
  FibNode *prev = fib->root;
  FibNode *curr;

  if (nameBitvector_testBit(name, MSB_POS)) {
    curr = fib->root->right;
  } else {
    curr = fib->root->left;
  }

  while (prev->pos > curr->pos) {
    prev = curr;
    if (nameBitvector_testBit(name, curr->pos)) {
      curr = curr->right;
    } else {
      curr = curr->left;
    }
  }

  if (curr->entry != NULL &&
      nameBitvector_Equals(
          name, name_GetContentName(fibEntry_GetPrefix(curr->entry)))) {
    // there is already an entry with this name
    // do nothing. Before call ADD we should check
    // if the node exists, and, in that case update it
    return;
  }

  // if the name is not in the FIB search for the first different bit between
  // the new name to add and the node found in the trie
  uint8_t pos = MSB_POS;
  if (curr->entry != NULL)
    pos = nameBitvector_firstDiff(
        name, name_GetContentName(fibEntry_GetPrefix(curr->entry)));

  // reset pointer and search the insertion point
  prev = fib->root;
  if (nameBitvector_testBit(name, MSB_POS))
    curr = fib->root->right;
  else
    curr = fib->root->left;

  while (prev->pos > curr->pos && curr->pos > pos) {
    prev = curr;
    if (nameBitvector_testBit(name, curr->pos)) {
      curr = curr->right;
    } else {
      curr = curr->left;
    }
  }

  // insert the node
  fib->size++;
  FibNode *n = _createNode(NULL, NULL, entry, pos);

  if (nameBitvector_testBit(name, pos)) {
    n->left = curr;
    n->right = n;
  } else {
    n->left = n;
    n->right = curr;
  }

  uint8_t new_pos = prev->pos;
  if (new_pos == NULL_POS) new_pos = MSB_POS;

  if (nameBitvector_testBit(name, new_pos)) {
    prev->right = n;
  } else {
    prev->left = n;
  }
}

FibEntry *fib_Contains(const FIB *fib, const Name *prefix) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(prefix, "Parameter must be non-null");

  NameBitvector *name = name_GetContentName(prefix);

  // this is the same as the first part of the add function
  // we cannnot call this function inside the add because
  // we need the pointer prev and curr for the insertion

  FibNode *prev = fib->root;
  FibNode *curr;

  if (nameBitvector_testBit(name, MSB_POS))
    curr = fib->root->right;
  else
    curr = fib->root->left;

  while (prev->pos > curr->pos) {
    prev = curr;

    if (nameBitvector_testBit(name, curr->pos)) {
      curr = curr->right;
    } else {
      curr = curr->left;
    }
  }

  if (curr->entry != NULL &&
      nameBitvector_Equals(
          name, name_GetContentName(fibEntry_GetPrefix(curr->entry)))) {
    return curr->entry;
  } else {
    return NULL;
  }
}

void _removeNode(FIB *fib, const Name *prefix) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(prefix, "Parameter must be non-null");

  FibNode *grand = NULL;  // grandparent
  FibNode *prev =
      fib->root;  // parent: it will points to curr of the next hop in the trie
  FibNode *curr;  // current node: the node to remove

  NameBitvector *name = name_GetContentName(prefix);

  if (nameBitvector_testBit(name, MSB_POS)) {
    curr = fib->root->right;
  } else {
    curr = fib->root->left;
  }

  // in the first loop we always search the node to remove
  while (prev->pos > curr->pos) {
    grand = prev;
    prev = curr;

    if (nameBitvector_testBit(name, curr->pos)) {
      curr = curr->right;
    } else {
      curr = curr->left;
    }
  }

  if (!nameBitvector_Equals(
          name, name_GetContentName(fibEntry_GetPrefix(curr->entry)))) {
    // the node does not exists
    return;
  }

  // search for the real parent of curr (*tmpPrev)
  // prev points to curr or next node in the trie
  // this is because of the loopback links

  FibNode *tmpPrev = fib->root;
  FibNode *tmpCurr;

  if (nameBitvector_testBit(name, MSB_POS)) {
    tmpCurr = fib->root->right;
  } else {
    tmpCurr = fib->root->left;
  }

  // here we compare pointer so we are sure to stop at the right potion
  while (tmpCurr != curr) {
    tmpPrev = tmpCurr;

    if (nameBitvector_testBit(name, tmpCurr->pos)) {
      tmpCurr = tmpCurr->right;
    } else {
      tmpCurr = tmpCurr->left;
    }
  }

  // now curr is the node to remove and tmpPrev is the real parent of curr

  if (curr == prev) {
    // this is the case where curr is a leaf node
    FibNode *next;  // child of curr (the loopback)

    if (nameBitvector_testBit(name, curr->pos)) {
      next = curr->left;
    } else {
      next = curr->right;
    }

    if (nameBitvector_testBit(name, tmpPrev->pos)) {
      tmpPrev->right = next;
    } else {
      tmpPrev->left = next;
    }

  } else {
    // curr is an internal node
    FibNode *next;  // child of prev (loopback)

    if (nameBitvector_testBit(name, prev->pos)) {
      next = prev->left;
    } else {
      next = prev->right;
    }

    if (nameBitvector_testBit(name, grand->pos)) {
      grand->right = next;
    } else {
      grand->left = next;
    }

    if (nameBitvector_testBit(name, tmpPrev->pos)) {
      tmpPrev->right = prev;
    } else {
      tmpPrev->left = prev;
    }

    prev->left = curr->left;
    prev->right = curr->right;
    prev->pos = curr->pos;
  }

  fib->size--;
  _destroyNode(curr);
}

void fib_Remove(FIB *fib, const Name *name, unsigned connId) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(name, "Parameter must be non-null");

  FibEntry *entry = fib_Contains(fib, name);

  if (entry == NULL) {
    return;
  }

  fibEntry_RemoveNexthopByConnectionId(entry, connId);
  if (fibEntry_NexthopCount(entry) == 0) {
    _removeNode(fib, name);
  }
}

void _removeConnectionId(FibNode *n, unsigned pos, unsigned connectionId,
                         FibEntryList *list) {
  if (n->pos < pos) {
    fibEntry_RemoveNexthopByConnectionId(n->entry, connectionId);
    if (fibEntry_NexthopCount(n->entry) == 0) {
      fibEntryList_Append(list, n->entry);
    }
    _removeConnectionId(n->left, n->pos, connectionId, list);
    _removeConnectionId(n->right, n->pos, connectionId, list);
  }
}

void fib_RemoveConnectionId(FIB *fib, unsigned connectionId) {
  parcAssertNotNull(fib, "Parameter must be non-null");

  // 1 - we vist the tree to remove the connection id
  // 2 - during the visit we collect the fib entry with 0 nexthop
  // 3 - after the visit we remove this entries

  FibEntryList *list = fibEntryList_Create();

  _removeConnectionId(fib->root->left, fib->root->pos, connectionId, list);
  _removeConnectionId(fib->root->right, fib->root->pos, connectionId, list);

  for (int i = 0; i < fibEntryList_Length(list); i++) {
    _removeNode(fib, fibEntry_GetPrefix(fibEntryList_Get(list, i)));
  }

  fibEntryList_Destroy(&list);
}

size_t fib_Length(const FIB *fib) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  return fib->size;
}

FibEntry *fib_Match(const FIB *fib, const Message *interestMessage) {
  parcAssertNotNull(fib, "Parameter must be non-null");
  parcAssertNotNull(interestMessage, "Parameter must be non-null");

  NameBitvector *name = name_GetContentName(message_GetName(interestMessage));

  FibNode *prev = fib->root;
  FibNode *curr;

  FibNode *match = NULL;
  unsigned len = 0;

  if (nameBitvector_testBit(name, MSB_POS))
    curr = fib->root->right;
  else
    curr = fib->root->left;

  while (prev->pos > curr->pos) {
    prev = curr;

    if (curr->entry != NULL) {
      if (nameBitvector_StartsWith(
              name, name_GetContentName(fibEntry_GetPrefix(curr->entry))) &&
          nameBitvector_GetLength(
              name_GetContentName(fibEntry_GetPrefix(curr->entry))) > len) {
        match = curr;
        len = nameBitvector_GetLength(
            name_GetContentName(fibEntry_GetPrefix(curr->entry)));
      }
    }

    if (nameBitvector_testBit(name, curr->pos))
      curr = curr->right;
    else
      curr = curr->left;
  }

  if (curr->entry != NULL) {
    if (nameBitvector_StartsWith(
            name, name_GetContentName(fibEntry_GetPrefix(curr->entry))) &&
        nameBitvector_GetLength(
            name_GetContentName(fibEntry_GetPrefix(curr->entry))) > len) {
      match = curr;
      len = nameBitvector_GetLength(
          name_GetContentName(fibEntry_GetPrefix(curr->entry)));
    }
  }

  if (match != NULL && match->entry != NULL) {
    return match->entry;
  } else {
    return NULL;
  }
}

void _collectFibEntries(FibNode *n, int pos, FibEntryList *list) {
  if (n->pos < (unsigned)pos) {
    fibEntryList_Append(list, n->entry);
    _collectFibEntries(n->left, n->pos, list);
    _collectFibEntries(n->right, n->pos, list);
  }
}

FibEntryList *fib_GetEntries(const FIB *fib) {
  parcAssertNotNull(fib, "Parameter must be non-null");

  FibEntryList *list = fibEntryList_Create();

  _collectFibEntries(fib->root->left, fib->root->pos, list);
  _collectFibEntries(fib->root->right, fib->root->pos, list);

  return list;
}
