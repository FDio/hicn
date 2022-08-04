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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/core/fib.h>

typedef struct fib_node_s {
  struct fib_node_s *child[2]; /* 0: left, 1: right */
  fib_entry_t *entry;
  bool is_used;
} fib_node_t;

#define ZERO 0
#define ONE 1

static fib_node_t *fib_node_create(fib_node_t *left, fib_node_t *right,
                                   fib_entry_t *entry, bool is_used) {
  fib_node_t *node = malloc(sizeof(fib_node_t));
  if (!node) return NULL;

  *node = (fib_node_t){
      .child = {left, right},
      .entry = entry,
      .is_used = is_used,
  };

  return node;
}

static void fib_node_free(fib_node_t *node) {
  if (!node) return;

  fib_node_free(node->child[ZERO]);
  fib_node_free(node->child[ONE]);

  fib_entry_free(node->entry);
  free(node);
}

/******************************************************************************/

struct fib_s {
  void *forwarder;
  fib_node_t *root;
  unsigned size;
};

fib_t *fib_create(void *forwarder) {
  fib_t *fib = malloc(sizeof(fib_t));
  if (!fib) return NULL;

  fib->forwarder = forwarder;
  fib->root = NULL;
  fib->size = 0;

  return fib;
}

void fib_free(fib_t *fib) {
  assert(fib);

  fib_node_free(fib->root);

  free(fib);
}

size_t fib_get_size(const fib_t *fib) {
  assert(fib);
  return fib->size;
}

/*
 * This struct will hold various information related to the returned node such
 * as its parent and grandparent if any, as well as some already computed
 * information about the prefix.
 */
typedef struct {
  /* Result node ancestors (NULL if not applicable) */
  fib_node_t *parent;
  fib_node_t *gparent;
  /* Information related to the result node */
  hicn_prefix_t *prefix;
  uint32_t prefix_len;
  uint32_t match_len;
} fib_search_t;
/*
 * @brief Search for longest subprefix (helper function)
 * @param [in] fib - Pointer to the FIB to search
 * @param [in] prefix - The prefix used for search
 * @param [out] search - A pointer to a structure that will hold related search
 * information, that can be NULL if this is not needed.
 *
 * @returns The node whose entry corresponds to the longest subprefix of the
 * prefix passed in parameter, or NULL if not found. The longest prefix match is
 * thus the resulting node if curr_len == prefix_len, and its parent
 * otherwise.
 *
 * Implementation details:
 *
 * This function performs a descent in the tree, following branches
 * corresponding to the value of the next bit, until reaching past a leaf, or
 * either the current node prefix:
 * when one of the two following conditions is met:
 * - is not a prefix of the searched one (match_len < curr_len), or
 * - is longer or equal than the inserted one (curr_len >= prefix_len)
 */
fib_node_t *fib_search(const fib_t *fib, const hicn_prefix_t *prefix,
                       fib_search_t *search) {
  uint32_t prefix_len = hicn_prefix_get_len(prefix);
  uint32_t curr_len;
  uint32_t match_len;

  fib_node_t *parent = NULL;
  fib_node_t *gparent = NULL;
  fib_node_t *curr = fib->root;
  while (curr) {
    const hicn_prefix_t *curr_prefix = fib_entry_get_prefix(curr->entry);
    curr_len = hicn_prefix_get_len(curr_prefix);
    match_len = hicn_prefix_lpm(prefix, curr_prefix);

    // XXX >= vs == for the second stop condition
    // curr_len >= prefix_len l >= L
    // L is a prefix of l
    // > means we did not find
    // = means we could have found
    //  leverage this info for contains!
    // XXX remove this comment when done
    if (match_len < curr_len || curr_len >= prefix_len) break;

    gparent = parent;
    parent = curr;

    /* The following lookup won't fail since curr_len < prefix_len */
    uint8_t next_bit = hicn_prefix_get_bit(prefix, curr_len);
    curr = curr->child[next_bit];
  }

  if (search) {
    search->parent = parent;
    search->gparent = gparent;
    if (curr) {
      search->prefix_len = curr_len;
      search->match_len = match_len;
    }
  }
  return curr;
}

/*
 * Helper: insert a new node between parent and child.
 *
 * parent == NULL means we set the root of the FIB
 * child == NULL means our node has no child
 */
fib_node_t *_fib_insert(fib_t *fib, fib_entry_t *entry, fib_node_t *parent,
                        fib_node_t *child, bool is_used) {
  fib_node_t *new_node = fib_node_create(NULL, NULL, entry, is_used);
  const hicn_prefix_t *prefix = fib_entry_get_prefix(entry);

  if (!parent) {
    fib->root = new_node;
  } else {
    const hicn_prefix_t *parent_prefix = fib_entry_get_prefix(parent->entry);
    uint32_t parent_prefix_len = hicn_prefix_get_len(parent_prefix);
    uint8_t next_bit = hicn_prefix_get_bit(prefix, parent_prefix_len);
    parent->child[next_bit] = new_node;
  }

  if (child) {
    const hicn_prefix_t *curr_prefix = fib_entry_get_prefix(entry);
    uint32_t match_len = hicn_prefix_lpm(prefix, curr_prefix);
    uint8_t next_bit = hicn_prefix_get_bit(curr_prefix, match_len);
    new_node->child[next_bit] = child;
  }

  if (is_used) fib->size++;
  return new_node;
}

/*
 * Helper: remove a node from parent
 */
void _fib_remove(fib_t *fib, fib_node_t *curr, fib_node_t *parent) {
  /*
   * If we remove the node, curr has either 0 or 1 child. In the latter case,
   * we attach it to parent
   */
  fib_node_t *child = curr->child[ZERO] ? curr->child[ZERO] : curr->child[ONE];
  if (!parent) {
    fib->root = child;
  } else {
    if (parent->child[ZERO] == curr)
      parent->child[ZERO] = child;
    else
      parent->child[ONE] = child;
  }
  if (curr->is_used) fib->size--;
  fib_node_free(curr);
}

/*
 * - Stop condition: curr == NULL. This corresponds to:
 *
 *   (CASE 1) Our parent is a strict prefix and we simply have to create a new
 *   leaf child in the correct branch based on the next bit following the parent
 *   prefix.
 *
 *   Otherwise, our parent node exist. Based on the stop condition, we
 *   either have:
 *
 * - Stop condition 1 : curr_len == match_len AND curr_len >=
 *   prefix_len l == m && l >= L
 *
 *    2 sub-cases:
 *      - l = m > L : IMPOSSIBLE L < m since m = LPM(l, L) means L >= m
 *      - l = m = L : insert the current node, either it exists or not
 *
 *    We thus have:
 *
 *    (CASE 2) The node already exist. If is not in use we turn it on and we set
 *    the right fib entry.
 *
 *    The case when it is used should never occur because of the way we add
 *    entries in the FIB... but let's add the nexthops we wish to insert into
 *    the existing FIB entry.
 *
 * - Stop condition 2: curr_len != match_len
 *   l != m => l > m
 *
 *   We have two possibilities:
 *     - Only one is bigger than m (case 3)
 *     - They are both bigger than m (case 4)
 *
 *    (CASE 3) Only one is bigger than m
 *    L == m => L < l (since l != m and l >= m)
 *    l > L = m
 *
 *    This means L is a prefix of l.
 *             l'
 *           /
 *         L
 *       /
 *     l
 *
 *    (CASE 4) They are both bigger than m
 *     - l > L > m
 *     - L > l > m
 *     - L = l > m
 *
 *    Both share L and l share l' as a common prefix, and this is not l' since
 *    they share the name next bit.
 *
 *    So this case is impossible and we would have taken the other branch during
 *    the descent:
 *
 *           l'
 *         /   \
 *        l      L
 *
 *     We are in a situation where e need to insert an internal node:
 *
 *            l'
 *            |
 *            X <------ internal node
 *         /     \
 *       l        L
 */
void fib_add(fib_t *fib, fib_entry_t *entry) {
  assert(fib);
  assert(entry);

  const hicn_prefix_t *prefix = fib_entry_get_prefix(entry);
  uint32_t prefix_len = hicn_prefix_get_len(prefix);

  fib_search_t search;
  fib_node_t *curr = fib_search(fib, prefix, &search);

  /* Case 1 */
  if (!curr) {
    _fib_insert(fib, entry, search.parent, NULL, true);
    return;
  }

  /* Case 2 */
  if (search.prefix_len == search.match_len && prefix_len == search.match_len) {
    if (!curr->is_used) {
      curr->is_used = true;
      if (curr->entry) fib_entry_free(curr->entry);
      curr->entry = entry;
      fib->size++;
    } else {
      const nexthops_t *nexthops = fib_entry_get_nexthops(entry);
      nexthops_foreach(nexthops, nexthop,
                       { fib_entry_nexthops_add(curr->entry, nexthop); });
      fib_entry_free(entry);
    }
    return;
  }

  /* Case 3 */
  if (prefix_len == search.match_len) {
    _fib_insert(fib, entry, search.parent, curr, true);
    return;
  }

  /* Case 4 */
  hicn_prefix_t inner_prefix; /* dup'ed in fib_entry_create */
  hicn_prefix_copy(&inner_prefix, prefix);
  hicn_prefix_truncate(&inner_prefix, search.match_len);
  fib_entry_t *inner_entry = fib_entry_create(
      &inner_prefix, STRATEGY_TYPE_UNDEFINED, NULL, fib->forwarder);
  fib_node_t *new_node =
      _fib_insert(fib, inner_entry, search.parent, curr, false);
  _fib_insert(fib, entry, new_node, NULL, true);
}

/*
 * Implementation details:
 *
 * To find whether the fib contains a prefix, we issue a search, and based on
 * the stopping conditions, we return the entry if and only if curr
 * is not NULL, and prefix_len == curr_len (== match_len)
 */
fib_entry_t *fib_contains(const fib_t *fib, const hicn_prefix_t *prefix) {
  assert(fib);
  assert(prefix);

  uint32_t prefix_len = hicn_prefix_get_len(prefix);

  fib_search_t search;
  fib_node_t *curr = fib_search(fib, prefix, &search);

  if (!curr) return NULL;
  if (search.prefix_len != prefix_len) return NULL;
  return curr->is_used ? curr->entry : NULL;
}

/*
 * @brief Remove a prefix (and the associated node) from FIB
 *
 * We search for
 *
 * Actions depend on N, the number of children of the node to remove
 * Examples are build using 'left' children only, but the cases with 'right'
 * children are symmetrical.
 *
 * Legend:
 * (empty) : no children
 *    *    : 0 or more children
 *    +    : at least one children
 *
 * N == 2 - Mark the node as unused
 *
 *          parent                parent
 *          /    \                /    \
 *        curr    ...    ==>     (curr)   ...
 *       /    \                 /    \
 *     L        R              L       R
 *
 * N == 1 - Attach the child to the parent node (whether parent is used or not)
 *
 * a) curr has no parent (curr is the root)
 *
 *        curr                    +
 *       /               ==>
 *     +
 *
 * b) curr has a parent
 *          parent                parent
 *          /    \                /    \
 *        curr    *      ==>     L      *
 *       /    \
 *     L
 *
 *         (parent)               (parent)
 *          /    \                 /    \
 *        curr    +      ==>     L       +
 *       /    \
 *     L
 *
 * N == 0
 *
 * a) curr has no parent (curr is the root)
 *
 *      curr
 *    /      \           ==>
 *
 * b) parent is unused.
 *
 * Assuming curr is the left child, then parent must have a
 * right child, and the grand-parent must be used.
 *
 *               gp                    gp                        gp
 *             /                     /                         /
 *         (parent)       ==>    (parent)        ==>         +
 *          /    \                 /   \
 *        curr    +                     +
 *       /    \
 *
 * c) parent is used.
 *
 * Assuming curr is the left child, we simply remove it from
 * parent, leaving parent unchanged whether it has a right child or not.
 *
 *          parent                parent
 *          /    \                /    \
 *        curr    *      ==>            *
 *       /    \
 *
 *
 */
static void fib_node_remove(fib_t *fib, const hicn_prefix_t *prefix) {
  assert(fib);
  assert(prefix);

  uint32_t prefix_len = hicn_prefix_get_len(prefix);

  fib_search_t search;
  fib_node_t *curr = fib_search(fib, prefix, &search);

  /*
   * If we reach a NULL, unused node, or a node not matching, that means the
   * node does not exist
   */
  if (!curr || !curr->is_used || (search.prefix_len != prefix_len)) return;

  uint8_t N = 0;
  if (curr->child[ZERO]) N++;
  if (curr->child[ONE]) N++;

  switch (N) {
    case 2:
      curr->is_used = false;
      break;

    case 1:
      _fib_remove(fib, curr, search.parent);
      break;

    case 0:
      _fib_remove(fib, curr, search.parent);
      if (!search.parent->is_used)
        _fib_remove(fib, search.parent, search.gparent);
      break;
  }
}

void fib_remove(fib_t *fib, const hicn_prefix_t *prefix, unsigned conn_id) {
  assert(fib);
  assert(prefix);

  fib_entry_t *entry = fib_contains(fib, prefix);
  if (!entry) return;

  fib_entry_nexthops_remove(entry, conn_id);
#ifndef WITH_MAPME
  if (fib_entry_nexthops_len(entry) == 0) fib_node_remove(fib, name);
#endif /* WITH_MAPME */
}

static size_t fib_node_remove_connection_id(fib_node_t *node, unsigned conn_id,
                                            fib_entry_t **array, size_t pos) {
  if (!node) return pos;
  if (node->is_used) {
    fib_entry_nexthops_remove(node->entry, conn_id);

    /* When using MAP-Me, we keep empty FIB entries */
#ifndef WITH_MAPME
    if (fib_entry_nexthops_len(node->entry) == 0) array[pos++] = node->entry;
#endif /* WITH_MAPME */
  }
  pos = fib_node_remove_connection_id(node->child[ONE], conn_id, array, pos);
  pos = fib_node_remove_connection_id(node->child[ZERO], conn_id, array, pos);
  return pos;
}

void fib_remove_entry(fib_t *fib, fib_entry_t *entry) {
  fib_node_remove(fib, fib_entry_get_prefix(entry));
}

void fib_remove_connection(fib_t *fib, unsigned conn_id,
                           fib_entry_t ***removed_entries,
                           size_t *num_removed_entries) {
  assert(fib);

  fib_entry_t **array = malloc(sizeof(fib_entry_t *) * fib->size);

  size_t pos = 0;
  pos = fib_node_remove_connection_id(fib->root, conn_id, array, pos);

  if (removed_entries) {
    /*
     * The caller is taking charge of releasing entries (as well as the returned
     * array
     */
    assert(num_removed_entries);

    *removed_entries = array;
    *num_removed_entries = pos;

  } else {
    for (int i = 0; i < pos; i++)
      fib_node_remove(fib, fib_entry_get_prefix(array[i]));
  }
  free(array);
}

fib_entry_t *fib_match_msgbuf(const fib_t *fib, const msgbuf_t *msgbuf) {
  assert(fib);
  assert(msgbuf);

  return fib_match_name(fib, msgbuf_get_name(msgbuf));
}

/*
 * Implementation details:
 *
 * fib_search returns the longest non-strict subprefix.
 * - curr == NULL means no such prefix exist and we can return the parent.
 * - if we have an exact match (curr_len == key_prefix_len), then we
 *   return curr unless is_used is false, in which case we return the parent.
 * - otherwise, the parent is the longest prefix match
 */
fib_entry_t *fib_match_prefix(const fib_t *fib, const hicn_prefix_t *prefix) {
  assert(fib);
  assert(prefix);

  uint32_t prefix_len = hicn_prefix_get_len(prefix);

  fib_search_t search;
  fib_node_t *curr = fib_search(fib, prefix, &search);

  if (!curr) {
    /* This can happen with an empty FIB for instance */
    if (!search.parent) return NULL;
    return search.parent->entry;
  }
  if ((search.prefix_len <= prefix_len) && curr->is_used) return curr->entry;
  if (search.parent) return search.parent->entry;
  return NULL;
}

fib_entry_t *fib_match_name(const fib_t *fib, const hicn_name_t *name) {
  hicn_prefix_t prefix;
  const hicn_name_prefix_t *name_prefix = hicn_name_get_prefix(name);
  prefix.name = *name_prefix;
  prefix.len = hicn_name_prefix_get_len_bits(name_prefix);
  return fib_match_prefix(fib, &prefix);
}

static size_t fib_node_collect_entries(fib_node_t *node, fib_entry_t **array,
                                       size_t pos) {
  assert(array);

  if (!node) return pos;

  if (node->is_used) array[pos++] = node->entry;

  pos = fib_node_collect_entries(node->child[ONE], array, pos);
  pos = fib_node_collect_entries(node->child[ZERO], array, pos);
  return pos;
}

size_t fib_get_entry_array(const fib_t *fib, fib_entry_t ***array_p) {
  size_t pos = 0;
  *array_p = malloc(sizeof(fib_entry_t *) * fib->size);
  if (!*array_p) return pos;
  pos = fib_node_collect_entries(fib->root, *array_p, pos);
  return pos;
}

bool _fib_is_valid(const fib_node_t *node) {
  if (!node) return true;

  const hicn_prefix_t *prefix = fib_entry_get_prefix(node->entry);
  uint32_t prefix_len = hicn_prefix_get_len(prefix);

  for (unsigned i = 0; i < 2; i++) {
    const fib_node_t *child = node->child[i];
    if (!child) continue;
    const hicn_prefix_t *child_prefix = fib_entry_get_prefix(child->entry);

    uint32_t match_len = hicn_prefix_lpm(prefix, child_prefix);
    if (match_len != prefix_len) return false;
    if (!node->is_used && !child->is_used) return false;
    if (hicn_prefix_get_bit(child_prefix, match_len) != i) return false;
    if (!_fib_is_valid(child)) return false;
  }
  return true;
}

/*
 * @brief Check that the structure of the FIB is correct : prefixes are
 * correctly nested, 0 are on the left, 1 on the right, and that we have no
 * more than 1 unused prefix as parents.
 */
bool fib_is_valid(const fib_t *fib) { return _fib_is_valid(fib->root); }

/*
 * Checks whether the preorder traversal of the sub-tree corresponds to the
 * prefix and used arrays, starting from pos (helper)
 */
bool __fib_check_preorder(const fib_node_t *node,
                          const hicn_prefix_t **prefix_array, bool *used_array,
                          size_t size, size_t *pos) {
  /* Check left subtree... */
  fib_node_t *left = node->child[ZERO];
  if (left && !__fib_check_preorder(left, prefix_array, used_array, size, pos))
    return false;

  /* ... then current node ... */
  if (*pos > size) {
    ERROR("size error");
    return false;
  }

  const hicn_prefix_t *prefix = fib_entry_get_prefix(node->entry);

  if (!hicn_prefix_equals(prefix, prefix_array[*pos])) {
    char buf[MAXSZ_HICN_PREFIX];
    int rc;

    ERROR("Prefix mismatch in position %d %s != %s", pos);
    rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, prefix);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "%s", "(error)");
    ERROR("Expected: %s", buf);

    rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, prefix_array[*pos]);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "%s", "(error)");
    ERROR("Expected: %s", buf);
    return false;
  }

  (*pos)++;

  /* ... then right subtree */
  fib_node_t *right = node->child[ONE];
  if (right &&
      !__fib_check_preorder(right, prefix_array, used_array, size, pos))
    return false;

  return true;
}

/*
 * Checks whether the preorder traversal of the trie
 * corresponds to the prefix and used arrays.
 */
bool _fib_check_preorder(const fib_t *fib, const hicn_prefix_t **prefix_array,
                         bool *used_array, size_t size) {
  if (!fib->root) return true;
  size_t pos = 0;
  if (!__fib_check_preorder(fib->root, prefix_array, used_array, size, &pos))
    return false;
  /* We need to check that we don't miss elements */
  return pos == size;
}

// XXX print empty node but not recurse
void _fib_dump(const fib_node_t *node, int start, int indent) {
  char buf[MAXSZ_HICN_PREFIX];

  if (node) {
    const hicn_prefix_t *prefix = fib_entry_get_prefix(node->entry);
    int rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, prefix);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "%s %d", "(error)", rc);
  } else {
    snprintf(buf, MAXSZ_HICN_PREFIX, "%s", "(null)");
  }

  // Left
  if (indent > 0) {
    for (int i = 0; i < start - 1; i++) printf("   ");
    for (int i = start + 1; i < indent; i++) printf("|  ");
    printf("|");
    printf("_ %s\n", buf);
  } else {
    printf("%s\n", buf);
  }

  if (!node) return;

  _fib_dump(node->child[ZERO], start, indent + 1);
  _fib_dump(node->child[ONE], start + 1, indent + 1);
}

void fib_dump(const fib_t *fib) { _fib_dump(fib->root, 0, 0); }
