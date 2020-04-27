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

#include <hicn/core/fib.h>

typedef struct fib_node_s {
    struct fib_node_s *left;
    struct fib_node_s *right;
    fib_entry_t *entry;
    bool is_used;
} fib_node_t;

static
fib_node_t *
fib_node_create(fib_node_t * left, fib_node_t * right, fib_entry_t * entry,
        bool is_used)
{
    fib_node_t * node = malloc(sizeof(fib_node_t));
    if (!node)
        return NULL;

    *node = (fib_node_t) {
        .left = left,
        .right = right,
        .entry = entry,
        .is_used = is_used,
    };

    return node;
}

static
void
fib_node_free(fib_node_t * node)
{
    if (!node)
        return;

    fib_node_free(node->right);
    fib_node_free(node->left);

    free(node);
}

/******************************************************************************/

struct fib_s {
    void * forwarder;
    fib_node_t * root;
    unsigned size;
};

fib_t *
fib_create(void * forwarder)
{
    fib_t * fib = malloc(sizeof(fib_t));
    if (!fib)
        return NULL;

    fib->forwarder = forwarder;
    fib->root = NULL;
    fib->size = 0;

    return fib;
}


void
fib_free(fib_t * fib)
{
    assert(fib);

    fib_node_free(fib->root);

    free(fib);
}

size_t
fib_get_size(const fib_t * fib)
{
    return fib->size;
}


#define FIB_SET(CURR, NEW_PREFIX, CURR_PREFIX_LEN)                      \
do {                                                                    \
    bool bit;                                                           \
    int res = nameBitvector_testBit(NEW_PREFIX, CURR_PREFIX_LEN, &bit); \
    assert(res >= 0);                                                   \
    (void)res; /* unused */                                             \
    CURR = bit ? CURR->right : CURR->left;                              \
} while(0)

#define FIB_INSERT(DST, SRC, PREFIX, PREFIX_LEN)                        \
do {                                                                    \
    bool bit;                                                           \
    int res = nameBitvector_testBit(PREFIX, PREFIX_LEN, &bit);          \
    assert(res >= 0);                                                   \
    (void)res; /* unused */                                             \
    if (bit)                                                            \
        DST->right = SRC;                                               \
    else                                                                \
        DST->left = SRC;                                                \
} while(0)

void
fib_add(fib_t * fib, fib_entry_t * entry)
{
    assert(fib);
    assert(entry);

    NameBitvector *new_prefix = name_GetContentName(fib_entry_get_prefix(entry));
    uint32_t new_prefix_len = nameBitvector_GetLength(new_prefix);
    fib_node_t * curr =  fib->root;
    fib_node_t * last =  NULL;

    NameBitvector *curr_name;
    uint32_t curr_prefix_len;
    uint32_t match_len;

    while (curr) {
        curr_name = name_GetContentName(fib_entry_get_prefix(curr->entry));

        match_len =  nameBitvector_lpm(new_prefix, curr_name);
        curr_prefix_len = nameBitvector_GetLength(curr_name);

        if(curr_prefix_len != match_len || //the new entry does not match the curr
                curr_prefix_len >= new_prefix_len) //in this case we cannot procede anymore
            break;

        last = curr;
        FIB_SET(curr, new_prefix, curr_prefix_len);
    }

    //this is the root (empty trie) or an empty child
    if (!curr) {
        fib_node_t * new_node = fib_node_create(NULL, NULL, entry, true);
        if (!last) {
            fib->root = new_node;
        } else {
            uint32_t last_prefix_len = nameBitvector_GetLength(
                    name_GetContentName(fib_entry_get_prefix(last->entry)));

            FIB_INSERT(last, new_node, new_prefix, last_prefix_len);
        }
        fib->size++;
        return;
    }

    //curr is not null

    //the node already exist
    //if is not in use we turn it on and we set the rigth fib entry
    if (curr_prefix_len == match_len && new_prefix_len == match_len) {
        if (!curr->is_used) {
            curr->is_used = true;
            curr->entry = entry;
            fib->size++;
            return;
        } else {
            //this case should never happen beacuse of the way we add
            //entries in the fib
            const nexthops_t * nexthops = fib_entry_get_nexthops(entry);
            unsigned nexthop;
            nexthops_foreach(nexthops, nexthop, {
                fib_entry_nexthops_add(curr->entry, nexthop);
            });
        }
    }

    //key is prefix of the curr node (so new_prefix_len < curr_prefix_len)
    if (new_prefix_len == match_len){
        fib_node_t * new_node = fib_node_create(NULL, NULL, entry, true);
        if (!last) {
            fib->root = new_node;
        } else {
            uint32_t last_prefix_len = nameBitvector_GetLength(
                    name_GetContentName(fib_entry_get_prefix(last->entry)));
            FIB_INSERT(last, new_node, new_prefix, last_prefix_len);
        }
        FIB_INSERT(new_node, curr, curr_name, match_len);
        fib->size++;
        return;
    }

    //in the last case we need to add an inner node
    Name * inner_prefix = name_Copy(fib_entry_get_prefix(entry));
    nameBitvector_clear(name_GetContentName(inner_prefix), match_len);
    name_setLen(inner_prefix,  match_len);

    //this is an inner node, we don't want an acctive strategy
    //like low_latency that sends probes in this node
    fib_entry_t * inner_entry = fib_entry_create(inner_prefix,
            STRATEGY_TYPE_UNDEFINED, NULL, fib->forwarder);

    fib_node_t * inner_node = fib_node_create(NULL, NULL, inner_entry, false);
    fib_node_t * new_node = fib_node_create(NULL, NULL, entry, true);

    if (!last) {
        //we need to place the inner_node at the root
        fib->root = inner_node;
    } else {
        uint32_t last_prefix_len = nameBitvector_GetLength(
                name_GetContentName(fib_entry_get_prefix(last->entry)));
        NameBitvector *inner_name = name_GetContentName(inner_prefix);
        FIB_INSERT(last, inner_node, inner_name, last_prefix_len);
    }

    bool bit;
    int res = nameBitvector_testBit(new_prefix, match_len, &bit);
    assert(res >= 0);
    (void)res; /* unused */
    inner_node->left = bit ? curr : new_node;
    inner_node->right = bit ? new_node : curr;
    fib->size++;
}

fib_entry_t *
fib_contains(const fib_t * fib, const Name * prefix)
{
    assert(fib);
    assert(prefix);

    NameBitvector * key_name = name_GetContentName(prefix);
    uint32_t key_prefix_len = nameBitvector_GetLength(key_name);

    fib_node_t * curr = fib->root;

    while (curr) {
        NameBitvector *curr_name =
            name_GetContentName(fib_entry_get_prefix(curr->entry));
        uint32_t match_len = nameBitvector_lpm(key_name, curr_name);
        uint32_t curr_prefix_len = nameBitvector_GetLength(curr_name);

        if (match_len < curr_prefix_len) {
            //the current node does not match completelly the key, so
            //the key is not in the trie
            //this implies curr_prefix_len > key_prefix_len
            return NULL;
        }

        if (curr_prefix_len == key_prefix_len) { //== match_len
            //this is an exact match
            if (!curr->is_used) {
                //the key does not exists
                return NULL;
            }
            //we found the key
            return curr->entry;
        }

        FIB_SET(curr, key_name, curr_prefix_len);
    }

    return NULL;
}

static
void
fib_node_remove(fib_t *fib, const Name *prefix)
{
    assert(fib);
    assert(prefix);

    NameBitvector *key_name = name_GetContentName(prefix);
    uint32_t key_prefix_len = nameBitvector_GetLength(key_name);

    fib_node_t * curr = fib->root;
    fib_node_t * parent = NULL;
    fib_node_t * grandpa = NULL;

    uint32_t match_len;
    uint32_t curr_prefix_len;

    while(curr) {
        NameBitvector *curr_name =
            name_GetContentName(fib_entry_get_prefix(curr->entry));
        match_len = nameBitvector_lpm(key_name, curr_name);
        curr_prefix_len = nameBitvector_GetLength(curr_name);

        if(match_len < curr_prefix_len ||
                curr_prefix_len == key_prefix_len){
            break;
        }

        grandpa = parent;
        parent = curr;

        FIB_SET(curr, key_name, curr_prefix_len);
    }

    if (!curr || !curr->is_used || (curr_prefix_len != key_prefix_len)) {
        //the node does not exists
        return;
    }

    //curr has 2 children, leave it there and mark it as inner
    if (curr->right && curr->left) {
        curr->is_used = false;
        fib->size--;
        return;
    }

    //curr has no children
    if (!curr->right && !curr->left) {
        if (!parent) {
            //curr is the root and is the only node in the fib
            fib->root = NULL;
            fib->size--;
            fib_node_free(curr);
            return;
        }
        if (!grandpa) {
            //parent is the root
            if(fib->root->left == curr)
                fib->root->left = NULL;
            else
                fib->root->right = NULL;
            fib->size--;
            fib_node_free(curr);
            return;
        }
        if(!parent->is_used){
            //parent is an inner node
            //remove curr and inner_node (parent), connect the other child
            //of the parent to the grandpa
            fib_node_t * tmp = (parent->right == curr) ? parent->left : parent->right;

            if(grandpa->right == parent)
                grandpa->right = tmp;
            else
                grandpa->left = tmp;

            fib->size--;
            fib_node_free(curr);
            fib_node_free(parent);
            return;
        }
        //parent is node not an inner_node
        //just remove curr the node
        if(parent->right == curr)
            parent->right = NULL;
        else
            parent->left = NULL;
        fib->size--;
        fib_node_free(curr);
        return;
    }

    //curr has one child
    if (curr->right || curr->left) {
        if (!parent) {
            //curr is the root
            fib->root = fib->root->right ? fib->root->right : fib->root->left;
            fib->size--;
            fib_node_free(curr);
            return;
        }
        //attach the child of curr to parent
        fib_node_t * tmp = curr->right ? curr->right : curr->left;

        if (parent->right == curr)
            parent->right = tmp;
        else
            parent->left = tmp;

        fib->size--;
        fib_node_free(curr);
        return;
    }
}

void
fib_remove(fib_t * fib, const Name * name, unsigned conn_id)
{
    assert(fib);
    assert(name);

    fib_entry_t *entry = fib_contains(fib, name);
    if (!entry)
        return;

    fib_entry_nexthops_remove(entry, conn_id);
#ifndef WITH_MAPME
    if (fib_entry_nexthops_len(entry) == 0)
        fib_node_remove(fib, name);
#endif /* WITH_MAPME */
}

static
size_t
fib_node_remove_connection_id(fib_node_t * node, unsigned conn_id,
        fib_entry_t ** array, size_t pos)
{
    if (!node)
        return pos;
    if (node->is_used) {
        fib_entry_nexthops_remove(node->entry, conn_id);
#ifndef WITH_MAPME
        if (fib_entry_nexthops_len(node->entry) == 0)
            array[pos++] = node->entry;
#endif /* WITH_MAPME */
    }
    pos = fib_node_remove_connection_id(node->right, conn_id, array, pos);
    pos = fib_node_remove_connection_id(node->left, conn_id, array, pos);
    return pos;
}

void
fib_remove_connection_id(fib_t * fib, unsigned conn_id)
{
    assert(fib);

    fib_entry_t ** array = malloc(sizeof(fib_entry_t*) * fib->size);

    size_t pos = 0;
    pos = fib_node_remove_connection_id(fib->root, conn_id, array, pos);

    for (int i = 0; i < pos; i++)
        fib_node_remove(fib, fib_entry_get_prefix(array[i]));
    free(array);
}

size_t
fib_length(const fib_t * fib)
{
    assert(fib);
    return fib->size;
}

fib_entry_t *
fib_match_message(const fib_t *fib, const msgbuf_t *interest_msgbuf)
{
    assert(fib);
    assert(interest_msgbuf);

    return fib_match_bitvector(fib, name_GetContentName(
                msgbuf_get_name(interest_msgbuf)));
}

fib_entry_t *
fib_match_name(const fib_t * fib, const Name * name)
{
    assert(fib);
    assert(name);

    return fib_match_bitvector(fib, name_GetContentName(name));
}


fib_entry_t *
fib_match_bitvector(const fib_t * fib, const NameBitvector * name)
{
    assert(fib);
    assert(name);

    uint32_t key_prefix_len = nameBitvector_GetLength(name);

    fib_node_t * curr = fib->root;
    fib_node_t * candidate = NULL;

    while (curr) {
        NameBitvector *curr_name =
            name_GetContentName(fib_entry_get_prefix(curr->entry));
        uint32_t match_len = nameBitvector_lpm(name, curr_name);
        uint32_t curr_prefix_len = nameBitvector_GetLength(curr_name);

        if(match_len < curr_prefix_len){
            //the current node does not match completelly the key, so
            //return the parent of this node (saved in candidate)
            break;
        }

        if (curr->is_used)
            candidate = curr;

        //if we are here match_len == curr_prefix_len (can't be larger)
        //so this node is actually a good candidate for a match
        if (curr_prefix_len == key_prefix_len){
            //this an exact match, do not continue
            break;
        }

        FIB_SET(curr, name, curr_prefix_len);
    }

    return candidate ? candidate->entry : NULL;
}

static
size_t
fib_node_collect_entries(fib_node_t * node, fib_entry_t ** array, size_t pos)
{
    assert(array);

    if (!node)
        return pos;

    if(node->is_used)
        array[pos++] = node->entry;

    pos = fib_node_collect_entries(node->right, array, pos);
    pos = fib_node_collect_entries(node->left, array, pos);
    return pos;
}

size_t
fib_get_entry_array(const fib_t * fib, fib_entry_t *** array_p)
{
    size_t pos = 0;
    *array_p = malloc(sizeof(fib_entry_t*) * fib->size);
    if (!*array_p)
        return pos;
    pos = fib_node_collect_entries(fib->root, *array_p, pos);
    return pos;
}
