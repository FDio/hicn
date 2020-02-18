/*
 * Copyright 2013-present Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The code in this file if adapated from the IOBuf of folly:
 * https://github.com/facebook/folly/blob/master/folly/io/IOBuf.h
 */

#pragma once

#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/branch_prediction.h>

#include <atomic>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <type_traits>
#include <vector>

#include <stdlib.h>

#ifndef _WIN32
TRANSPORT_GNU_DISABLE_WARNING("-Wshadow")
#endif

namespace utils {

class MemBuf {
 public:
  enum CreateOp { CREATE };
  enum WrapBufferOp { WRAP_BUFFER };
  enum TakeOwnershipOp { TAKE_OWNERSHIP };
  enum CopyBufferOp { COPY_BUFFER };

  typedef void (*FreeFunction)(void* buf, void* userData);

  static std::unique_ptr<MemBuf> create(std::size_t capacity);
  MemBuf(CreateOp, std::size_t capacity);

  /**
   * Create a new MemBuf, using a single memory allocation to allocate space
   * for both the MemBuf object and the data storage space.
   *
   * This saves one memory allocation.  However, it can be wasteful if you
   * later need to grow the buffer using reserve().  If the buffer needs to be
   * reallocated, the space originally allocated will not be freed() until the
   * MemBuf object itself is also freed.  (It can also be slightly wasteful in
   * some cases where you clone this MemBuf and then free the original MemBuf.)
   */
  static std::unique_ptr<MemBuf> createCombined(std::size_t capacity);

  /**
   * Create a new IOBuf, using separate memory allocations for the IOBuf object
   * for the IOBuf and the data storage space.
   *
   * This requires two memory allocations, but saves space in the long run
   * if you know that you will need to reallocate the data buffer later.
   */
  static std::unique_ptr<MemBuf> createSeparate(std::size_t capacity);

  /**
   * Allocate a new MemBuf chain with the requested total capacity, allocating
   * no more than maxBufCapacity to each buffer.
   */
  static std::unique_ptr<MemBuf> createChain(size_t totalCapacity,
                                             std::size_t maxBufCapacity);

  static std::unique_ptr<MemBuf> takeOwnership(void* buf, std::size_t capacity,
                                               FreeFunction freeFn = nullptr,
                                               void* userData = nullptr,
                                               bool freeOnError = true) {
    return takeOwnership(buf, capacity, capacity, freeFn, userData,
                         freeOnError);
  }

  MemBuf(TakeOwnershipOp op, void* buf, std::size_t capacity,
         FreeFunction freeFn = nullptr, void* userData = nullptr,
         bool freeOnError = true)
      : MemBuf(op, buf, capacity, capacity, freeFn, userData, freeOnError) {}

  static std::unique_ptr<MemBuf> takeOwnership(void* buf, std::size_t capacity,
                                               std::size_t length,
                                               FreeFunction freeFn = nullptr,
                                               void* userData = nullptr,
                                               bool freeOnError = true);

  MemBuf(TakeOwnershipOp, void* buf, std::size_t capacity, std::size_t length,
         FreeFunction freeFn = nullptr, void* userData = nullptr,
         bool freeOnError = true);

  static std::unique_ptr<MemBuf> wrapBuffer(const void* buf,
                                            std::size_t capacity);

  static MemBuf wrapBufferAsValue(const void* buf,
                                  std::size_t capacity) noexcept;

  MemBuf(WrapBufferOp op, const void* buf, std::size_t capacity) noexcept;

  /**
   * Convenience function to create a new MemBuf object that copies data from a
   * user-supplied buffer, optionally allocating a given amount of
   * headroom and tailroom.
   */
  static std::unique_ptr<MemBuf> copyBuffer(const void* buf, std::size_t size,
                                            std::size_t headroom = 0,
                                            std::size_t minTailroom = 0);

  MemBuf(CopyBufferOp op, const void* buf, std::size_t size,
         std::size_t headroom = 0, std::size_t minTailroom = 0);

  /**
   * Convenience function to free a chain of MemBufs held by a unique_ptr.
   */
  static void destroy(std::unique_ptr<MemBuf>&& data) {
    auto destroyer = std::move(data);
  }

  ~MemBuf();

  bool empty() const;

  const uint8_t* data() const { return data_; }

  uint8_t* writableData() { return data_; }

  const uint8_t* tail() const { return data_ + length_; }

  uint8_t* writableTail() { return data_ + length_; }

  std::size_t length() const { return length_; }

  std::size_t headroom() const { return std::size_t(data_ - buffer()); }

  std::size_t tailroom() const { return std::size_t(bufferEnd() - tail()); }

  const uint8_t* buffer() const { return buf_; }

  uint8_t* writableBuffer() { return buf_; }

  const uint8_t* bufferEnd() const { return buf_ + capacity_; }

  std::size_t capacity() const { return capacity_; }

  MemBuf* next() { return next_; }

  const MemBuf* next() const { return next_; }

  MemBuf* prev() { return prev_; }

  const MemBuf* prev() const { return prev_; }

  /**
   * Shift the data forwards in the buffer.
   *
   * This shifts the data pointer forwards in the buffer to increase the
   * headroom.  This is commonly used to increase the headroom in a newly
   * allocated buffer.
   *
   * The caller is responsible for ensuring that there is sufficient
   * tailroom in the buffer before calling advance().
   *
   * If there is a non-zero data length, advance() will use memmove() to shift
   * the data forwards in the buffer.  In this case, the caller is responsible
   * for making sure the buffer is unshared, so it will not affect other MemBufs
   * that may be sharing the same underlying buffer.
   */
  void advance(std::size_t amount) {
    // In debug builds, assert if there is a problem.
    assert(amount <= tailroom());

    if (length_ > 0) {
      memmove(data_ + amount, data_, length_);
    }
    data_ += amount;
  }

  /**
   * Shift the data backwards in the buffer.
   *
   * The caller is responsible for ensuring that there is sufficient headroom
   * in the buffer before calling retreat().
   *
   * If there is a non-zero data length, retreat() will use memmove() to shift
   * the data backwards in the buffer.  In this case, the caller is responsible
   * for making sure the buffer is unshared, so it will not affect other MemBufs
   * that may be sharing the same underlying buffer.
   */
  void retreat(std::size_t amount) {
    // In debug builds, assert if there is a problem.
    assert(amount <= headroom());

    if (length_ > 0) {
      memmove(data_ - amount, data_, length_);
    }
    data_ -= amount;
  }

  void prepend(std::size_t amount) {
    data_ -= amount;
    length_ += amount;
  }

  void append(std::size_t amount) { length_ += amount; }

  void trimStart(std::size_t amount) {
    data_ += amount;
    length_ -= amount;
  }

  void trimEnd(std::size_t amount) { length_ -= amount; }

  // Never call clear on cloned membuf sharing different
  // portions of the same underlying buffer.
  // Use the trim functions instead.
  void clear() {
    data_ = writableBuffer();
    length_ = 0;
  }

  void reserve(std::size_t minHeadroom, std::size_t minTailroom) {
    // Maybe we don't need to do anything.
    if (headroom() >= minHeadroom && tailroom() >= minTailroom) {
      return;
    }
    // If the buffer is empty but we have enough total room (head + tail),
    // move the data_ pointer around.
    if (length() == 0 && headroom() + tailroom() >= minHeadroom + minTailroom) {
      data_ = writableBuffer() + minHeadroom;
      return;
    }
    // Bah, we have to do actual work.
    reserveSlow(minHeadroom, minTailroom);
  }

  bool isChained() const {
    assert((next_ == this) == (prev_ == this));
    return next_ != this;
  }

  size_t countChainElements() const;

  std::size_t computeChainDataLength() const;

  void prependChain(std::unique_ptr<MemBuf>&& iobuf);

  void appendChain(std::unique_ptr<MemBuf>&& iobuf) {
    // Just use prependChain() on the next element in our chain
    next_->prependChain(std::move(iobuf));
  }

  std::unique_ptr<MemBuf> unlink() {
    next_->prev_ = prev_;
    prev_->next_ = next_;
    prev_ = this;
    next_ = this;
    return std::unique_ptr<MemBuf>(this);
  }

  /**
   * Remove this MemBuf from its current chain and return a unique_ptr to
   * the MemBuf that formerly followed it in the chain.
   */
  std::unique_ptr<MemBuf> pop() {
    MemBuf* next = next_;
    next_->prev_ = prev_;
    prev_->next_ = next_;
    prev_ = this;
    next_ = this;
    return std::unique_ptr<MemBuf>((next == this) ? nullptr : next);
  }

  /**
   * Remove a subchain from this chain.
   *
   * Remove the subchain starting at head and ending at tail from this chain.
   *
   * Returns a unique_ptr pointing to head.  (In other words, ownership of the
   * head of the subchain is transferred to the caller.)  If the caller ignores
   * the return value and lets the unique_ptr be destroyed, the subchain will
   * be immediately destroyed.
   *
   * The subchain referenced by the specified head and tail must be part of the
   * same chain as the current MemBuf, but must not contain the current MemBuf.
   * However, the specified head and tail may be equal to each other (i.e.,
   * they may be a subchain of length 1).
   */
  std::unique_ptr<MemBuf> separateChain(MemBuf* head, MemBuf* tail) {
    assert(head != this);
    assert(tail != this);

    head->prev_->next_ = tail->next_;
    tail->next_->prev_ = head->prev_;

    head->prev_ = tail;
    tail->next_ = head;

    return std::unique_ptr<MemBuf>(head);
  }

  /**
   * Return true if at least one of the MemBufs in this chain are shared,
   * or false if all of the MemBufs point to unique buffers.
   *
   * Use isSharedOne() to only check this MemBuf rather than the entire chain.
   */
  bool isShared() const {
    const MemBuf* current = this;
    while (true) {
      if (current->isSharedOne()) {
        return true;
      }
      current = current->next_;
      if (current == this) {
        return false;
      }
    }
  }

  /**
   * Return true if all MemBufs in this chain are managed by the usual
   * refcounting mechanism (and so the lifetime of the underlying memory
   * can be extended by clone()).
   */
  bool isManaged() const {
    const MemBuf* current = this;
    while (true) {
      if (!current->isManagedOne()) {
        return false;
      }
      current = current->next_;
      if (current == this) {
        return true;
      }
    }
  }

  /**
   * Return true if this MemBuf is managed by the usual refcounting mechanism
   * (and so the lifetime of the underlying memory can be extended by
   * cloneOne()).
   */
  bool isManagedOne() const { return sharedInfo(); }

  /**
   * Return true if other MemBufs are also pointing to the buffer used by this
   * MemBuf, and false otherwise.
   *
   * If this MemBuf points at a buffer owned by another (non-MemBuf) part of the
   * code (i.e., if the MemBuf was created using wrapBuffer(), or was cloned
   * from such an MemBuf), it is always considered shared.
   *
   * This only checks the current MemBuf, and not other MemBufs in the chain.
   */
  bool isSharedOne() const {
    // If this is a user-owned buffer, it is always considered shared
    if ((TRANSPORT_EXPECT_FALSE(!sharedInfo()))) {
      return true;
    }

    if ((TRANSPORT_EXPECT_FALSE(sharedInfo()->externallyShared))) {
      return true;
    }

    if ((TRANSPORT_EXPECT_TRUE(!(flags() & flag_maybe_shared)))) {
      return false;
    }

    // flag_maybe_shared is set, so we need to check the reference count.
    // (Checking the reference count requires an atomic operation, which is why
    // we prefer to only check flag_maybe_shared if possible.)
    bool shared = sharedInfo()->refcount.load(std::memory_order_acquire) > 1;
    if (!shared) {
      // we're the last one left
      clearFlags(flag_maybe_shared);
    }
    return shared;
  }

  /**
   * Ensure that this MemBuf has a unique buffer that is not shared by other
   * MemBufs.
   *
   * unshare() operates on an entire chain of MemBuf objects.  If the chain is
   * shared, it may also coalesce the chain when making it unique.  If the
   * chain is coalesced, subsequent MemBuf objects in the current chain will be
   * automatically deleted.
   *
   * Note that buffers owned by other (non-MemBuf) users are automatically
   * considered shared.
   *
   * Throws std::bad_alloc on error.  On error the MemBuf chain will be
   * unmodified.
   *
   * Currently unshare may also throw std::overflow_error if it tries to
   * coalesce.  (TODO: In the future it would be nice if unshare() were smart
   * enough not to coalesce the entire buffer if the data is too large.
   * However, in practice this seems unlikely to become an issue.)
   */
  void unshare() {
    if (isChained()) {
      unshareChained();
    } else {
      unshareOne();
    }
  }

  /**
   * Ensure that this MemBuf has a unique buffer that is not shared by other
   * MemBufs.
   *
   * unshareOne() operates on a single MemBuf object.  This MemBuf will have a
   * unique buffer after unshareOne() returns, but other MemBufs in the chain
   * may still be shared after unshareOne() returns.
   *
   * Throws std::bad_alloc on error.  On error the MemBuf will be unmodified.
   */
  void unshareOne() {
    if (isSharedOne()) {
      unshareOneSlow();
    }
  }

  /**
   * Mark the underlying buffers in this chain as shared with external memory
   * management mechanism. This will make isShared() always returns true.
   *
   * This function is not thread-safe, and only safe to call immediately after
   * creating an MemBuf, before it has been shared with other threads.
   */
  void markExternallyShared();

  /**
   * Mark the underlying buffer that this MemBuf refers to as shared with
   * external memory management mechanism. This will make isSharedOne() always
   * returns true.
   *
   * This function is not thread-safe, and only safe to call immediately after
   * creating an MemBuf, before it has been shared with other threads.
   */
  void markExternallySharedOne() {
    SharedInfo* info = sharedInfo();
    if (info) {
      info->externallyShared = true;
    }
  }

  /**
   * Ensure that the memory that MemBufs in this chain refer to will continue to
   * be allocated for as long as the MemBufs of the chain (or any clone()s
   * created from this point onwards) is alive.
   *
   * This only has an effect for user-owned buffers (created with the
   * WRAP_BUFFER constructor or wrapBuffer factory function), in which case
   * those buffers are unshared.
   */
  void makeManaged() {
    if (isChained()) {
      makeManagedChained();
    } else {
      makeManagedOne();
    }
  }

  /**
   * Ensure that the memory that this MemBuf refers to will continue to be
   * allocated for as long as this MemBuf (or any clone()s created from this
   * point onwards) is alive.
   *
   * This only has an effect for user-owned buffers (created with the
   * WRAP_BUFFER constructor or wrapBuffer factory function), in which case
   * those buffers are unshared.
   */
  void makeManagedOne() {
    if (!isManagedOne()) {
      // We can call the internal function directly; unmanaged implies shared.
      unshareOneSlow();
    }
  }

  // /**
  //  * Coalesce this MemBuf chain into a single buffer.
  //  *
  //  * This method moves all of the data in this MemBuf chain into a single
  //  * contiguous buffer, if it is not already in one buffer.  After coalesce()
  //  * returns, this MemBuf will be a chain of length one.  Other MemBufs in
  //  the
  //  * chain will be automatically deleted.
  //  *
  //  * After coalescing, the MemBuf will have at least as much headroom as the
  //  * first MemBuf in the chain, and at least as much tailroom as the last
  //  MemBuf
  //  * in the chain.
  //  *
  //  * Throws std::bad_alloc on error.  On error the MemBuf chain will be
  //  * unmodified.
  //  *
  //  * Returns ByteRange that points to the data MemBuf stores.
  //  */
  // ByteRange coalesce() {
  //   const std::size_t newHeadroom = headroom();
  //   const std::size_t newTailroom = prev()->tailroom();
  //   return coalesceWithHeadroomTailroom(newHeadroom, newTailroom);
  // }

  // /**
  //  * This is similar to the coalesce() method, except this allows to set a
  //  * headroom and tailroom after coalescing.
  //  *
  //  * Returns ByteRange that points to the data MemBuf stores.
  //  */
  // ByteRange coalesceWithHeadroomTailroom(std::size_t newHeadroom,
  //                                        std::size_t newTailroom) {
  //   if (isChained()) {
  //     coalesceAndReallocate(newHeadroom, computeChainDataLength(), this,
  //                           newTailroom);
  //   }
  //   return ByteRange(data_, length_);
  // }

  /**
   * Ensure that this chain has at least maxLength bytes available as a
   * contiguous memory range.
   *
   * This method coalesces whole buffers in the chain into this buffer as
   * necessary until this buffer's length() is at least maxLength.
   *
   * After coalescing, the MemBuf will have at least as much headroom as the
   * first MemBuf in the chain, and at least as much tailroom as the last MemBuf
   * that was coalesced.
   *
   * Throws std::bad_alloc or std::overflow_error on error.  On error the MemBuf
   * chain will be unmodified.  Throws std::overflow_error if maxLength is
   * longer than the total chain length.
   *
   * Upon return, either enough of the chain was coalesced into a contiguous
   * region, or the entire chain was coalesced.  That is,
   * length() >= maxLength || !isChained() is true.
   */
  void gather(std::size_t maxLength) {
    if (!isChained() || length_ >= maxLength) {
      return;
    }
    coalesceSlow(maxLength);
  }

  /**
   * Return a new MemBuf chain sharing the same data as this chain.
   *
   * The new MemBuf chain will normally point to the same underlying data
   * buffers as the original chain.  (The one exception to this is if some of
   * the MemBufs in this chain contain small internal data buffers which cannot
   * be shared.)
   */
  std::unique_ptr<MemBuf> clone() const;

  /**
   * Similar to clone(). But returns MemBuf by value rather than heap-allocating
   * it.
   */
  MemBuf cloneAsValue() const;

  /**
   * Return a new MemBuf with the same data as this MemBuf.
   *
   * The new MemBuf returned will not be part of a chain (even if this MemBuf is
   * part of a larger chain).
   */
  std::unique_ptr<MemBuf> cloneOne() const;

  /**
   * Similar to cloneOne(). But returns MemBuf by value rather than
   * heap-allocating it.
   */
  MemBuf cloneOneAsValue() const;

  /**
   * Return a new unchained MemBuf that may share the same data as this chain.
   *
   * If the MemBuf chain is not chained then the new MemBuf will point to the
   * same underlying data buffer as the original chain. Otherwise, it will clone
   * and coalesce the MemBuf chain.
   *
   * The new MemBuf will have at least as much headroom as the first MemBuf in
   * the chain, and at least as much tailroom as the last MemBuf in the chain.
   *
   * Throws std::bad_alloc on error.
   */
  std::unique_ptr<MemBuf> cloneCoalesced() const;

  /**
   * This is similar to the cloneCoalesced() method, except this allows to set a
   * headroom and tailroom for the new MemBuf.
   */
  std::unique_ptr<MemBuf> cloneCoalescedWithHeadroomTailroom(
      std::size_t newHeadroom, std::size_t newTailroom) const;

  /**
   * Similar to cloneCoalesced(). But returns MemBuf by value rather than
   * heap-allocating it.
   */
  MemBuf cloneCoalescedAsValue() const;

  /**
   * This is similar to the cloneCoalescedAsValue() method, except this allows
   * to set a headroom and tailroom for the new MemBuf.
   */
  MemBuf cloneCoalescedAsValueWithHeadroomTailroom(
      std::size_t newHeadroom, std::size_t newTailroom) const;

  /**
   * Similar to Clone(). But use other as the head node. Other nodes in the
   * chain (if any) will be allocted on heap.
   */
  void cloneInto(MemBuf& other) const { other = cloneAsValue(); }

  /**
   * Similar to CloneOne(). But to fill an existing MemBuf instead of a new
   * MemBuf.
   */
  void cloneOneInto(MemBuf& other) const { other = cloneOneAsValue(); }

  /**
   * Return an iovector suitable for e.g. writev()
   *
   *   auto iov = buf->getIov();
   *   auto xfer = writev(fd, iov.data(), iov.size());
   *
   * Naturally, the returned iovector is invalid if you modify the buffer
   * chain.
   */
  std::vector<struct iovec> getIov() const;

  /**
   * Update an existing iovec array with the MemBuf data.
   *
   * New iovecs will be appended to the existing vector; anything already
   * present in the vector will be left unchanged.
   *
   * Naturally, the returned iovec data will be invalid if you modify the
   * buffer chain.
   */
  void appendToIov(std::vector<struct iovec>* iov) const;

  /**
   * Fill an iovec array with the MemBuf data.
   *
   * Returns the number of iovec filled. If there are more buffer than
   * iovec, returns 0. This version is suitable to use with stack iovec
   * arrays.
   *
   * Naturally, the filled iovec data will be invalid if you modify the
   * buffer chain.
   */
  size_t fillIov(struct iovec* iov, size_t len) const;

  /**
   * A helper that wraps a number of iovecs into an MemBuf chain.  If count ==
   * 0, then a zero length buf is returned.  This function never returns
   * nullptr.
   */
  static std::unique_ptr<MemBuf> wrapIov(const iovec* vec, size_t count);

  /**
   * A helper that takes ownerships a number of iovecs into an MemBuf chain.  If
   * count == 0, then a zero length buf is returned.  This function never
   * returns nullptr.
   */
  static std::unique_ptr<MemBuf> takeOwnershipIov(const iovec* vec,
                                                  size_t count,
                                                  FreeFunction freeFn = nullptr,
                                                  void* userData = nullptr,
                                                  bool freeOnError = true);

  /*
   * Overridden operator new and delete.
   * These perform specialized memory management to help support
   * createCombined(), which allocates MemBuf objects together with the buffer
   * data.
   */
  void* operator new(size_t size);
  void* operator new(size_t size, void* ptr);
  void operator delete(void* ptr);
  void operator delete(void* ptr, void* placement);

  // /**
  //  * Iteration support: a chain of MemBufs may be iterated through using
  //  * STL-style iterators over const ByteRanges.  Iterators are only
  //  invalidated
  //  * if the MemBuf that they currently point to is removed.
  //  */
  // Iterator cbegin() const;
  // Iterator cend() const;
  // Iterator begin() const;
  // Iterator end() const;

  /**
   * Allocate a new null buffer.
   *
   * This can be used to allocate an empty MemBuf on the stack.  It will have no
   * space allocated for it.  This is generally useful only to later use move
   * assignment to fill out the MemBuf.
   */
  MemBuf() noexcept;

  /**
   * Move constructor and assignment operator.
   *
   * In general, you should only ever move the head of an MemBuf chain.
   * Internal nodes in an MemBuf chain are owned by the head of the chain, and
   * should not be moved from.  (Technically, nothing prevents you from moving
   * a non-head node, but the moved-to node will replace the moved-from node in
   * the chain.  This has implications for ownership, since non-head nodes are
   * owned by the chain head.  You are then responsible for relinquishing
   * ownership of the moved-to node, and manually deleting the moved-from
   * node.)
   *
   * With the move assignment operator, the destination of the move should be
   * the head of an MemBuf chain or a solitary MemBuf not part of a chain.  If
   * the move destination is part of a chain, all other MemBufs in the chain
   * will be deleted.
   */
  MemBuf(MemBuf&& other) noexcept;
  MemBuf& operator=(MemBuf&& other) noexcept;

  MemBuf(const MemBuf& other);
  MemBuf& operator=(const MemBuf& other);

 private:
  enum FlagsEnum : uintptr_t {
    // Adding any more flags would not work on 32-bit architectures,
    // as these flags are stashed in the least significant 2 bits of a
    // max-align-aligned pointer.
    flag_free_shared_info = 0x1,
    flag_maybe_shared = 0x2,
    flag_mask = flag_free_shared_info | flag_maybe_shared
  };

  struct SharedInfo {
    SharedInfo();
    SharedInfo(FreeFunction fn, void* arg);

    // A pointer to a function to call to free the buffer when the refcount
    // hits 0.  If this is null, free() will be used instead.
    FreeFunction freeFn;
    void* userData;
    std::atomic<uint32_t> refcount;
    bool externallyShared{false};
  };
  // Helper structs for use by operator new and delete
  struct HeapPrefix;
  struct HeapStorage;
  struct HeapFullStorage;

  /**
   * Create a new MemBuf pointing to an external buffer.
   *
   * The caller is responsible for holding a reference count for this new
   * MemBuf.  The MemBuf constructor does not automatically increment the
   * reference count.
   */
  struct InternalConstructor {};  // avoid conflicts
  MemBuf(InternalConstructor, uintptr_t flagsAndSharedInfo, uint8_t* buf,
         std::size_t capacity, uint8_t* data, std::size_t length) noexcept;

  void unshareOneSlow();
  void unshareChained();
  void makeManagedChained();
  void coalesceSlow();
  void coalesceSlow(size_t maxLength);
  // newLength must be the entire length of the buffers between this and
  // end (no truncation)
  void coalesceAndReallocate(size_t newHeadroom, size_t newLength, MemBuf* end,
                             size_t newTailroom);
  void coalesceAndReallocate(size_t newLength, MemBuf* end) {
    coalesceAndReallocate(headroom(), newLength, end, end->prev_->tailroom());
  }
  void decrementRefcount();
  void reserveSlow(std::size_t minHeadroom, std::size_t minTailroom);
  void freeExtBuffer();

  static size_t goodExtBufferSize(std::size_t minCapacity);
  static void initExtBuffer(uint8_t* buf, size_t mallocSize,
                            SharedInfo** infoReturn,
                            std::size_t* capacityReturn);
  static void allocExtBuffer(std::size_t minCapacity, uint8_t** bufReturn,
                             SharedInfo** infoReturn,
                             std::size_t* capacityReturn);
  static void releaseStorage(HeapStorage* storage, uint16_t freeFlags);
  static void freeInternalBuf(void* buf, void* userData);

  /*
   * Member variables
   */

  /*
   * Links to the next and the previous MemBuf in this chain.
   *
   * The chain is circularly linked (the last element in the chain points back
   * at the head), and next_ and prev_ can never be null.  If this MemBuf is the
   * only element in the chain, next_ and prev_ will both point to this.
   */
  MemBuf* next_{this};
  MemBuf* prev_{this};

  /*
   * A pointer to the start of the data referenced by this MemBuf, and the
   * length of the data.
   *
   * This may refer to any subsection of the actual buffer capacity.
   */
  uint8_t* data_{nullptr};
  uint8_t* buf_{nullptr};
  std::size_t length_{0};
  std::size_t capacity_{0};

  // Pack flags in least significant 2 bits, sharedInfo in the rest
  mutable uintptr_t flags_and_shared_info_{0};

  static inline uintptr_t packFlagsAndSharedInfo(uintptr_t flags,
                                                 SharedInfo* info) {
    uintptr_t uinfo = reinterpret_cast<uintptr_t>(info);
    return flags | uinfo;
  }

  inline SharedInfo* sharedInfo() const {
    return reinterpret_cast<SharedInfo*>(flags_and_shared_info_ & ~flag_mask);
  }

  inline void setSharedInfo(SharedInfo* info) {
    uintptr_t uinfo = reinterpret_cast<uintptr_t>(info);
    flags_and_shared_info_ = (flags_and_shared_info_ & flag_mask) | uinfo;
  }

  inline uintptr_t flags() const { return flags_and_shared_info_ & flag_mask; }

  // flags_ are changed from const methods
  inline void setFlags(uintptr_t flags) const {
    flags_and_shared_info_ |= flags;
  }

  inline void clearFlags(uintptr_t flags) const {
    flags_and_shared_info_ &= ~flags;
  }

  inline void setFlagsAndSharedInfo(uintptr_t flags, SharedInfo* info) {
    flags_and_shared_info_ = packFlagsAndSharedInfo(flags, info);
  }

  struct DeleterBase {
    virtual ~DeleterBase() {}
    virtual void dispose(void* p) = 0;
  };

  template <class UniquePtr>
  struct UniquePtrDeleter : public DeleterBase {
    typedef typename UniquePtr::pointer Pointer;
    typedef typename UniquePtr::deleter_type Deleter;

    explicit UniquePtrDeleter(Deleter deleter) : deleter_(std::move(deleter)) {}
    void dispose(void* p) override {
      try {
        deleter_(static_cast<Pointer>(p));
        delete this;
      } catch (...) {
        abort();
      }
    }

   private:
    Deleter deleter_;
  };

  static void freeUniquePtrBuffer(void* ptr, void* userData) {
    static_cast<DeleterBase*>(userData)->dispose(ptr);
  }
};

// template <class UniquePtr>
// typename std::enable_if<
//     detail::IsUniquePtrToSL<UniquePtr>::value,
//     std::unique_ptr<MemBuf>>::type
// MemBuf::takeOwnership(UniquePtr&& buf, size_t count) {
//   size_t size = count * sizeof(typename UniquePtr::element_type);
//   auto deleter = new UniquePtrDeleter<UniquePtr>(buf.get_deleter());
//   return takeOwnership(
//       buf.release(), size, &MemBuf::freeUniquePtrBuffer, deleter);
// }

inline std::unique_ptr<MemBuf> MemBuf::copyBuffer(const void* data,
                                                  std::size_t size,
                                                  std::size_t headroom,
                                                  std::size_t minTailroom) {
  std::size_t capacity = headroom + size + minTailroom;
  std::unique_ptr<MemBuf> buf = MemBuf::create(capacity);
  buf->advance(headroom);
  if (size != 0) {
    memcpy(buf->writableData(), data, size);
  }
  buf->append(size);
  return buf;
}

}  // namespace utils
