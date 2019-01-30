/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Copyright 2013-present Facebook, Inc.
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
#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

#include <hicn/transport/utils/membuf.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <vector>

using std::unique_ptr;

namespace {

enum : uint16_t {
  kHeapMagic = 0xa5a5,
  // This memory segment contains an MemBuf that is still in use
  kMemBufInUse = 0x01,
  // This memory segment contains buffer data that is still in use
  kDataInUse = 0x02,
};

enum : std::size_t {
  // When create() is called for buffers less than kDefaultCombinedBufSize,
  // we allocate a single combined memory segment for the MemBuf and the data
  // together.  See the comments for createCombined()/createSeparate() for more
  // details.
  //
  // (The size of 1k is largely just a guess here.  We could could probably do
  // benchmarks of real applications to see if adjusting this number makes a
  // difference.  Callers that know their exact use case can also explicitly
  // call createCombined() or createSeparate().)
  kDefaultCombinedBufSize = 1024
};

// Helper function for MemBuf::takeOwnership()
void takeOwnershipError(bool freeOnError, void* buf,
                        utils::MemBuf::FreeFunction freeFn, void* userData) {
  if (!freeOnError) {
    return;
  }
  if (!freeFn) {
    free(buf);
    return;
  }
  try {
    freeFn(buf, userData);
  } catch (...) {
    // The user's free function is not allowed to throw.
    // (We are already in the middle of throwing an exception, so
    // we cannot let this exception go unhandled.)
    abort();
  }
}

}  // namespace

namespace utils {

struct MemBuf::HeapPrefix {
  explicit HeapPrefix(uint16_t flg) : magic(kHeapMagic), flags(flg) {}
  ~HeapPrefix() {
    // Reset magic to 0 on destruction.  This is solely for debugging purposes
    // to help catch bugs where someone tries to use HeapStorage after it has
    // been deleted.
    magic = 0;
  }

  uint16_t magic;
  std::atomic<uint16_t> flags;
};

struct MemBuf::HeapStorage {
  HeapPrefix prefix;
  // The MemBuf is last in the HeapStorage object.
  // This way operator new will work even if allocating a subclass of MemBuf
  // that requires more space.
  utils::MemBuf buf;
};

struct MemBuf::HeapFullStorage {
  // Make sure jemalloc allocates from the 64-byte class.  Putting this here
  // because HeapStorage is private so it can't be at namespace level.
  static_assert(sizeof(HeapStorage) <= 64,
                "MemBuf may not grow over 56 bytes!");

  HeapStorage hs;
  SharedInfo shared;
  std::max_align_t align;
};

MemBuf::SharedInfo::SharedInfo() : freeFn(nullptr), userData(nullptr) {
  // Use relaxed memory ordering here.  Since we are creating a new SharedInfo,
  // no other threads should be referring to it yet.
  refcount.store(1, std::memory_order_relaxed);
}

MemBuf::SharedInfo::SharedInfo(FreeFunction fn, void* arg)
    : freeFn(fn), userData(arg) {
  // Use relaxed memory ordering here.  Since we are creating a new SharedInfo,
  // no other threads should be referring to it yet.
  refcount.store(1, std::memory_order_relaxed);
}

void* MemBuf::operator new(size_t size) {
  size_t fullSize = offsetof(HeapStorage, buf) + size;
  auto* storage = static_cast<HeapStorage*>(malloc(fullSize));

  new (&storage->prefix) HeapPrefix(kMemBufInUse);
  return &(storage->buf);
}

void* MemBuf::operator new(size_t /* size */, void* ptr) { return ptr; }

void MemBuf::operator delete(void* ptr) {
  auto* storageAddr = static_cast<uint8_t*>(ptr) - offsetof(HeapStorage, buf);
  auto* storage = reinterpret_cast<HeapStorage*>(storageAddr);
  releaseStorage(storage, kMemBufInUse);
}

void MemBuf::operator delete(void* /* ptr */, void* /* placement */) {
  // Provide matching operator for `MemBuf::new` to avoid MSVC compilation
  // warning (C4291) about memory leak when exception is thrown in the
  // constructor.
}

void MemBuf::releaseStorage(HeapStorage* storage, uint16_t freeFlags) {
  // Use relaxed memory order here.  If we are unlucky and happen to get
  // out-of-date data the compare_exchange_weak() call below will catch
  // it and load new data with memory_order_acq_rel.
  auto flags = storage->prefix.flags.load(std::memory_order_acquire);

  while (true) {
    uint16_t newFlags = uint16_t(flags & ~freeFlags);
    if (newFlags == 0) {
      // The storage space is now unused.  Free it.
      storage->prefix.HeapPrefix::~HeapPrefix();
      free(storage);
      return;
    }

    // This storage segment still contains portions that are in use.
    // Just clear the flags specified in freeFlags for now.
    auto ret = storage->prefix.flags.compare_exchange_weak(
        flags, newFlags, std::memory_order_acq_rel);
    if (ret) {
      // We successfully updated the flags.
      return;
    }

    // We failed to update the flags.  Some other thread probably updated them
    // and cleared some of the other bits.  Continue around the loop to see if
    // we are the last user now, or if we need to try updating the flags again.
  }
}

void MemBuf::freeInternalBuf(void* /* buf */, void* userData) {
  auto* storage = static_cast<HeapStorage*>(userData);
  releaseStorage(storage, kDataInUse);
}

MemBuf::MemBuf(CreateOp, std::size_t capacity)
    : next_(this),
      prev_(this),
      data_(nullptr),
      length_(0),
      flags_and_shared_info_(0) {
  SharedInfo* info;
  allocExtBuffer(capacity, &buf_, &info, &capacity_);
  setSharedInfo(info);
  data_ = buf_;
}

MemBuf::MemBuf(CopyBufferOp /* op */, const void* buf, std::size_t size,
               std::size_t headroom, std::size_t min_tailroom)
    : MemBuf(CREATE, headroom + size + min_tailroom) {
  advance(headroom);
  if (size > 0) {
    assert(buf != nullptr);
    memcpy(writableData(), buf, size);
    append(size);
  }
}

unique_ptr<MemBuf> MemBuf::create(std::size_t capacity) {
  // For smaller-sized buffers, allocate the MemBuf, SharedInfo, and the buffer
  // all with a single allocation.
  //
  // We don't do this for larger buffers since it can be wasteful if the user
  // needs to reallocate the buffer but keeps using the same MemBuf object.
  // In this case we can't free the data space until the MemBuf is also
  // destroyed.  Callers can explicitly call createCombined() or
  // createSeparate() if they know their use case better, and know if they are
  // likely to reallocate the buffer later.
  if (capacity <= kDefaultCombinedBufSize) {
    return createCombined(capacity);
  }
  return createSeparate(capacity);
}

unique_ptr<MemBuf> MemBuf::createCombined(std::size_t capacity) {
  // To save a memory allocation, allocate space for the MemBuf object, the
  // SharedInfo struct, and the data itself all with a single call to malloc().
  size_t requiredStorage = offsetof(HeapFullStorage, align) + capacity;
  size_t mallocSize = requiredStorage;
  auto* storage = static_cast<HeapFullStorage*>(malloc(mallocSize));

  new (&storage->hs.prefix) HeapPrefix(kMemBufInUse | kDataInUse);
  new (&storage->shared) SharedInfo(freeInternalBuf, storage);

  uint8_t* bufAddr = reinterpret_cast<uint8_t*>(&storage->align);
  uint8_t* storageEnd = reinterpret_cast<uint8_t*>(storage) + mallocSize;
  size_t actualCapacity = size_t(storageEnd - bufAddr);
  unique_ptr<MemBuf> ret(new (&storage->hs.buf) MemBuf(
      InternalConstructor(), packFlagsAndSharedInfo(0, &storage->shared),
      bufAddr, actualCapacity, bufAddr, 0));
  return ret;
}

unique_ptr<MemBuf> MemBuf::createSeparate(std::size_t capacity) {
  return std::make_unique<MemBuf>(CREATE, capacity);
}

unique_ptr<MemBuf> MemBuf::createChain(size_t totalCapacity,
                                       std::size_t maxBufCapacity) {
  unique_ptr<MemBuf> out =
      create(std::min(totalCapacity, size_t(maxBufCapacity)));
  size_t allocatedCapacity = out->capacity();

  while (allocatedCapacity < totalCapacity) {
    unique_ptr<MemBuf> newBuf = create(
        std::min(totalCapacity - allocatedCapacity, size_t(maxBufCapacity)));
    allocatedCapacity += newBuf->capacity();
    out->prependChain(std::move(newBuf));
  }

  return out;
}

MemBuf::MemBuf(TakeOwnershipOp, void* buf, std::size_t capacity,
               std::size_t length, FreeFunction freeFn, void* userData,
               bool freeOnError)
    : next_(this),
      prev_(this),
      data_(static_cast<uint8_t*>(buf)),
      buf_(static_cast<uint8_t*>(buf)),
      length_(length),
      capacity_(capacity),
      flags_and_shared_info_(
          packFlagsAndSharedInfo(flag_free_shared_info, nullptr)) {
  try {
    setSharedInfo(new SharedInfo(freeFn, userData));
  } catch (...) {
    takeOwnershipError(freeOnError, buf, freeFn, userData);
    throw;
  }
}

unique_ptr<MemBuf> MemBuf::takeOwnership(void* buf, std::size_t capacity,
                                         std::size_t length,
                                         FreeFunction freeFn, void* userData,
                                         bool freeOnError) {
  try {
    // TODO: We could allocate the MemBuf object and SharedInfo all in a single
    // memory allocation.  We could use the existing HeapStorage class, and
    // define a new kSharedInfoInUse flag.  We could change our code to call
    // releaseStorage(flag_free_shared_info) when this flag_free_shared_info,
    // rather than directly calling delete.
    //
    // Note that we always pass freeOnError as false to the constructor.
    // If the constructor throws we'll handle it below.  (We have to handle
    // allocation failures from std::make_unique too.)
    return std::make_unique<MemBuf>(TAKE_OWNERSHIP, buf, capacity, length,
                                    freeFn, userData, false);
  } catch (...) {
    takeOwnershipError(freeOnError, buf, freeFn, userData);
    throw;
  }
}

MemBuf::MemBuf(WrapBufferOp, const void* buf, std::size_t capacity) noexcept
    : MemBuf(InternalConstructor(), 0,
             // We cast away the const-ness of the buffer here.
             // This is okay since MemBuf users must use unshare() to create a
             // copy of this buffer before writing to the buffer.
             static_cast<uint8_t*>(const_cast<void*>(buf)), capacity,
             static_cast<uint8_t*>(const_cast<void*>(buf)), capacity) {}

unique_ptr<MemBuf> MemBuf::wrapBuffer(const void* buf, std::size_t capacity) {
  return std::make_unique<MemBuf>(WRAP_BUFFER, buf, capacity);
}

MemBuf MemBuf::wrapBufferAsValue(const void* buf,
                                 std::size_t capacity) noexcept {
  return MemBuf(WrapBufferOp::WRAP_BUFFER, buf, capacity);
}

MemBuf::MemBuf() noexcept {}

MemBuf::MemBuf(MemBuf&& other) noexcept
    : data_(other.data_),
      buf_(other.buf_),
      length_(other.length_),
      capacity_(other.capacity_),
      flags_and_shared_info_(other.flags_and_shared_info_) {
  // Reset other so it is a clean state to be destroyed.
  other.data_ = nullptr;
  other.buf_ = nullptr;
  other.length_ = 0;
  other.capacity_ = 0;
  other.flags_and_shared_info_ = 0;

  // If other was part of the chain, assume ownership of the rest of its chain.
  // (It's only valid to perform move assignment on the head of a chain.)
  if (other.next_ != &other) {
    next_ = other.next_;
    next_->prev_ = this;
    other.next_ = &other;

    prev_ = other.prev_;
    prev_->next_ = this;
    other.prev_ = &other;
  }
}

MemBuf::MemBuf(const MemBuf& other) { *this = other.cloneAsValue(); }

MemBuf::MemBuf(InternalConstructor, uintptr_t flagsAndSharedInfo, uint8_t* buf,
               std::size_t capacity, uint8_t* data, std::size_t length) noexcept
    : next_(this),
      prev_(this),
      data_(data),
      buf_(buf),
      length_(length),
      capacity_(capacity),
      flags_and_shared_info_(flagsAndSharedInfo) {
  assert(data >= buf);
  assert(data + length <= buf + capacity);
}

MemBuf::~MemBuf() {
  // Destroying an MemBuf destroys the entire chain.
  // Users of MemBuf should only explicitly delete the head of any chain.
  // The other elements in the chain will be automatically destroyed.
  while (next_ != this) {
    // Since unlink() returns unique_ptr() and we don't store it,
    // it will automatically delete the unlinked element.
    (void)next_->unlink();
  }

  decrementRefcount();
}

MemBuf& MemBuf::operator=(MemBuf&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  // If we are part of a chain, delete the rest of the chain.
  while (next_ != this) {
    // Since unlink() returns unique_ptr() and we don't store it,
    // it will automatically delete the unlinked element.
    (void)next_->unlink();
  }

  // Decrement our refcount on the current buffer
  decrementRefcount();

  // Take ownership of the other buffer's data
  data_ = other.data_;
  buf_ = other.buf_;
  length_ = other.length_;
  capacity_ = other.capacity_;
  flags_and_shared_info_ = other.flags_and_shared_info_;
  // Reset other so it is a clean state to be destroyed.
  other.data_ = nullptr;
  other.buf_ = nullptr;
  other.length_ = 0;
  other.capacity_ = 0;
  other.flags_and_shared_info_ = 0;

  // If other was part of the chain, assume ownership of the rest of its chain.
  // (It's only valid to perform move assignment on the head of a chain.)
  if (other.next_ != &other) {
    next_ = other.next_;
    next_->prev_ = this;
    other.next_ = &other;

    prev_ = other.prev_;
    prev_->next_ = this;
    other.prev_ = &other;
  }

  return *this;
}

MemBuf& MemBuf::operator=(const MemBuf& other) {
  if (this != &other) {
    *this = MemBuf(other);
  }
  return *this;
}

bool MemBuf::empty() const {
  const MemBuf* current = this;
  do {
    if (current->length() != 0) {
      return false;
    }
    current = current->next_;
  } while (current != this);
  return true;
}

size_t MemBuf::countChainElements() const {
  size_t numElements = 1;
  for (MemBuf* current = next_; current != this; current = current->next_) {
    ++numElements;
  }
  return numElements;
}

std::size_t MemBuf::computeChainDataLength() const {
  std::size_t fullLength = length_;
  for (MemBuf* current = next_; current != this; current = current->next_) {
    fullLength += current->length_;
  }
  return fullLength;
}

void MemBuf::prependChain(unique_ptr<MemBuf>&& iobuf) {
  // Take ownership of the specified MemBuf
  MemBuf* other = iobuf.release();

  // Remember the pointer to the tail of the other chain
  MemBuf* otherTail = other->prev_;

  // Hook up prev_->next_ to point at the start of the other chain,
  // and other->prev_ to point at prev_
  prev_->next_ = other;
  other->prev_ = prev_;

  // Hook up otherTail->next_ to point at us,
  // and prev_ to point back at otherTail,
  otherTail->next_ = this;
  prev_ = otherTail;
}

unique_ptr<MemBuf> MemBuf::clone() const {
  return std::make_unique<MemBuf>(cloneAsValue());
}

unique_ptr<MemBuf> MemBuf::cloneOne() const {
  return std::make_unique<MemBuf>(cloneOneAsValue());
}

unique_ptr<MemBuf> MemBuf::cloneCoalesced() const {
  return std::make_unique<MemBuf>(cloneCoalescedAsValue());
}

unique_ptr<MemBuf> MemBuf::cloneCoalescedWithHeadroomTailroom(
    std::size_t new_headroom, std::size_t new_tailroom) const {
  return std::make_unique<MemBuf>(
      cloneCoalescedAsValueWithHeadroomTailroom(new_headroom, new_tailroom));
}

MemBuf MemBuf::cloneAsValue() const {
  auto tmp = cloneOneAsValue();

  for (MemBuf* current = next_; current != this; current = current->next_) {
    tmp.prependChain(current->cloneOne());
  }

  return tmp;
}

MemBuf MemBuf::cloneOneAsValue() const {
  if (SharedInfo* info = sharedInfo()) {
    setFlags(flag_maybe_shared);
    info->refcount.fetch_add(1, std::memory_order_acq_rel);
  }
  return MemBuf(InternalConstructor(), flags_and_shared_info_, buf_, capacity_,
                data_, length_);
}

MemBuf MemBuf::cloneCoalescedAsValue() const {
  const std::size_t new_headroom = headroom();
  const std::size_t new_tailroom = prev()->tailroom();
  return cloneCoalescedAsValueWithHeadroomTailroom(new_headroom, new_tailroom);
}

MemBuf MemBuf::cloneCoalescedAsValueWithHeadroomTailroom(
    std::size_t new_headroom, std::size_t new_tailroom) const {
  if (!isChained()) {
    return cloneOneAsValue();
  }
  // Coalesce into newBuf
  const std::size_t new_length = computeChainDataLength();
  const std::size_t new_capacity = new_length + new_headroom + new_tailroom;
  MemBuf newBuf{CREATE, new_capacity};
  newBuf.advance(new_headroom);

  auto current = this;
  do {
    if (current->length() > 0) {
      memcpy(newBuf.writableTail(), current->data(), current->length());
      newBuf.append(current->length());
    }
    current = current->next();
  } while (current != this);

  return newBuf;
}

void MemBuf::unshareOneSlow() {
  // Allocate a new buffer for the data
  uint8_t* buf;
  SharedInfo* sharedInfo;
  std::size_t actualCapacity;
  allocExtBuffer(capacity_, &buf, &sharedInfo, &actualCapacity);

  // Copy the data
  // Maintain the same amount of headroom.  Since we maintained the same
  // minimum capacity we also maintain at least the same amount of tailroom.
  std::size_t headlen = headroom();
  if (length_ > 0) {
    assert(data_ != nullptr);
    memcpy(buf + headlen, data_, length_);
  }

  // Release our reference on the old buffer
  decrementRefcount();
  // Make sure flag_maybe_shared and flag_free_shared_info are all cleared.
  setFlagsAndSharedInfo(0, sharedInfo);

  // Update the buffer pointers to point to the new buffer
  data_ = buf + headlen;
  buf_ = buf;
}

void MemBuf::unshareChained() {
  // unshareChained() should only be called if we are part of a chain of
  // multiple MemBufs.  The caller should have already verified this.
  assert(isChained());

  MemBuf* current = this;
  while (true) {
    if (current->isSharedOne()) {
      // we have to unshare
      break;
    }

    current = current->next_;
    if (current == this) {
      // None of the MemBufs in the chain are shared,
      // so return without doing anything
      return;
    }
  }

  // We have to unshare.  Let coalesceSlow() do the work.
  coalesceSlow();
}

void MemBuf::markExternallyShared() {
  MemBuf* current = this;
  do {
    current->markExternallySharedOne();
    current = current->next_;
  } while (current != this);
}

void MemBuf::makeManagedChained() {
  assert(isChained());

  MemBuf* current = this;
  while (true) {
    current->makeManagedOne();
    current = current->next_;
    if (current == this) {
      break;
    }
  }
}

void MemBuf::coalesceSlow() {
  // coalesceSlow() should only be called if we are part of a chain of multiple
  // MemBufs.  The caller should have already verified this.

  // Compute the length of the entire chain
  std::size_t new_length = 0;
  MemBuf* end = this;
  do {
    new_length += end->length_;
    end = end->next_;
  } while (end != this);

  coalesceAndReallocate(new_length, end);
  // We should be only element left in the chain now
}

void MemBuf::coalesceSlow(size_t max_length) {
  // coalesceSlow() should only be called if we are part of a chain of multiple
  // MemBufs.  The caller should have already verified this.

  // Compute the length of the entire chain
  std::size_t new_length = 0;
  MemBuf* end = this;
  while (true) {
    new_length += end->length_;
    end = end->next_;
    if (new_length >= max_length) {
      break;
    }
    if (end == this) {
      throw std::overflow_error(
          "attempted to coalesce more data than "
          "available");
    }
  }

  coalesceAndReallocate(new_length, end);
  // We should have the requested length now
}

void MemBuf::coalesceAndReallocate(size_t new_headroom, size_t new_length,
                                   MemBuf* end, size_t new_tailroom) {
  std::size_t new_capacity = new_length + new_headroom + new_tailroom;

  // Allocate space for the coalesced buffer.
  // We always convert to an external buffer, even if we happened to be an
  // internal buffer before.
  uint8_t* newBuf;
  SharedInfo* newInfo;
  std::size_t actualCapacity;
  allocExtBuffer(new_capacity, &newBuf, &newInfo, &actualCapacity);

  // Copy the data into the new buffer
  uint8_t* new_data = newBuf + new_headroom;
  uint8_t* p = new_data;
  MemBuf* current = this;
  size_t remaining = new_length;
  do {
    if (current->length_ > 0) {
      assert(current->length_ <= remaining);
      assert(current->data_ != nullptr);
      remaining -= current->length_;
      memcpy(p, current->data_, current->length_);
      p += current->length_;
    }
    current = current->next_;
  } while (current != end);
  assert(remaining == 0);

  // Point at the new buffer
  decrementRefcount();

  // Make sure flag_maybe_shared and flag_free_shared_info are all cleared.
  setFlagsAndSharedInfo(0, newInfo);

  capacity_ = actualCapacity;
  buf_ = newBuf;
  data_ = new_data;
  length_ = new_length;

  // Separate from the rest of our chain.
  // Since we don't store the unique_ptr returned by separateChain(),
  // this will immediately delete the returned subchain.
  if (isChained()) {
    (void)separateChain(next_, current->prev_);
  }
}

void MemBuf::decrementRefcount() {
  // Externally owned buffers don't have a SharedInfo object and aren't managed
  // by the reference count
  SharedInfo* info = sharedInfo();
  if (!info) {
    return;
  }

  // Decrement the refcount
  uint32_t newcnt = info->refcount.fetch_sub(1, std::memory_order_acq_rel);
  // Note that fetch_sub() returns the value before we decremented.
  // If it is 1, we were the only remaining user; if it is greater there are
  // still other users.
  if (newcnt > 1) {
    return;
  }

  // We were the last user.  Free the buffer
  freeExtBuffer();

  // Free the SharedInfo if it was allocated separately.
  //
  // This is only used by takeOwnership().
  //
  // To avoid this special case handling in decrementRefcount(), we could have
  // takeOwnership() set a custom freeFn() that calls the user's free function
  // then frees the SharedInfo object.  (This would require that
  // takeOwnership() store the user's free function with its allocated
  // SharedInfo object.)  However, handling this specially with a flag seems
  // like it shouldn't be problematic.
  if (flags() & flag_free_shared_info) {
    delete sharedInfo();
  }
}

void MemBuf::reserveSlow(std::size_t min_headroom, std::size_t min_tailroom) {
  size_t new_capacity = (size_t)length_ + min_headroom + min_tailroom;

  // // reserveSlow() is dangerous if anyone else is sharing the buffer, as we
  // may
  // // reallocate and free the original buffer.  It should only ever be called
  // if
  // // we are the only user of the buffer.

  // We'll need to reallocate the buffer.
  // There are a few options.
  // - If we have enough total room, move the data around in the buffer
  //   and adjust the data_ pointer.
  // - If we're using an internal buffer, we'll switch to an external
  //   buffer with enough headroom and tailroom.
  // - If we have enough headroom (headroom() >= min_headroom) but not too much
  //   (so we don't waste memory), we can try:
  //   - If we don't have too much to copy, we'll use realloc() (note that
  //   realloc might have to copy
  //     headroom + data + tailroom)
  // - Otherwise, bite the bullet and reallocate.
  if (headroom() + tailroom() >= min_headroom + min_tailroom) {
    uint8_t* new_data = writableBuffer() + min_headroom;
    std::memmove(new_data, data_, length_);
    data_ = new_data;
    return;
  }

  size_t new_allocated_capacity = 0;
  uint8_t* new_buffer = nullptr;
  std::size_t new_headroom = 0;
  std::size_t old_headroom = headroom();

  // If we have a buffer allocated with malloc and we just need more tailroom,
  // try to use realloc()/xallocx() to grow the buffer in place.
  SharedInfo* info = sharedInfo();
  if (info && (info->freeFn == nullptr) && length_ != 0 &&
      old_headroom >= min_headroom) {
    size_t head_slack = old_headroom - min_headroom;
    new_allocated_capacity = goodExtBufferSize(new_capacity + head_slack);

    size_t copySlack = capacity() - length_;
    if (copySlack * 2 <= length_) {
      void* p = realloc(buf_, new_allocated_capacity);
      if (TRANSPORT_EXPECT_FALSE(p == nullptr)) {
        throw std::bad_alloc();
      }
      new_buffer = static_cast<uint8_t*>(p);
      new_headroom = old_headroom;
    }
  }

  // None of the previous reallocation strategies worked (or we're using
  // an internal buffer).  malloc/copy/free.
  if (new_buffer == nullptr) {
    new_allocated_capacity = goodExtBufferSize(new_capacity);
    new_buffer = static_cast<uint8_t*>(malloc(new_allocated_capacity));
    if (length_ > 0) {
      assert(data_ != nullptr);
      memcpy(new_buffer + min_headroom, data_, length_);
    }
    if (sharedInfo()) {
      freeExtBuffer();
    }
    new_headroom = min_headroom;
  }

  std::size_t cap;
  initExtBuffer(new_buffer, new_allocated_capacity, &info, &cap);

  if (flags() & flag_free_shared_info) {
    delete sharedInfo();
  }

  setFlagsAndSharedInfo(0, info);
  capacity_ = cap;
  buf_ = new_buffer;
  data_ = new_buffer + new_headroom;
  // length_ is unchanged
}

void MemBuf::freeExtBuffer() {
  SharedInfo* info = sharedInfo();

  if (info->freeFn) {
    try {
      info->freeFn(buf_, info->userData);
    } catch (...) {
      // The user's free function should never throw.  Otherwise we might
      // throw from the MemBuf destructor.  Other code paths like coalesce()
      // also assume that decrementRefcount() cannot throw.
      abort();
    }
  } else {
    free(buf_);
  }
}

void MemBuf::allocExtBuffer(std::size_t minCapacity, uint8_t** bufReturn,
                            SharedInfo** infoReturn,
                            std::size_t* capacityReturn) {
  size_t mallocSize = goodExtBufferSize(minCapacity);
  uint8_t* buf = static_cast<uint8_t*>(malloc(mallocSize));
  initExtBuffer(buf, mallocSize, infoReturn, capacityReturn);
  *bufReturn = buf;
}

size_t MemBuf::goodExtBufferSize(std::size_t minCapacity) {
  // Determine how much space we should allocate.  We'll store the SharedInfo
  // for the external buffer just after the buffer itself.  (We store it just
  // after the buffer rather than just before so that the code can still just
  // use free(buf_) to free the buffer.)
  size_t minSize = static_cast<size_t>(minCapacity) + sizeof(SharedInfo);
  // Add room for padding so that the SharedInfo will be aligned on an 8-byte
  // boundary.
  minSize = (minSize + 7) & ~7;

  // Use goodMallocSize() to bump up the capacity to a decent size to request
  // from malloc, so we can use all of the space that malloc will probably give
  // us anyway.
  return minSize;
}

void MemBuf::initExtBuffer(uint8_t* buf, size_t mallocSize,
                           SharedInfo** infoReturn,
                           std::size_t* capacityReturn) {
  // Find the SharedInfo storage at the end of the buffer
  // and construct the SharedInfo.
  uint8_t* infoStart = (buf + mallocSize) - sizeof(SharedInfo);
  SharedInfo* sharedInfo = new (infoStart) SharedInfo;

  *capacityReturn = std::size_t(infoStart - buf);
  *infoReturn = sharedInfo;
}

}  // namespace utils