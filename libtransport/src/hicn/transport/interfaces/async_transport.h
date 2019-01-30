
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

#pragma once

#include <hicn/transport/interfaces/publication_options.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/sharable_vector.h>

#ifndef _WIN32
#include <sys/uio.h>
#endif

#include <memory>

namespace transport {

namespace interface {

/*
 * flags given by the application for write* calls
 */
enum class WriteFlags : uint32_t {
  NONE = 0x00,
  /*
   * Whether to delay the output until a subsequent non-corked write.
   * (Note: may not be supported in all subclasses or on all platforms.)
   */
  CORK = 0x01,
  /*
   * for a socket that has ACK latency enabled, it will cause the kernel
   * to fire a TCP ESTATS event when the last byte of the given write call
   * will be acknowledged.
   */
  EOR = 0x02,
  /*
   * this indicates that only the write side of socket should be shutdown
   */
  WRITE_SHUTDOWN = 0x04,
  /*
   * use msg zerocopy if allowed
   */
  WRITE_MSG_ZEROCOPY = 0x08,
};

/*
 * union operator
 */
TRANSPORT_ALWAYS_INLINE WriteFlags operator|(WriteFlags a, WriteFlags b) {
  return static_cast<WriteFlags>(static_cast<uint32_t>(a) |
                                 static_cast<uint32_t>(b));
}

/*
 * compound assignment union operator
 */
TRANSPORT_ALWAYS_INLINE WriteFlags &operator|=(WriteFlags &a, WriteFlags b) {
  a = a | b;
  return a;
}

/*
 * intersection operator
 */
TRANSPORT_ALWAYS_INLINE WriteFlags operator&(WriteFlags a, WriteFlags b) {
  return static_cast<WriteFlags>(static_cast<uint32_t>(a) &
                                 static_cast<uint32_t>(b));
}

/*
 * compound assignment intersection operator
 */
TRANSPORT_ALWAYS_INLINE WriteFlags &operator&=(WriteFlags &a, WriteFlags b) {
  a = a & b;
  return a;
}

/*
 * exclusion parameter
 */
TRANSPORT_ALWAYS_INLINE WriteFlags operator~(WriteFlags a) {
  return static_cast<WriteFlags>(~static_cast<uint32_t>(a));
}

/*
 * unset operator
 */
TRANSPORT_ALWAYS_INLINE WriteFlags unSet(WriteFlags a, WriteFlags b) {
  return a & ~b;
}

/*
 * inclusion operator
 */
TRANSPORT_ALWAYS_INLINE bool isSet(WriteFlags a, WriteFlags b) {
  return (a & b) == b;
}

class ConnectCallback {
 public:
  virtual ~ConnectCallback() = default;

  /**
   * connectSuccess() will be invoked when the connection has been
   * successfully established.
   */
  virtual void connectSuccess() noexcept = 0;

  /**
   * connectErr() will be invoked if the connection attempt fails.
   *
   * @param ex        An exception describing the error that occurred.
   */
  virtual void connectErr(const std::error_code ec) noexcept = 0;
};

/**
 * AsyncSocket defines an asynchronous API for streaming I/O.
 *
 * This class provides an API to for asynchronously waiting for data
 * on a streaming transport, and for asynchronously sending data.
 *
 * The APIs for reading and writing are intentionally asymmetric.  Waiting for
 * data to read is a persistent API: a callback is installed, and is notified
 * whenever new data is available.  It continues to be notified of new events
 * until it is uninstalled.
 *
 * AsyncSocket does not provide read timeout functionality, because it
 * typically cannot determine when the timeout should be active.  Generally, a
 * timeout should only be enabled when processing is blocked waiting on data
 * from the remote endpoint.  For server-side applications, the timeout should
 * not be active if the server is currently processing one or more outstanding
 * requests on this transport.  For client-side applications, the timeout
 * should not be active if there are no requests pending on the transport.
 * Additionally, if a client has multiple pending requests, it will ususally
 * want a separate timeout for each request, rather than a single read timeout.
 *
 * The write API is fairly intuitive: a user can request to send a block of
 * data, and a callback will be informed once the entire block has been
 * transferred to the kernel, or on error.  AsyncSocket does provide a send
 * timeout, since most callers want to give up if the remote end stops
 * responding and no further progress can be made sending the data.
 */
class AsyncSocket {
 public:
  /**
   * Close the transport.
   *
   * This gracefully closes the transport, waiting for all pending write
   * requests to complete before actually closing the underlying transport.
   *
   * If a read callback is set, readEOF() will be called immediately.  If there
   * are outstanding write requests, the close will be delayed until all
   * remaining writes have completed.  No new writes may be started after
   * close() has been called.
   */
  virtual void close() = 0;

  /**
   * Close the transport immediately.
   *
   * This closes the transport immediately, dropping any outstanding data
   * waiting to be written.
   *
   * If a read callback is set, readEOF() will be called immediately.
   * If there are outstanding write requests, these requests will be aborted
   * and writeError() will be invoked immediately on all outstanding write
   * callbacks.
   */
  virtual void closeNow() = 0;

  /**
   * Perform a half-shutdown of the write side of the transport.
   *
   * The caller should not make any more calls to write() or writev() after
   * shutdownWrite() is called.  Any future write attempts will fail
   * immediately.
   *
   * Not all transport types support half-shutdown.  If the underlying
   * transport does not support half-shutdown, it will fully shutdown both the
   * read and write sides of the transport.  (Fully shutting down the socket is
   * better than doing nothing at all, since the caller may rely on the
   * shutdownWrite() call to notify the other end of the connection that no
   * more data can be read.)
   *
   * If there is pending data still waiting to be written on the transport,
   * the actual shutdown will be delayed until the pending data has been
   * written.
   *
   * Note: There is no corresponding shutdownRead() equivalent.  Simply
   * uninstall the read callback if you wish to stop reading.  (On TCP sockets
   * at least, shutting down the read side of the socket is a no-op anyway.)
   */
  virtual void shutdownWrite() = 0;

  /**
   * Perform a half-shutdown of the write side of the transport.
   *
   * shutdownWriteNow() is identical to shutdownWrite(), except that it
   * immediately performs the shutdown, rather than waiting for pending writes
   * to complete.  Any pending write requests will be immediately failed when
   * shutdownWriteNow() is called.
   */
  virtual void shutdownWriteNow() = 0;

  /**
   * Determine if transport is open and ready to read or write.
   *
   * Note that this function returns false on EOF; you must also call error()
   * to distinguish between an EOF and an error.
   *
   * @return  true iff the transport is open and ready, false otherwise.
   */
  virtual bool good() const = 0;

  /**
   * Determine if the transport is readable or not.
   *
   * @return  true iff the transport is readable, false otherwise.
   */
  virtual bool readable() const = 0;

  /**
   * Determine if the transport is writable or not.
   *
   * @return  true iff the transport is writable, false otherwise.
   */
  virtual bool writable() const {
    // By default return good() - leave it to implementers to override.
    return good();
  }

  /**
   * Determine if the there is pending data on the transport.
   *
   * @return  true iff the if the there is pending data, false otherwise.
   */
  virtual bool isPending() const { return readable(); }

  /**
   * Determine if transport is connected to the endpoint
   *
   * @return  false iff the transport is connected, otherwise true
   */
  virtual bool connected() const = 0;

  /**
   * Determine if an error has occurred with this transport.
   *
   * @return  true iff an error has occurred (not EOF).
   */
  virtual bool error() const = 0;

  // /**
  //  * Attach the transport to a EventBase.
  //  *
  //  * This may only be called if the transport is not currently attached to a
  //  * EventBase (by an earlier call to detachEventBase()).
  //  *
  //  * This method must be invoked in the EventBase's thread.
  //  */
  // virtual void attachEventBase(EventBase* eventBase) = 0;

  // /**
  //  * Detach the transport from its EventBase.
  //  *
  //  * This may only be called when the transport is idle and has no reads or
  //  * writes pending.  Once detached, the transport may not be used again
  //  until
  //  * it is re-attached to a EventBase by calling attachEventBase().
  //  *
  //  * This method must be called from the current EventBase's thread.
  //  */
  // virtual void detachEventBase() = 0;

  // /**
  //  * Determine if the transport can be detached.
  //  *
  //  * This method must be called from the current EventBase's thread.
  //  */
  // virtual bool isDetachable() const = 0;

  /**
   * Set the send timeout.
   *
   * If write requests do not make any progress for more than the specified
   * number of milliseconds, fail all pending writes and close the transport.
   *
   * If write requests are currently pending when setSendTimeout() is called,
   * the timeout interval is immediately restarted using the new value.
   *
   * @param milliseconds  The timeout duration, in milliseconds.  If 0, no
   *                      timeout will be used.
   */
  virtual void setSendTimeout(uint32_t milliseconds) = 0;

  /**
   * Get the send timeout.
   *
   * @return Returns the current send timeout, in milliseconds.  A return value
   *         of 0 indicates that no timeout is set.
   */
  virtual uint32_t getSendTimeout() const = 0;

  virtual void connect(ConnectCallback *callback,
                       const core::Prefix &prefix_) = 0;

  // /**
  //  * Get the address of the local endpoint of this transport.
  //  *
  //  * This function may throw AsyncSocketException on error.
  //  *
  //  * @param address  The local address will be stored in the specified
  //  *                 SocketAddress.
  //  */
  // virtual void getLocalAddress(* address) const = 0;

  virtual size_t getAppBytesWritten() const = 0;
  virtual size_t getRawBytesWritten() const = 0;
  virtual size_t getAppBytesReceived() const = 0;
  virtual size_t getRawBytesReceived() const = 0;

  class BufferCallback {
   public:
    virtual ~BufferCallback() {}
    virtual void onEgressBuffered() = 0;
    virtual void onEgressBufferCleared() = 0;
  };

  ~AsyncSocket() = default;
};

class AsyncAcceptor {
 public:
  class AcceptCallback {
   public:
    virtual ~AcceptCallback() = default;

    /**
     * connectionAccepted() is called whenever a new client connection is
     * received.
     *
     * The AcceptCallback will remain installed after connectionAccepted()
     * returns.
     *
     * @param fd          The newly accepted client socket.  The AcceptCallback
     *                    assumes ownership of this socket, and is responsible
     *                    for closing it when done.  The newly accepted file
     *                    descriptor will have already been put into
     *                    non-blocking mode.
     * @param clientAddr  A reference to a SocketAddress struct containing the
     *                    client's address.  This struct is only guaranteed to
     *                    remain valid until connectionAccepted() returns.
     */
    virtual void connectionAccepted(
        const core::Name &subscriber_name) noexcept = 0;

    /**
     * acceptError() is called if an error occurs while accepting.
     *
     * The AcceptCallback will remain installed even after an accept error,
     * as the errors are typically somewhat transient, such as being out of
     * file descriptors.  The server socket must be explicitly stopped if you
     * wish to stop accepting after an error.
     *
     * @param ex  An exception representing the error.
     */
    virtual void acceptError(const std::exception &ex) noexcept = 0;

    /**
     * acceptStarted() will be called in the callback's EventBase thread
     * after this callback has been added to the AsyncServerSocket.
     *
     * acceptStarted() will be called before any calls to connectionAccepted()
     * or acceptError() are made on this callback.
     *
     * acceptStarted() makes it easier for callbacks to perform initialization
     * inside the callback thread.  (The call to addAcceptCallback() must
     * always be made from the AsyncServerSocket's primary EventBase thread.
     * acceptStarted() provides a hook that will always be invoked in the
     * callback's thread.)
     *
     * Note that the call to acceptStarted() is made once the callback is
     * added, regardless of whether or not the AsyncServerSocket is actually
     * accepting at the moment.  acceptStarted() will be called even if the
     * AsyncServerSocket is paused when the callback is added (including if
     * the initial call to startAccepting() on the AsyncServerSocket has not
     * been made yet).
     */
    virtual void acceptStarted() noexcept {}

    /**
     * acceptStopped() will be called when this AcceptCallback is removed from
     * the AsyncServerSocket, or when the AsyncServerSocket is destroyed,
     * whichever occurs first.
     *
     * No more calls to connectionAccepted() or acceptError() will be made
     * after acceptStopped() is invoked.
     */
    virtual void acceptStopped() noexcept {}
  };

  /**
   * Wait for subscribers
   *
   */
  virtual void waitForSubscribers(AcceptCallback *cb) = 0;
};

class AsyncReader {
 public:
  class ReadCallback {
   public:
    virtual ~ReadCallback() = default;

    /**
     * When data becomes available, getReadBuffer() will be invoked to get the
     * buffer into which data should be read.
     *
     * This method allows the ReadCallback to delay buffer allocation until
     * data becomes available.  This allows applications to manage large
     * numbers of idle connections, without having to maintain a separate read
     * buffer for each idle connection.
     *
     * It is possible that in some cases, getReadBuffer() may be called
     * multiple times before readDataAvailable() is invoked.  In this case, the
     * data will be written to the buffer returned from the most recent call to
     * readDataAvailable().  If the previous calls to readDataAvailable()
     * returned different buffers, the ReadCallback is responsible for ensuring
     * that they are not leaked.
     *
     * If getReadBuffer() throws an exception, returns a nullptr buffer, or
     * returns a 0 length, the ReadCallback will be uninstalled and its
     * readError() method will be invoked.
     *
     * getReadBuffer() is not allowed to change the transport state before it
     * returns.  (For example, it should never uninstall the read callback, or
     * set a different read callback.)
     *
     * @param bufReturn getReadBuffer() should update *bufReturn to contain the
     *                  address of the read buffer.  This parameter will never
     *                  be nullptr.
     * @param lenReturn getReadBuffer() should update *lenReturn to contain the
     *                  maximum number of bytes that may be written to the read
     *                  buffer.  This parameter will never be nullptr.
     *
     *
     * XXX TODO this does not seems to be completely true Checlk i/.
     */
    virtual void getReadBuffer(void **bufReturn, size_t *lenReturn) = 0;

    /**
     * readDataAvailable() will be invoked when data has been successfully read
     * into the buffer returned by the last call to getReadBuffer().
     *
     * The read callback remains installed after readDataAvailable() returns.
     * It must be explicitly uninstalled to stop receiving read events.
     * getReadBuffer() will be called at least once before each call to
     * readDataAvailable().  getReadBuffer() will also be called before any
     * call to readEOF().
     *
     * @param len       The number of bytes placed in the buffer.
     */

    virtual void readDataAvailable(size_t len) noexcept = 0;

    /**
     * When data becomes available, isBufferMovable() will be invoked to figure
     * out which API will be used, readBufferAvailable() or
     * readDataAvailable(). If isBufferMovable() returns true, that means
     * ReadCallback supports the IOBuf ownership transfer and
     * readBufferAvailable() will be used.  Otherwise, not.

     * By default, isBufferMovable() always return false. If
     * readBufferAvailable() is implemented and to be invoked, You should
     * overwrite isBufferMovable() and return true in the inherited class.
     *
     * This method allows the AsyncSocket/AsyncSSLSocket do buffer allocation by
     * itself until data becomes available.  Compared with the pre/post buffer
     * allocation in getReadBuffer()/readDataAvailabe(), readBufferAvailable()
     * has two advantages.  First, this can avoid memcpy. E.g., in
     * AsyncSSLSocket, the decrypted data was copied from the openssl internal
     * buffer to the readbuf buffer.  With the buffer ownership transfer, the
     * internal buffer can be directly "moved" to ReadCallback. Second, the
     * memory allocation can be more precise.  The reason is
     * AsyncSocket/AsyncSSLSocket can allocate the memory of precise size
     * because they have more context about the available data than
     * ReadCallback.  Think about the getReadBuffer() pre-allocate 4072 bytes
     * buffer, but the available data is always 16KB (max OpenSSL record size).
     */

    virtual bool isBufferMovable() noexcept { return false; }

    /**
     * Suggested buffer size, allocated for read operations,
     * if callback is movable and supports folly::IOBuf
     */

    virtual size_t maxBufferSize() const {
      return 64 * 1024;  // 64K
    }

    /**
     * readBufferAvailable() will be invoked when data has been successfully
     * read.
     *
     * Note that only either readBufferAvailable() or readDataAvailable() will
     * be invoked according to the return value of isBufferMovable(). The timing
     * and aftereffect of readBufferAvailable() are the same as
     * readDataAvailable()
     *
     * @param readBuf The unique pointer of read buffer.
     */

    // virtual void readBufferAvailable(uint8_t** buffer, std::size_t
    // *buf_length) noexcept {}

    virtual void readBufferAvailable(
        utils::SharableVector<uint8_t> &&buffer) noexcept {}

    // virtual void readBufferAvailable(utils::SharableBuffer<uint8_t>&& buffer)
    // noexcept {}

    /**
     * readEOF() will be invoked when the transport is closed.
     *
     * The read callback will be automatically uninstalled immediately before
     * readEOF() is invoked.
     */
    virtual void readEOF() noexcept = 0;

    /**
     * readError() will be invoked if an error occurs reading from the
     * transport.
     *
     * The read callback will be automatically uninstalled immediately before
     * readError() is invoked.
     *
     * @param ex        An exception describing the error that occurred.
     */
    virtual void readErr(const std::error_code ec) noexcept = 0;
  };

  // Read methods that aren't part of AsyncTransport.
  virtual void setReadCB(ReadCallback *callback) = 0;
  virtual ReadCallback *getReadCallback() const = 0;

 protected:
  virtual ~AsyncReader() = default;
};

class AsyncWriter {
 public:
  class WriteCallback {
   public:
    virtual ~WriteCallback() = default;

    /**
     * writeSuccess() will be invoked when all of the data has been
     * successfully written.
     *
     * Note that this mainly signals that the buffer containing the data to
     * write is no longer needed and may be freed or re-used.  It does not
     * guarantee that the data has been fully transmitted to the remote
     * endpoint.  For example, on socket-based transports, writeSuccess() only
     * indicates that the data has been given to the kernel for eventual
     * transmission.
     */
    virtual void writeSuccess() noexcept = 0;

    /**
     * writeError() will be invoked if an error occurs writing the data.
     *
     * @param bytesWritten      The number of bytes that were successfull
     * @param ex                An exception describing the error that occurred.
     */
    virtual void writeErr(size_t bytesWritten) noexcept = 0;
  };

  /**
   * If you supply a non-null WriteCallback, exactly one of writeSuccess()
   * or writeErr() will be invoked when the write completes. If you supply
   * the same WriteCallback object for multiple write() calls, it will be
   * invoked exactly once per call. The only way to cancel outstanding
   * write requests is to close the socket (e.g., with closeNow() or
   * shutdownWriteNow()). When closing the socket this way, writeErr() will
   * still be invoked once for each outstanding write operation.
   */
  virtual void write(WriteCallback *callback, const void *buf, size_t bytes,
                     const PublicationOptions &options,
                     WriteFlags flags = WriteFlags::NONE) = 0;

  /**
   * If you supply a non-null WriteCallback, exactly one of writeSuccess()
   * or writeErr() will be invoked when the write completes. If you supply
   * the same WriteCallback object for multiple write() calls, it will be
   * invoked exactly once per call. The only way to cancel outstanding
   * write requests is to close the socket (e.g., with closeNow() or
   * shutdownWriteNow()). When closing the socket this way, writeErr() will
   * still be invoked once for each outstanding write operation.
   */
  virtual void write(WriteCallback *callback,
                     utils::SharableVector<uint8_t> &&output_buffer,
                     const PublicationOptions &options,
                     WriteFlags flags = WriteFlags::NONE) = 0;

  // /**
  //  * If you supply a non-null WriteCallback, exactly one of writeSuccess()
  //  * or writeErr() will be invoked when the write completes. If you supply
  //  * the same WriteCallback object for multiple write() calls, it will be
  //  * invoked exactly once per call. The only way to cancel outstanding
  //  * write requests is to close the socket (e.g., with closeNow() or
  //  * shutdownWriteNow()). When closing the socket this way, writeErr() will
  //  * still be invoked once for each outstanding write operation.
  //  */
  // virtual void writeChain(
  //     WriteCallback* callback,
  //     std::unique_ptr<IOBuf>&& buf,
  //     WriteFlags flags = WriteFlags::NONE) = 0;

  virtual void setWriteCB(WriteCallback *callback) = 0;
  virtual WriteCallback *getWriteCallback() const = 0;

 protected:
  virtual ~AsyncWriter() = default;
};

}  // namespace interface

}  // namespace transport