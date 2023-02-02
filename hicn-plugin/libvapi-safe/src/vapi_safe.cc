/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include <vapi/vapi_safe.h>
}

#include <thread>
#include <random>
#include <asio.hpp>
#include <iostream>

namespace
{
class NonCopyable
{
protected:
  NonCopyable () = default;
  ~NonCopyable () = default;

  NonCopyable (const NonCopyable &) = delete;
  NonCopyable &operator= (const NonCopyable &) = delete;
};

template <typename T> class Singleton : NonCopyable
{
public:
  static T &
  getInstance ()
  {
    static T instance;
    return instance;
  }

protected:
  Singleton () {}
  ~Singleton () {}
};

template <typename T> class ThreadLocalSingleton : NonCopyable
{
public:
  static T &
  getInstance ()
  {
    static thread_local T instance;
    return instance;
  }

protected:
  ThreadLocalSingleton () {}
  ~ThreadLocalSingleton () {}
};

class EventThread
{
public:
  EventThread (asio::io_service &io_service, bool detached = false)
      : internal_io_service_ (nullptr), io_service_ (std::ref (io_service)),
	work_guard_ (asio::make_work_guard (io_service_.get ())),
	thread_ (nullptr), detached_ (detached)
  {
    run ();
  }

  explicit EventThread (bool detached = false)
      : internal_io_service_ (std::make_unique<asio::io_service> ()),
	io_service_ (std::ref (*internal_io_service_)),
	work_guard_ (asio::make_work_guard (io_service_.get ())),
	thread_ (nullptr), detached_ (detached)
  {
    run ();
  }

  EventThread (const EventThread &) = delete;
  EventThread &operator= (const EventThread &) = delete;

  EventThread (EventThread &&other) noexcept
      : internal_io_service_ (std::move (other.internal_io_service_)),
	io_service_ (std::move (other.io_service_)),
	work_guard_ (std::move (other.work_guard_)),
	thread_ (std::move (other.thread_)),
	detached_ (other.detached_)
  {
  }

  ~EventThread () { stop (); }

  void
  run ()
  {
    if (stopped ())
      {
	io_service_.get ().stopped ();
      }

    thread_ =
      std::make_unique<std::thread> ([this] () { io_service_.get ().run (); });

    if (detached_)
      {
	thread_->detach ();
      }
  }

  std::thread::id
  getThreadId () const
  {
    if (thread_)
      {
	return thread_->get_id ();
      }
    else
      {
	throw std::runtime_error ("Event thread is not running.");
      }
  }

  template <typename Func>
  void
  add (Func &&f)
  {
    io_service_.get ().post (std::forward<Func> (f));
  }

  template <typename Func>
  void
  tryRunHandlerNow (Func &&f)
  {
    io_service_.get ().dispatch (std::forward<Func> (f));
  }

  template <typename Func>
  void
  addAndWaitForExecution (Func &&f) const
  {
    auto promise = std::promise<void> ();
    auto future = promise.get_future ();

    asio::dispatch (io_service_.get (),
		    [&promise, f = std::forward<Func> (f)] () {
		      f ();
		      promise.set_value ();
		    });

    future.wait ();
  }

  void
  stop ()
  {
    add ([this] () { work_guard_.reset (); });

    if (thread_ && thread_->joinable ())
      {
	thread_->join ();
      }

    thread_.reset ();
  }

  bool
  stopped () const
  {
    return io_service_.get ().stopped ();
  }

  asio::io_service &
  getIoService ()
  {
    return io_service_;
  }

private:
  std::unique_ptr<asio::io_service> internal_io_service_;
  std::reference_wrapper<asio::io_service> io_service_;
  asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
  std::unique_ptr<std::thread> thread_;
  bool detached_;
};

class UUID : public Singleton<UUID>
{
  friend class Singleton<UUID>;
  static inline unsigned char hex_chars[16] = { '0', '1', '2', '3', '4', '5',
						'6', '7', '8', '9', 'a', 'b',
						'c', 'd', 'e', 'f' };

public:
  static inline constexpr unsigned int UUID_LEN = 64;

  ~UUID () = default;
  std::string
  generate ()
  {
    return generate_hex (UUID_LEN);
  }

  std::string
  generate_hex (const unsigned int len)
  {
    std::string ret (len, 0);

    for (auto &c : ret)
      {
	c = random_char ();
      }

    return ret;
  }

private:
  UUID () : rd_ (), gen_ (rd_ ()), dis_ (0, sizeof (hex_chars) - 1) {}

  unsigned char
  random_char ()
  {
    return hex_chars[dis_ (gen_)];
  }

private:
  std::random_device rd_;
  std::mt19937 gen_;
  std::uniform_int_distribution<> dis_;
};

} // namespace

DEFINE_VAPI_MSG_IDS_HICN_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON
DEFINE_VAPI_MSG_IDS_UDP_API_JSON
DEFINE_VAPI_MSG_IDS_MEMIF_API_JSON

class VapiGlobalConnection : public Singleton<VapiGlobalConnection>
{
  friend class Singleton<VapiGlobalConnection>;

  static inline char kapp_name[] = "hicn_app";
  static inline char kapi_prefix[] = "";
  static inline int kresponse_queue_size = 32;
  static inline int kmax_outstanding_requests = 32;
  static inline uint32_t ktimeout_seconds = 1;

public:
  vapi_error_e
  vapiConnectSafe (vapi_ctx_t *vapi_ctx_ret)
  {
    if (isConnected ())
      {
	*vapi_ctx_ret = vapi_ctx_;
	return VAPI_OK;
      }

    std::unique_lock<std::mutex> lock (vapi_mtx_);

    auto rv = vapi_ctx_alloc (&vapi_ctx_);
    if (rv != VAPI_OK)
      {
	return rv;
      }

    rv = vapi_connect (vapi_ctx_, app_name_.c_str (), nullptr,
		       max_outstanding_requests_, response_queue_size_,
		       VAPI_MODE_BLOCKING, 1);
    connected_ = true;

    vapi_set_generic_event_cb (vapi_ctx_, &VapiGlobalConnection::genericCb,
			       nullptr);

    if (rv == VAPI_OK)
      {
	// startDispatcher ();
	*vapi_ctx_ret = vapi_ctx_;
      }

    return rv;
  }

  void
  vapiLock ()
  {
    vapi_mtx_.lock ();
  }

  void
  vapiUnLock ()
  {
    vapi_mtx_.unlock ();
  }

  bool
  isConnected ()
  {
    return connected_;
  }

  ~VapiGlobalConnection ()
  {
    if (!isConnected ())
      {
	return;
      }
    std::unique_lock<std::mutex> lock (vapi_mtx_);
    vapi_disconnect (vapi_ctx_);
    vapi_ctx_free (vapi_ctx_);
    try
      {
	timer_.cancel ();
      }
    catch (asio::system_error e)
      {
	// quit anyway
      }
  }

private:
  VapiGlobalConnection (
    const std::string &app_name = std::string (kapp_name) + "_" +
				  UUID::getInstance ().generate_hex (5),
    const std::string &api_prefix = kapi_prefix,
    int max_outstanding_requests = kmax_outstanding_requests,
    int response_queue_size = kresponse_queue_size)
      : app_name_ (app_name), api_prefix_ (api_prefix),
	max_outstanding_requests_ (max_outstanding_requests),
	response_queue_size_ (response_queue_size), vapi_mtx_ (),
	vapi_ctx_ (nullptr), connected_ (false), thread_ (),
	timer_ (thread_.getIoService ())
  {
  }

  void
  timerHandler (const std::error_code &ec)
  {
    if (ec)
      {
	// Timer was canceled
	return;
      }

    if (!isConnected ())
      {
	return;
      }

    std::unique_lock<std::mutex> lock (vapi_mtx_);
    auto err = vapi_dispatch (vapi_ctx_);
    if (err != VAPI_OK)
      {
	return;
      }

    startDispatcher ();
  }

  void
  startDispatcher ()
  {
    timer_.expires_after (std::chrono::seconds (ktimeout_seconds));
    timer_.async_wait (std::bind (&VapiGlobalConnection::timerHandler, this,
				  std::placeholders::_1));
  }

  static vapi_error_e
  genericCb (vapi_ctx_t ctx, void *callback_ctx, vapi_msg_id_t id, void *msg)
  {
    std::cout << "Called" << std::endl;
    return VAPI_OK;
  }

private:
  std::string app_name_;
  std::string api_prefix_;
  int max_outstanding_requests_;
  int response_queue_size_;
  std::mutex vapi_mtx_;
  vapi_ctx_t vapi_ctx_;
  std::atomic_bool connected_;
  EventThread thread_;
  asio::steady_timer timer_;
};

vapi_error_e
vapi_connect_safe (vapi_ctx_t *vapi_ctx_ret, int async)
{
  return VapiGlobalConnection::getInstance ().vapiConnectSafe (vapi_ctx_ret);
}

vapi_error_e
vapi_disconnect_safe ()
{
  return VAPI_OK;
}

void
vapi_lock ()
{
  VapiGlobalConnection::getInstance ().vapiLock ();
}

void
vapi_unlock ()
{
  VapiGlobalConnection::getInstance ().vapiUnLock ();
}
