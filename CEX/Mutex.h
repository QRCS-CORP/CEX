#ifndef CEX_MUTEX_H
#define CEX_MUTEX_H

#include "CexDomain.h"
#if defined(CEX_OS_HASTHREADS)
#	include <mutex>
#endif

NAMESPACE_ROOT

/// cond private

#if defined(CEX_OS_HASTHREADS)

	template<typename T> using lock_guard_type = std::lock_guard<T>;
	typedef std::mutex mutex_type;

#else

	template<typename Mutex>
	class lock_guard final
	{
	public:

		explicit lock_guard(Mutex& m) : m_mutex(m)
		{
			m_mutex.lock();
		}

		~lock_guard() { m_mutex.unlock(); }
		lock_guard(const lock_guard& other) = delete;
		lock_guard& operator=(const lock_guard& other) = delete;

	private:

		Mutex& m_mutex;
	};

	class noop_mutex final
	{
	public:

		void lock() {}
		void unlock() {}
	};

	typedef noop_mutex mutex_type;
	template<typename T> using lock_guard_type = lock_guard<T>;

#endif

	NAMESPACE_ROOTEND
#endif
