#include "SecureMemory.h"

NAMESPACE_COMMON

size_t SecureMemory::Allocate(void* Pointer, size_t Length)
{
	const size_t PGESZE = PageSize();

	// avoid unnecessary page length boundary errors, and return correct size
	if (Length % PGESZE != 0)
	{
		Length = (Length + PGESZE - (Length % PGESZE));
	}

#if defined(CEX_OS_POSIX)

#	if !defined(MAP_NOCORE)
#		define MAP_NOCORE 0
#	endif

#	if !defined(MAP_ANONYMOUS)
#		define MAP_ANONYMOUS MAP_ANON
#	endif

	void* Pointer = ::mmap(nullptr, Length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE, -1, 0);

	if (Pointer == MAP_FAILED)
	{
		Pointer = nullptr;
		return 0;
	}

#	if defined(MADV_DONTDUMP)
		::madvise(Pointer, Length, MADV_DONTDUMP);
#	endif

#	if defined(CEX_HAS_POSIXMLOCK)
	if (::mlock(Pointer, Length) != 0)
	{
		::munmap(Pointer, Length);

		// failed to lock
		Pointer = nullptr;
		return 0;
	}
#	endif

	::memset(Pointer, 0, Length);

#elif defined(CEX_HAS_VIRTUALLOCK)

	LPVOID ptr = ::VirtualAlloc(nullptr, Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!ptr)
	{
		Pointer = nullptr;
		return 0;
	}

	if (::VirtualLock(Pointer, Length) == 0)
	{
		::VirtualFree(Pointer, 0, MEM_RELEASE);

		// failed to lock
		Pointer = nullptr;
		return 0;
	}

#else
	// not implemented
	Pointer = nullptr;
	return 0;

#endif

	return Length;
}

void SecureMemory::Erase(void* Pointer, size_t Length)
{
#if defined(CEX_HAS_RTLSECUREMEMORY)

	::RtlSecureZeroMemory(Pointer, Length);

#elif defined(CEX_OS_OPENBSD)

	::explicit_bzero(Pointer, Length);

#elif defined(CEX_VOLATILE_MEMSET)

	static void* (*const volatile memsetptr)(void*, int, size_t) = std::memset;
	(memsetptr)(Pointer, 0, Length);

#else

	volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(Pointer);

	for (size_t i = 0; i != Length; ++i)
	{
		Pointer[i] = 0;
	}

#endif
}

void SecureMemory::Free(void* Pointer, size_t Length)
{
	if (Pointer == nullptr || Length == 0)
	{
		return;
	}

#if defined(CEX_OS_POSIX)

	Erase(Pointer, Length);

#	if defined(CEX_HAS_POSIXMLOCK)
		::munlock(Pointer, Length);
#	endif

	::munmap(Pointer, Length);

#elif defined(CEX_HAS_VIRTUALLOCK)

	Erase(Pointer, Length);
	::VirtualUnlock(Pointer, Length);
	::VirtualFree(Pointer, 0, MEM_RELEASE);

#else

	throw CryptoException("SecureMemory::Free", "Invalid pointer to locked pages.");

#endif
}

size_t SecureMemory::Limit()
{
#if defined(CEX_OS_POSIX)

	size_t mreq = CEX_SECMEMALLOC_MAXKB;

	// allow override via environment variable
	if (const char* env = std::getenv("CEX_MLOCKPOOL_SIZE"))
	{
		try
		{
			const size_t ureq = std::stoul(env, nullptr);
			mreq = std::min(ureq, mreq);
		}
		catch (std::exception&) {}
	}

#	if defined(RLIMIT_MEMLOCK)

	if (mreq > 0)
	{
		struct ::rlimit limits;

		::getrlimit(RLIMIT_MEMLOCK, &limits);

		if (limits.rlim_cur < limits.rlim_max)
		{
			limits.rlim_cur = limits.rlim_max;
			::setrlimit(RLIMIT_MEMLOCK, &limits);
			::getrlimit(RLIMIT_MEMLOCK, &limits);
		}

		return std::min<size_t>(limits.rlim_cur, mreq * 1024);
	}

#	else

	// if RLIMIT_MEMLOCK is not defined, likely the OS does not support unprivileged mlock calls
	return 0;

#	endif

#elif defined(CEX_HAS_VIRTUALLOCK)

	size_t lockable;
	size_t overhead;
	SIZE_T wmax;
	SIZE_T wmin;

	wmax = 0;
	wmin = 0;

	if (!::GetProcessWorkingSetSize(::GetCurrentProcess(), &wmin, &wmax))
	{
		return 0;
	}

	overhead = PageSize() * 11ULL;

	if (wmin > overhead)
	{
		lockable = wmin - overhead;

		if (lockable < (CEX_SECMEMALLOC_MAXKB * 1024ULL))
		{
			return lockable;
		}
		else
		{
			return CEX_SECMEMALLOC_MAXKB * 1024ULL;
		}
	}

#endif

	return 0;
}

size_t SecureMemory::PageSize()
{
#if defined(CEX_OS_POSIX)

	long p = ::sysconf(_SC_PAGESIZE);

	if (p > 1)
	{
		return static_cast<size_t>(p);
	}
	else
	{
		return CEX_SECMEMALLOC_DEFAULT;
	}

#elif defined(CEX_HAS_VIRTUALLOCK)

	SYSTEM_INFO sysinfo;
	::GetSystemInfo(&sysinfo);
	return sysinfo.dwPageSize;

#else

	// default value
	return 4096;

#endif
}

NAMESPACE_COMMONEND