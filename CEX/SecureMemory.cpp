#include "SecureMemory.h"

NAMESPACE_ROOT

void* SecureMemory::Allocate(size_t Length)
{
	const size_t PGESZE = PageSize();
	void* ptr;

	ptr = nullptr;

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

	ptr = ::mmap(nullptr, Length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE, -1, 0);

	if (ptr == MAP_FAILED)
	{
		ptr = nullptr;
	}

	if (ptr != nullptr)
	{
#	if defined(MADV_DONTDUMP)
		::madvise(ptr, Length, MADV_DONTDUMP);
#	endif

#	if defined(CEX_HAS_POSIXMLOCK)
		if (::mlock(ptr, Length) != 0)
		{
			::munmap(ptr, Length);
			::memset(ptr, 0, Length);
			// failed to lock
			ptr = nullptr;
		}
#	endif
	}

#elif defined(CEX_HAS_VIRTUALLOCK)

	(LPVOID)ptr = ::VirtualAlloc(nullptr, Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (ptr != nullptr)
	{
		if (::VirtualLock(ptr, Length) == 0)
		{
			::VirtualFree(ptr, 0, MEM_RELEASE);
			::memset(ptr, 0, Length);
			// failed to lock
			ptr = nullptr;
		}
	}

#endif

	return ptr;
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

	volatile byte* ptr = reinterpret_cast<volatile byte*>(Pointer);

	for (size_t i = 0; i != Length; ++i)
	{
		ptr[i] = 0;
	}

#endif
}

void SecureMemory::Free(void* Pointer, size_t Length)
{
	if (Pointer != nullptr || Length != 0)
	{
		
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

		throw CryptoException(std::string("SecureMemory"), std::string("Free"), std::string("Secure memory not supported on this system!"), Enumeration::ErrorCodes::NoAccess);

#endif
	}
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

#elif defined(CEX_OS_WINDOWS)

	size_t lockable;
	size_t overhead;
	SIZE_T wmax;
	SIZE_T wmin;

	lockable = CEX_SECMEMALLOC_MAXKB * 1024ULL;
	wmax = 0;
	wmin = 0;

	if (::GetProcessWorkingSetSize(::GetCurrentProcess(), &wmin, &wmax))
	{
		overhead = PageSize() * 11ULL;

		if (wmin > overhead)
		{
			lockable = wmin - overhead;
		}
	}

#endif

	return lockable;
}

size_t SecureMemory::PageSize()
{
	long pagelen;

	pagelen = 4096;

#if defined(CEX_OS_POSIX)

	pagelen = ::sysconf(_SC_PAGESIZE);

	if (pagelen < 1)
	{
		pagelen = CEX_SECMEMALLOC_DEFAULT;
	}

	return static_cast<size_t>(pagelen);

#elif defined(CEX_OS_WINDOWS)

	SYSTEM_INFO sysinfo;
	::GetSystemInfo(&sysinfo);
	pagelen = static_cast<size_t>(sysinfo.dwPageSize);

	return static_cast<size_t>(pagelen);

#endif

	return static_cast<size_t>(pagelen);
}

NAMESPACE_ROOTEND