#include "SecureMemory.h"
#include <stdlib.h>

#if defined(CEX_OS_OPENBSD)
#	include <string.h>
#endif
#if defined(CEX_OS_POSIX)
#	include <sys/types.h>
#	include <sys/resource.h>
#	include <sys/mman.h>
#	include <cstdlib>
#	include <signal.h>
#	include <setjmp.h>
#	include <unistd.h>
#	include <errno.h>
#elif defined(CEX_OS_WINDOWS)
#	include <windows.h>
#endif

NAMESPACE_ROOT

const std::string SecureMemory::CLASS_NAME = "SecureMemory";

void* SecureMemory::Allocate(size_t Length)
{
	const size_t PGESZE = PageSize();


	if (Length % PGESZE != 0)
	{
		Length = (Length + PGESZE - (Length % PGESZE));
	}

#if defined(CEX_OS_POSIX)

	void* ptr;

	ptr = nullptr;

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
			::memset(ptr, 0, Length);
			::munmap(ptr, Length);

			// failed to lock
			ptr = nullptr;
		}
#	endif
	}

	return ptr;

#elif defined(CEX_HAS_VIRTUALLOCK)

	LPVOID ptr;

	ptr = ::VirtualAlloc(nullptr, Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (ptr != nullptr)
	{
		if (::VirtualLock(reinterpret_cast<LPVOID>(ptr), Length) == 0)
		{
			::memset(ptr, 0, Length);
			::VirtualFree(reinterpret_cast<LPVOID>(ptr), 0, MEM_RELEASE);

			// failed to lock
			ptr = nullptr;
		}
	}

	return ptr;

#else
	
	byte* ptr;

	ptr = (byte*)malloc(Length);

	return ptr;

#endif
}

const bool SecureMemory::Available()
{
#if defined(CEX_OS_POSIX) || defined(CEX_HAS_VIRTUALLOCK)
	return true;
#else
	return false;
#endif
}

void SecureMemory::Erase(void* Pointer, size_t Length)
{
#if defined(CEX_HAS_RTLSECUREMEMORY)

	::RtlSecureZeroMemory(reinterpret_cast<PVOID>(Pointer), Length);

#elif defined(CEX_OS_OPENBSD)

	::explicit_bzero(Pointer, Length);

#elif defined(CEX_VOLATILE_MEMSET)

	static void* (*const volatile memsetptr)(void*, int, size_t) = std::memset;
	(memsetptr)(Pointer, 0, Length);

#else

	volatile byte* ptr = reinterpret_cast<volatile byte*>(Pointer);
	size_t i;

	for (i = 0; i != Length; ++i)
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

		if (Pointer != nullptr)
		{
			::VirtualUnlock(reinterpret_cast<LPVOID>(Pointer), Length);
			::VirtualFree(reinterpret_cast<LPVOID>(Pointer), 0, MEM_RELEASE);
		}

#else

		free((byte*)Pointer);

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
		overhead = PageSize() * 0x000BUL;

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

	pagelen = 0x00001000LL;

#if defined(CEX_OS_POSIX)

	pagelen = ::sysconf(_SC_PAGESIZE);

	if (pagelen < 1)
	{
		pagelen = CEX_SECMEMALLOC_DEFAULT;
	}

#elif defined(CEX_OS_WINDOWS)

	SYSTEM_INFO sysinfo;
	::GetSystemInfo(&sysinfo);
	pagelen = static_cast<long>(sysinfo.dwPageSize);

#endif

	return static_cast<size_t>(pagelen);
}

NAMESPACE_ROOTEND