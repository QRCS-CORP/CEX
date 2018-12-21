#ifndef CEX_SECUREMEMORY_H
#define CEX_SECUREMEMORY_H

#include "CexDomain.h"
#include "CryptoException.h"

#if defined(CEX_OS_OPENBSD)
#include <string.h>
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

NAMESPACE_COMMON

using Exception::CryptoException;

/// <summary>
/// 
/// </summary>
class SecureMemory
{
public:

	/// <summary>
	/// Allocate a set of memory pages locked to this process.
	/// <para>If a length call does not align to the page size boundary, it will return a rounded up to a multiple of the system memory page size</para>
	/// </summary>
	///
	/// <param name="Pointer">The pointer to the buffer to be allocated</param>
	/// <param name="Length">The number of bytes in the allocatation request</param>
	/// 
	/// <returns>The number of bytes allocated, zero for allocation failure</returns>
	static size_t Allocate(void* Pointer, size_t Length);

	/// <summary>
	/// Securely erase an array of data
	/// </summary>
	///
	/// <param name="Pointer">A pointer to the base address of the memory to be erased</param>
	/// <param name="Length">The number of bytes to erase</param>
	static void Erase(void* Pointer, size_t Length);

	/// <summary>
	/// Free memory pages locked to this process
	/// </summary>
	///
	/// <param name="Pointer">A pointer to the base address of the locked pages</param>
	/// <param name="Length">The number of bytes to allocate; should be a multiple of the system page size</param>
	static void Free(void* Pointer, size_t Length);

	/// <summary>
	/// The maximum number of bytes that can be locked on this system
	/// </summary>
	/// 
	/// <returns></returns>
	static size_t Limit();

	/// <summary>
	/// Get the size of the system memory page
	/// </summary>
	/// 
	/// <returns>The size in bytes of the system memory page</returns>
	static size_t PageSize();
};

NAMESPACE_COMMONEND
#endif
