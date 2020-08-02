#ifndef CEX_MEMORYPOOL_H
#define CEX_MEMORYPOOL_H

#include "CexDomain.h"
#include "CryptoException.h"
#include <cstdlib>
#include <mutex>

NAMESPACE_TOOLS

using Exception::CryptoException;

/// <summary>
/// A raw memory storage container.
/// <para>Based on the Botan mem_pool class, re-written for Misra compliance.</para>
/// </summary>
class MemoryPool
{
private:

	static const std::string CLASS_NAME;
	class PoolState;

	std::unique_ptr<PoolState> m_poolState;

public:

	/// <summary>
	/// Constructor: instantiate this class using a block of raw memory
	/// </summary>
	/// 
	/// <param name="Pool">The pointer to the memory</param>
	/// <param name="PoolSize">The size in bytes of the memory</param>
	/// <param name="PageSize">The size of the system memory page</param>
	/// <param name="MinAlloc">The minimum allocation allowed</param>
	/// <param name="MaxAlloc">The maximum allocation allowed</param>
	/// <param name="AlignBit">The alignment bit</param>
	///
	/// <exception cref="CryptoException">Thrown if invalid parameters are passed</exception>
	MemoryPool(byte* Pool, size_t PoolSize, size_t PageSize, size_t MinAlloc, size_t MaxAlloc, byte AlignBit);

	/// <summary>
	/// Class destructor
	/// </summary>
	~MemoryPool();

	/// <summary>
	/// Allocate a length of bytes and return a pointer to the memory
	/// </summary>
	/// 
	/// <param name="Length">The number of bytes to allocate from the pool</param>
	///
	/// <returns>Returns a pointer to the allocated memory</returns>
	///
	/// <exception cref="CryptoException">Thrown if invalid parameters are passed</exception>
	void* Allocate(size_t Length);

	/// <summary>
	/// Deallocate a length of bytes and return the status of the operation
	/// </summary>
	/// 
	/// <param name="Pointer">The pointer to the pool of memory</param>
	/// <param name="Length">The number of bytes to deallocate from the pool</param>
	///
	/// <returns>Returns true if the operation was successful</returns>
	bool Deallocate(void* Pointer, size_t Length);

	/// <summary>
	/// Reset the memory pool
	/// </summary>
	void Reset();

private:

	static void Clear(void* Pool, size_t Offset, size_t Length);
	static bool InPool(const void* Pointer, size_t PoolSize, const void* Buffer, size_t BufferSize);
	static size_t PadSize(size_t Length, size_t Alignment);
};

NAMESPACE_TOOLSEND
#endif
