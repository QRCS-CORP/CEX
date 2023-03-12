#ifndef CEX_LOCKINGALLOCATOR_H
#define CEX_LOCKINGALLOCATOR_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "MemoryPool.h"

NAMESPACE_TOOLS

/// cond private

/// <summary>
/// Internal class locking allocator for secure vector implementation
/// </summary>
class LockingAllocator final
{
private:

	uint8_t* m_lockedPages;
	size_t m_lockedPagesSize;
	std::unique_ptr<MemoryPool> m_memoryPool;

	LockingAllocator(const LockingAllocator&) = delete;

	LockingAllocator& operator=(const LockingAllocator&) = delete;

	LockingAllocator();

	~LockingAllocator();

public:

	static CEX_MALLOC_FN void* Allocate(size_t Elements, size_t ElementSize);

	static void Deallocate(void* Pointer, size_t Elements, size_t ElementSize);

	static LockingAllocator& Instance();

	void* allocate(size_t Elements, size_t ElementSize);

	bool deallocate(void* Pointer, size_t Elements, size_t ElementSize);
};

NAMESPACE_TOOLSEND
#endif
