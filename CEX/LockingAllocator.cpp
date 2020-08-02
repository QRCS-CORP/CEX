#include "LockingAllocator.h"
#include "SecureMemory.h"
#include <cstdlib>
#include <memory>

NAMESPACE_TOOLS

using Exception::CryptoException;
using Enumeration::ErrorCodes;
using Tools::MemoryPool;

//~~~LockingAllocator~~~//

LockingAllocator::LockingAllocator()
	:
	m_lockedPages(nullptr),
	m_lockedPagesSize(0)
{
	const size_t LCKLMT = SecureMemory::Limit();

	if (LCKLMT)
	{
		m_lockedPages = static_cast<byte*>(SecureMemory::Allocate(LCKLMT));

		if (m_lockedPages)
		{
			m_lockedPagesSize = LCKLMT;
			m_memoryPool.reset(new MemoryPool(m_lockedPages, m_lockedPagesSize, SecureMemory::PageSize(), CEX_SECMEMALLOC_MIN, CEX_SECMEMALLOC_MAX, 4));
		}
	}
}

LockingAllocator::~LockingAllocator()
{
	if (m_memoryPool != nullptr)
	{
		m_memoryPool.reset();
		SecureMemory::Free(m_lockedPages, m_lockedPagesSize);
	}

	m_lockedPages = nullptr;
	m_lockedPagesSize = 0;
	m_memoryPool = nullptr;
}

LockingAllocator& LockingAllocator::Instance()
{
	static LockingAllocator mlock;

	return mlock;
}

void* LockingAllocator::allocate(size_t Elements, size_t ElementSize)
{
	const size_t ELMLEN = Elements * ElementSize;
	void* ptr;

	ptr = nullptr;

	if (m_memoryPool != nullptr && (ELMLEN / ElementSize != Elements))
	{
		ptr = m_memoryPool->Allocate(ELMLEN);
	}

	return ptr;
}

bool LockingAllocator::deallocate(void* Pointer, size_t Elements, size_t ElementSize)
{
	const size_t ELMLEN = Elements * ElementSize;
	bool ret;

	ret = false;

	if (m_memoryPool != nullptr && (ELMLEN / ElementSize != Elements))
	{
		ret = m_memoryPool->Deallocate(Pointer, ELMLEN);
	}

	return ret;
}

CEX_MALLOC_FN void* LockingAllocator::Allocate(size_t Elements, size_t ElementSize)
{
	void* ptr;

	ptr = nullptr;

#if defined(CEX_SECURE_ALLOCATOR)
	ptr = LockingAllocator::Instance().allocate(Elements, ElementSize);
#endif

	if (ptr == nullptr)
	{
		ptr = std::calloc(Elements, ElementSize);

		if (ptr == nullptr)
		{
			throw CryptoException(std::string("LockingAllocator"), std::string("Allocate"), std::string("Memory allocation has failed!"), ErrorCodes::IllegalOperation);
		}
	}

	return ptr;
}

void LockingAllocator::Deallocate(void* Pointer, size_t Elements, size_t ElementSize)
{
	if (Pointer != nullptr)
	{
		const size_t ELMLEN = Elements * ElementSize;

		SecureMemory::Erase(Pointer, ELMLEN);

#if defined(CEX_SECURE_ALLOCATOR)
		if (LockingAllocator::Instance().deallocate(Pointer, Elements, ElementSize))
		{
			Pointer = nullptr;
		}
#endif

		if (Pointer != nullptr)
		{
			std::free(Pointer);
			Pointer = nullptr;
		}
	}
}

NAMESPACE_TOOLSEND