#include "MemoryPool.h"

NAMESPACE_UTILITY

using Enumeration::ErrorCodes;

const std::string MemoryPool::CLASS_NAME("MemoryPool");

MemoryPool::MemoryPool(byte* Pool, size_t PoolSize, size_t PageSize, size_t MinAlloc, size_t MaxAlloc, byte AlignBit)
	:
	m_alignBit(AlignBit),
	m_freeList(0),
	m_maxAlloc(MaxAlloc),
	m_memPool(nullptr),
	m_minAlloc(MinAlloc),
	m_pageSize(PageSize),
	m_poolSize(PoolSize)
{
	if (Pool == nullptr)
	{
		throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool pool was null!"), ErrorCodes::IllegalOperation);
	}

	if (m_minAlloc > m_maxAlloc)
	{
		throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool min alloc is more than max alloc!"), ErrorCodes::InvalidSize);
	}

	if (m_alignBit > 6)
	{
		throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool invalid align bit!"), ErrorCodes::InvalidParam);
	}

	Clear(Pool, 0, PoolSize);
	m_memPool = Pool;
	m_poolSize = PoolSize;
	m_freeList.push_back(std::make_pair(0, m_poolSize));
}

void* MemoryPool::Allocate(size_t Length)
{
	const size_t ALNBIT = static_cast<size_t>(1) << m_alignBit;
	std::vector<std::pair<size_t, size_t>>::iterator best;
	std::vector<std::pair<size_t, size_t>>::iterator itrl;
	void* poolr;

	poolr = nullptr;

	if (Length <= m_poolSize && Length >= m_minAlloc && Length <= m_maxAlloc)
	{
		lock_guard_type<mutex_type> lock(m_mutex);

		best = m_freeList.end();

		for (itrl = m_freeList.begin(); itrl != m_freeList.end(); ++itrl)
		{
			// perfect fit
			if (itrl->second == Length && (itrl->first % ALNBIT) == 0)
			{
				const size_t FSTOFT = itrl->first;

				m_freeList.erase(itrl);
				Clear(m_memPool, FSTOFT, Length);

				if ((reinterpret_cast<uintptr_t>(m_memPool) + FSTOFT) % ALNBIT != 0)
				{
					throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool pool is misaligned!"), ErrorCodes::InvalidState);
				}

				poolr = m_memPool + FSTOFT;
			}

			if (((best == m_freeList.end()) || (best->second > itrl->second)) && (itrl->second >= (Length + PadSize(itrl->first, ALNBIT))))
			{
				best = itrl;
			}
		}

		if (best != m_freeList.end())
		{
			const size_t FSTOFT = best->first;
			const size_t ALNPAD = PadSize(FSTOFT, ALNBIT);

			best->first += Length + ALNPAD;
			best->second -= Length + ALNPAD;

			// realign
			if (ALNPAD)
			{
				if (best->second == 0)
				{
					best->first = FSTOFT;
					best->second = ALNPAD;
				}
				else
				{
					m_freeList.insert(best, std::make_pair(FSTOFT, ALNPAD));
				}
			}

			Clear(m_memPool, FSTOFT + ALNPAD, Length);

			if ((reinterpret_cast<uintptr_t>(m_memPool) + FSTOFT + ALNPAD) % ALNBIT != 0)
			{
				throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool pool is misaligned!"), ErrorCodes::InvalidState);
			}

			poolr = m_memPool + FSTOFT + ALNPAD;
		}
	}

	return poolr;
}

bool MemoryPool::Deallocate(void* Pointer, size_t Length)
{
	bool status;
	std::vector<std::pair<size_t, size_t>>::iterator itrl;
	std::vector<std::pair<size_t, size_t>>::iterator prev;

	status = false;

	if (InPool(m_memPool, m_poolSize, Pointer, Length))
	{
		status = true;
		Clear(Pointer, 0, Length);

		lock_guard_type<mutex_type> lock(m_mutex);

		const size_t FSTPTR = static_cast<byte*>(Pointer) - m_memPool;
		itrl = std::lower_bound(m_freeList.begin(), m_freeList.end(), std::make_pair(FSTPTR, 0), [](std::pair<size_t, size_t> x, std::pair<size_t, size_t> y) { return x.first < y.first; });

		if (itrl != m_freeList.end() && FSTPTR + Length == itrl->first)
		{
			itrl->first = FSTPTR;
			itrl->second += Length;
			Length = 0;
		}

		if (itrl != m_freeList.begin())
		{
			prev = std::prev(itrl);

			if (prev->first + prev->second == FSTPTR)
			{
				if (Length)
				{
					prev->second += Length;
					Length = 0;
				}
				else
				{
					prev->second += itrl->second;
					m_freeList.erase(itrl);
				}
			}
		}

		if (Length != 0)
		{
			m_freeList.insert(itrl, std::make_pair(FSTPTR, Length));
		}
	}

	return status;
}

void MemoryPool::Clear(void* Pool, size_t Offset, size_t Length)
{
	// TODO: SecureMemory here?
	std::memset(reinterpret_cast<byte*>(Pool) + Offset, 0x00, Length);
}

bool MemoryPool::InPool(const void* Pointer, size_t PoolSize, const void* Buffer, size_t BufferSize)
{
	const uintptr_t MEMPOOL = reinterpret_cast<uintptr_t>(Pointer);
	const uintptr_t MEMBUF = reinterpret_cast<uintptr_t>(Buffer);

	return (MEMBUF >= MEMPOOL) && (MEMBUF + BufferSize <= MEMPOOL + PoolSize);
}

size_t MemoryPool::PadSize(size_t Length, size_t Alignment)
{
	const size_t MODVAL = Length % Alignment;

	return (MODVAL == 0) ? 0 : Alignment - MODVAL;
}

NAMESPACE_UTILITYEND
