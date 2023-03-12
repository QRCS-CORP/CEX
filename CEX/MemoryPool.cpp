#include "MemoryPool.h"

NAMESPACE_TOOLS

using Enumeration::ErrorCodes;


const std::string MemoryPool::CLASS_NAME("MemoryPool");

class MemoryPool::PoolState
{
public:

	uint8_t AlignBit;
	std::vector<std::pair<size_t, size_t>> FreeList;
	size_t MaxAlloc;
	uint8_t* MemPool;
	size_t MinAlloc;
	size_t PageSize;
	size_t PoolSize;

	PoolState(uint8_t* Pool, size_t PoolSize, size_t PageSize, size_t MinAlloc, size_t MaxAlloc, uint8_t AlignBit)
		:
		AlignBit((AlignBit <= 6) ?
			AlignBit : 
			throw CryptoException(std::string("MemoryPool"), std::string("Constructor"), std::string("MemoryPool invalid align bit!"), ErrorCodes::InvalidParam)),
		FreeList(0),
		MaxAlloc(MaxAlloc),
		MemPool((Pool != nullptr) ? 
			Pool : 
			throw CryptoException(std::string("MemoryPool"), std::string("Constructor"), std::string("MemoryPool pool was null!"), ErrorCodes::IllegalOperation)),
		MinAlloc((MinAlloc <= MaxAlloc) ? 
			MinAlloc :
			throw CryptoException(std::string("MemoryPool"), std::string("Constructor"), std::string("MemoryPool min alloc is more than max alloc!"), ErrorCodes::InvalidSize)),
		PageSize(PageSize),
		PoolSize(PoolSize)
	{
	}

	~PoolState()
	{
		AlignBit = 0;
		FreeList.clear();
		MaxAlloc = 0;
		MemPool = nullptr;
		MinAlloc = 0;
		PageSize = 0;
		PoolSize = 0;
	}
};

MemoryPool::MemoryPool(uint8_t* Pool, size_t PoolSize, size_t PageSize, size_t MinAlloc, size_t MaxAlloc, uint8_t AlignBit)
	:
	m_poolState(new PoolState(Pool, PoolSize, PageSize, MinAlloc, MaxAlloc, AlignBit))
{
	Reset();
}

MemoryPool::~MemoryPool()
{
	if (m_poolState != nullptr)
	{
		m_poolState.reset(nullptr);
	}
}

void* MemoryPool::Allocate(size_t Length)
{
	std::vector<std::pair<size_t, size_t>>::iterator best;
	std::vector<std::pair<size_t, size_t>>::iterator itrl;
	std::mutex m;
	void* poolr;

	std::lock_guard<std::mutex> lock(m);
	poolr = nullptr;

	if (Length <= m_poolState->PoolSize && Length >= m_poolState->MinAlloc && Length <= m_poolState->MaxAlloc)
	{
		const size_t ALNBIT = static_cast<size_t>(1) << m_poolState->AlignBit;
		best = m_poolState->FreeList.end();

		for (itrl = m_poolState->FreeList.begin(); itrl != m_poolState->FreeList.end(); ++itrl)
		{
			// perfect fit
			if (itrl->second == Length && (itrl->first % ALNBIT) == 0)
			{
				const size_t FSTOFT = itrl->first;

				m_poolState->FreeList.erase(itrl);
				Clear(m_poolState->MemPool, FSTOFT, Length);

				if ((reinterpret_cast<uintptr_t>(m_poolState->MemPool) + FSTOFT) % ALNBIT != 0)
				{
					throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool pool is misaligned!"), ErrorCodes::InvalidState);
				}

				poolr = m_poolState->MemPool + FSTOFT;
			}

			if (((best == m_poolState->FreeList.end()) || (best->second > itrl->second)) && (itrl->second >= (Length + PadSize(itrl->first, ALNBIT))))
			{
				best = itrl;
			}
		}

		if (best != m_poolState->FreeList.end())
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
					m_poolState->FreeList.insert(best, std::make_pair(FSTOFT, ALNPAD));
				}
			}

			Clear(m_poolState->MemPool, FSTOFT + ALNPAD, Length);

			if ((reinterpret_cast<uintptr_t>(m_poolState->MemPool) + FSTOFT + ALNPAD) % ALNBIT != 0)
			{
				throw CryptoException(CLASS_NAME, std::string("Constructor"), std::string("MemoryPool pool is misaligned!"), ErrorCodes::InvalidState);
			}

			poolr = m_poolState->MemPool + FSTOFT + ALNPAD;
		}
	}

	return poolr;
}

void MemoryPool::Reset()
{
	Clear(m_poolState->MemPool, 0, m_poolState->PoolSize);
	m_poolState->FreeList.push_back(std::make_pair(0, m_poolState->PoolSize));
}

bool MemoryPool::Deallocate(void* Pointer, size_t Length)
{
	bool status;
	std::vector<std::pair<size_t, size_t>>::iterator itrl;
	std::vector<std::pair<size_t, size_t>>::iterator prev;
	std::mutex m;
	std::lock_guard<std::mutex> lock(m);

	status = false;

	if (InPool(m_poolState->MemPool, m_poolState->PoolSize, Pointer, Length))
	{
		status = true;
		Clear(Pointer, 0, Length);

		const size_t FSTPTR = static_cast<uint8_t*>(Pointer) - m_poolState->MemPool;
		itrl = std::lower_bound(m_poolState->FreeList.begin(), m_poolState->FreeList.end(), std::make_pair(FSTPTR, 0), [](std::pair<size_t, size_t> x, std::pair<size_t, size_t> y) { return x.first < y.first; });

		if (itrl != m_poolState->FreeList.end() && FSTPTR + Length == itrl->first)
		{
			itrl->first = FSTPTR;
			itrl->second += Length;
			Length = 0;
		}

		if (itrl != m_poolState->FreeList.begin())
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
					m_poolState->FreeList.erase(itrl);
				}
			}
		}

		if (Length != 0)
		{
			m_poolState->FreeList.insert(itrl, std::make_pair(FSTPTR, Length));
		}

	}

	return status;
}

void MemoryPool::Clear(void* Pool, size_t Offset, size_t Length)
{
	std::memset(reinterpret_cast<uint8_t*>(Pool) + Offset, 0x00, Length);
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

NAMESPACE_TOOLSEND
