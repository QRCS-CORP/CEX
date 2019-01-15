#ifndef CEX_SECUREVECTOR_H
#define CEX_SECUREVECTOR_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "MemoryPool.h"
#include <deque>

NAMESPACE_ROOT

using Utility::MemoryPool;

/*! \cond private */

class LockingAllocator final
{
private:

	byte* m_lockedPages;
	size_t m_lockedPagesSize;
	std::unique_ptr<MemoryPool> m_memoryPool;

	LockingAllocator(const LockingAllocator&) = delete;

	LockingAllocator& operator=(const LockingAllocator&) = delete;

	LockingAllocator();

	~LockingAllocator();

public:

	static LockingAllocator& Instance();

	void* allocate(size_t Elements, size_t ElementSize);

	bool deallocate(void* Pointer, size_t Elements, size_t ElementSize);
};

template<typename T>
class SecureAllocator
{
public:

#if !defined(_ITERATOR_DEBUG_LEVEL) || _ITERATOR_DEBUG_LEVEL == 0
	static_assert(std::is_integral<T>::value, "SecureAllocator supports only integer types");
#endif

	typedef T value_type;
	typedef size_t size_type;

#if defined(CEX_COMPILER_MSC)

	SecureAllocator() = default;
	SecureAllocator(const SecureAllocator&) = default;
	SecureAllocator& operator=(const SecureAllocator&) = default;
	~SecureAllocator() = default;

	template <typename U>
	struct rebind
	{
		typedef SecureAllocator<U> other;
	};

#else

	SecureAllocator() noexcept = default;
	SecureAllocator(const SecureAllocator&) noexcept = default;
	SecureAllocator& operator=(const SecureAllocator&) noexcept = default;
	~SecureAllocator() noexcept = default;

#endif

	template<typename U>
	SecureAllocator(const SecureAllocator<U>&) noexcept {}

	T* allocate(size_t n)
	{
		return static_cast<T*>(AllocatorTools::Allocate(n, sizeof(T)));
	}

	void deallocate(T* p, size_t n)
	{
		AllocatorTools::Deallocate(p, n, sizeof(T));
	}
};

template<typename T> using SecureDeque = std::deque<T, SecureAllocator<T>>;

template<typename T> using SecureVector = std::vector<T, SecureAllocator<T>>;

template<typename T, typename U> inline bool operator == (const SecureAllocator<T>&, const SecureAllocator<U>&) { return true; }

template<typename T, typename U> inline bool operator != (const SecureAllocator<T>&, const SecureAllocator<U>&) { return false; }

template<typename T, typename Alloc, typename Alloc2>
std::vector<T, Alloc>& operator += (std::vector<T, Alloc> &Output, const std::vector<T, Alloc2> &Input)
{
	const size_t CPYOFT = Output.size();

	Output.resize(Output.size() + Input.size());

	if (Input.size() > 0)
	{
		std::memcpy(&Output[CPYOFT], Input.data(), Input.size());
	}

	return Output;
}

template<typename T, typename Alloc>
std::vector<T, Alloc>& operator += (std::vector<T, Alloc> &Output, T Input)
{
	Output.push_back(Input);

	return Output;
}

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator += (std::vector<T, Alloc> &Output, const std::pair<const T*, L> &Input)
{
	const size_t CPYOFT = Output.size();

	Output.resize(Output.size() + Input.second);

	if (Input.second > 0)
	{
		std::memcpy(&Output[CPYOFT], Input.first, Input.second);
	}

	return Output;
}

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator += (std::vector<T, Alloc> &Output, const std::pair<T*, L> &Input)
{
	const size_t CPYOFT = Output.size();

	Output.resize(Output.size() + Input.second);

	if (Input.second > 0)
	{
		std::memcpy(&Output[CPYOFT], Input.first, Input.second);
	}

	return Output;
}

class AllocatorTools final
{
private:

	static const std::string CLASS_NAME;

public:

	template<typename T, typename Alloc>
	static size_t Insert(std::vector<T, Alloc> &Output, size_t OutOffset, const T Input[], size_t Length)
	{
		CexAssert(OutOffset <= Output.size(), "The buffer is too small");

		const size_t CPYLEN = std::min(Length, Output.size() - OutOffset);

		if (CPYLEN > 0)
		{
			std::memcpy(&Output[OutOffset], Input, CPYLEN);
		}

		return CPYLEN;
	}

	template<typename T, typename Alloc1, typename Alloc2>
	static size_t Insert(std::vector<T, Alloc1> &Output, size_t OutOffset, const std::vector<T, Alloc2> &Input)
	{
		CexAssert(OutOffset <= Output.size(), "The buffer is too small");

		const size_t CPYLEN = std::min(Input.size(), Output.size() - OutOffset);

		if (CPYLEN > 0)
		{
			std::memcpy(&Output[OutOffset], Input.data(), CPYLEN);
		}

		return CPYLEN;
	}

	template<typename T, typename Alloc>
	static std::vector<T> ToVector(const std::vector<T, Alloc> &Input)
	{
		std::vector<T> otp(Input.size());

		std::memcpy(otp.data(), Input.data(), Input.size() * sizeof(T));

		return otp;
	}

	template<typename T>
	static std::vector<T> Unlock(const SecureVector<T> &Input)
	{
		std::vector<T> otp(Input.size());

		std::memcpy(otp.data(), Input.data(), Input.size());

		return otp;
	}

	static CEX_MALLOC_FN void* Allocate(size_t Elements, size_t ElementSize);

	static void Deallocate(void* Pointer, size_t Elements, size_t ElementSize);
};

NAMESPACE_ROOTEND
#endif
