#ifndef CEX_SECUREVECTOR_H
#define CEX_SECUREVECTOR_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "LockingAllocator.h"
#include "MemoryPool.h"
#include "MemoryTools.h"

NAMESPACE_ROOT

using Utility::LockingAllocator;
using Utility::MemoryPool;
using Utility::MemoryTools;

/// <summary>
/// A secure allocator template used internally to create locked memory allocations
/// </summary>
template<typename T>
class SecureAllocator
{
public:

#if (!defined(_ITERATOR_DEBUG_LEVEL) || (_ITERATOR_DEBUG_LEVEL == 0))
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
		return static_cast<T*>(LockingAllocator::Allocate(n, sizeof(T)));
	}

	void deallocate(T* p, size_t n)
	{
		LockingAllocator::Deallocate(p, n, sizeof(T));
	}
};

/// <summary>
/// A secure-vector template using locking memory allocations
/// </summary>
template<typename T> 
using SecureVector = std::vector<T, SecureAllocator<T>>;

/// <summary>
/// Compare two arrays for equality
/// </summary>
/// 
/// <returns>Returns true if equal</returns>
template<typename T, typename U>
inline bool operator == (const SecureAllocator<T>&, const SecureAllocator<U>&)
{
	return true;
}

/// <summary>
/// Compare two arrays for inequality
/// </summary>
/// 
/// <returns>Returns true if not equal</returns>
template<typename T, typename U>
inline bool operator != (const SecureAllocator<T>&, const SecureAllocator<U>&)
{
	return false;
}

/// <summary>
/// Erase a SecureVector and resize it to zero
/// </summary>
///
/// <param name="Input">The SecureVector to erase</param>
CEX_OPTIMIZE_IGNORE
template<typename T>
inline static void Clear(SecureVector<T> &Input)
{
	if (Input.size() != 0)
	{
		MemoryTools::Clear(Input, 0, Input.size() * sizeof(T));
		Input.clear();
	}
}
CEX_OPTIMIZE_RESUME

/// <summary>
/// Copy a length of bytes between two SecureVector arrays.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="InOffset">The starting offset within the SecureVector array</param>
/// <param name="Output">The SecureVector destination array</param>
/// <param name="OutOffset">The starting offset within the standard-vector</param>
/// <param name="Length">The number of bytes to copy</param>
template<typename T>
inline static void Copy(const SecureVector<T> &Input, size_t InOffset, SecureVector<T> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The length is longer than the input array");
	CEXASSERT(Output.size() - OutOffset >= Length, "The length is longer than the output array");

	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Length);
}

/// <summary>
/// Extract integers from a SecureVector and copy them to a standard-vector.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="Output">The standard-vector destination</param>
template<typename T>
inline static void Extract(const SecureVector<T> &Input, std::vector<T> &Output)
{
	const size_t OTPSZE = Output.size();

	Output.resize(OTPSZE + Input.size());
	MemoryTools::Copy(Input, 0, Output, OTPSZE, Input.size() * sizeof(T));
}

/// <summary>
/// Extract integers from a SecureVector and copy them to another SecureVector.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="Output">The SecureVector destination array</param>
template<typename T>
inline static void Extract(const SecureVector<T> &Input, SecureVector<T> &Output)
{
	const size_t OTPSZE = Output.size();

	Output.resize(OTPSZE + Input.size());
	MemoryTools::Copy(Input, 0, Output, OTPSZE, Input.size() * sizeof(T));
}

/// <summary>
/// Extract integers from a SecureVector and copy them to a standard-vector using offsets and an element count.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="InOffset">The starting offset within the source SecureVector</param>
/// <param name="Output">The standard-vector destination array</param>
/// <param name="OutOffset">The starting offset within the destination SecureVector</param>
/// <param name="Elements">The number of vector elements to copy</param>
template<typename T>
inline static void Extract(const SecureVector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Elements)
{
	const size_t OTPSZE = Output.size() >= OutOffset + Elements ? 0 : OutOffset + Elements;

	if (OTPSZE != 0)
	{
		Output.resize(OTPSZE);
	}

	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Elements * sizeof(T));
}

/// <summary>
/// Extract integers from a SecureVector and copy them to another SecureVector, using offsets and an element count.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="InOffset">The starting offset within the source SecureVector</param>
/// <param name="Output">The standard-vector destination array</param>
/// <param name="OutOffset">The starting offset within the destination SecureVector</param>
/// <param name="Elements">The number of vector elements to copy</param>
template<typename T>
inline static void Extract(const SecureVector<T> &Input, size_t InOffset, SecureVector<T> &Output, size_t OutOffset, size_t Elements)
{
	const size_t OTPSZE = Output.size() >= OutOffset + Elements ? 0 : OutOffset + Elements;

	if (OTPSZE != 0)
	{
		Output.resize(OTPSZE);
	}

	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Input.size() * sizeof(T));
}

/// <summary>
/// Insert a standard-vector into a SecureVector array.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The standard-vector source array</param>
/// <param name="Output">The SecureVector destination array</param>
template<typename T>
inline static void Insert(const std::vector<T> &Input, SecureVector<T> &Output)
{
	const size_t OTPSZE = Output.size();

	Output.resize(OTPSZE + Input.size());
	MemoryTools::Copy(Input, 0, Output, OTPSZE, Input.size() * sizeof(T));
}

/// <summary>
/// Insert a SecureVector into another SecureVector array.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="Output">The SecureVector destination array</param>
template<typename T>
inline static void Insert(const SecureVector<T> &Input, SecureVector<T> &Output)
{
	const size_t OTPSZE = Output.size();

	Output.resize(OTPSZE + Input.size());
	MemoryTools::Copy(Input, 0, Output, OTPSZE, Input.size() * sizeof(T));
}

/// <summary>
/// Insert a standard-vector into a SecureVector array using offsets and an element count.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The standard-vector source array</param>
/// <param name="InOffset">The starting offset within the standard-vector</param>
/// <param name="Output">The SecureVector destination array</param>
/// <param name="OutOffset">The starting offset within the SecureVector</param>
/// <param name="Elements">The number of elements to copy</param>
template<typename T>
inline static void Insert(const std::vector<T> &Input, size_t InOffset, SecureVector<T> &Output, size_t OutOffset, size_t Elements)
{
	const size_t OTPSZE = Output.size() >= OutOffset + Elements ? 0 : OutOffset + Elements;

	if (OTPSZE != 0)
	{
		Output.resize(OTPSZE);
	}

	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Elements * sizeof(T));
}

/// <summary>
/// Insert a SecureVector into another SecureVector array using offsets and an element count.
/// <para>This method will expand the output array to size.</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// <param name="InOffset">The starting offset within the source SecureVector</param>
/// <param name="Output">The SecureVector destination array</param>
/// <param name="OutOffset">The starting offset within the destination SecureVector</param>
/// <param name="Elements">The number of elements to copy</param>
template<typename T>
inline static void Insert(const SecureVector<T> &Input, size_t InOffset, SecureVector<T> &Output, size_t OutOffset, size_t Elements)
{
	const size_t OTPSZE = Output.size() >= OutOffset + Elements ? 0 : OutOffset + Elements;

	if (OTPSZE != 0)
	{
		Output.resize(OTPSZE);
	}

	MemoryTools::Copy(Input, InOffset, Output, OutOffset, Elements * sizeof(T));
}

/// <summary>
/// Copy a standard-vector to a SecureVector
/// </summary>
///
/// <param name="Input">The input source array to copy</param>
/// 
/// <returns>A SecureVector copy of the input array</returns>
template<typename T>
inline static SecureVector<T> Lock(const std::vector<T> &Input)
{
	SecureVector<T> ret(Input.size());

	MemoryTools::Copy(Input, 0, ret, 0, ret.size() * sizeof(T));

	return ret;
}

/// <summary>
/// Copy a standard-vector to a SecureVector, and erase the input vector
/// </summary>
///
/// <param name="Input">The input vector array, this will be erased and cleared</param>
/// 
/// <returns>A SecureVector copy of the input array</returns>
CEX_OPTIMIZE_IGNORE
template<typename T>
inline static SecureVector<T> LockClear(std::vector<T> &Input)
{
	SecureVector<T> ret(Input.size());

	MemoryTools::Copy(Input, 0, ret, 0, ret.size() * sizeof(T));
	MemoryTools::Clear(Input, 0, Input.size() * sizeof(T));
	Input.clear();

	return ret;
}
CEX_OPTIMIZE_RESUME

/// <summary>
/// Move a standard-vector to another SecureVector array, clearing the source</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array; will be cleared after copying</param>
/// <param name="Output">The SecureVector destination array</param>
/// <param name="OutOffset">The starting offset within the standard-vector</param>
/// <param name="Length">The number of bytes to copy</param>
CEX_OPTIMIZE_IGNORE
template<typename T>
inline static void Move(std::vector<T> &Input, SecureVector<T> &Output, size_t OutOffset)
{
	CEXASSERT(Output.size() - OutOffset >= Input.size(), "The input array is longer than the output array");

	MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size() * sizeof(T));
	MemoryTools::Clear(Input, 0, Input.size() * sizeof(T));
	Input.clear();
}
CEX_OPTIMIZE_RESUME

/// <summary>
/// Move a SecureVector array to another SecureVector array, clearing the source</para>
/// </summary>
///
/// <param name="Input">The SecureVector source array; will be cleared after copying</param>
/// <param name="Output">The SecureVector destination array</param>
/// <param name="OutOffset">The starting offset within the standard-vector</param>
/// <param name="Length">The number of bytes to copy</param>
CEX_OPTIMIZE_IGNORE
template<typename T>
inline static void Move(SecureVector<T> &Input, SecureVector<T> &Output, size_t OutOffset)
{
	CEXASSERT(Output.size() - OutOffset >= Input.size(), "The input array is longer than the output array");

	MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size() * sizeof(T));
	MemoryTools::Clear(Input, 0, Input.size() * sizeof(T));
	Input.clear();
}
CEX_OPTIMIZE_RESUME

/// <summary>
/// Copy a SecureVector to a standard-vector array
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// 
/// <returns>A standard-vector copy of the SecureArray</returns>
template<typename T>
inline static std::vector<T> Unlock(const SecureVector<T> &Input)
{
	std::vector<T> ret(Input.size());

	MemoryTools::Copy(Input, 0, ret, 0, ret.size() * sizeof(T));

	return ret;
}

/// <summary>
/// Copy a SecureVector to a standard-vector, and erase the input SecureArray
/// </summary>
///
/// <param name="Input">The SecureVector source array</param>
/// 
/// <returns>A standard-vector copy of the SecureArray</returns>
CEX_OPTIMIZE_IGNORE
template<typename T>
inline static std::vector<T> UnlockClear(SecureVector<T> &Input)
{
	std::vector<T> ret(Input.size());

	MemoryTools::Copy(Input, 0, ret, 0, ret.size() * sizeof(T));
	MemoryTools::Clear(Input, 0, Input.size() * sizeof(T));
	Input.clear();

	return ret;
}
CEX_OPTIMIZE_RESUME

NAMESPACE_ROOTEND
#endif
