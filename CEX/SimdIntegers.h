#ifndef CEX_SIMDINTEGERS_H
#define CEX_SIMDINTEGERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// SIMD integer wrappers
/// </summary>
enum class SimdIntegers : byte
{
	/// <summary>
	/// The system does not support SIMD instructions
	/// </summary>
	None = 0,
	/// <summary>
	/// AVX wrapper for unsigned 32bit integers
	/// </summary>
	UInt128 = 1,
	/// <summary>
	/// AVX2 wrapper for unsigned 32bit integers
	/// </summary>
	UInt256 = 2,
	/// <summary>
	/// AVX512 wrapper for unsigned 32bit integers
	/// </summary>
	UInt512 = 3,
	/// <summary>
	/// AVX2 wrapper for unsigned 64bit integers
	/// </summary>
	ULong256 = 4,
	/// <summary>
	/// AVX512 wrapper for unsigned 64bit integers
	/// </summary>
	ULong512 = 5,
	/// <summary>
	/// AVX wrapper for unsigned 16bit integers
	/// </summary>
	UShort128 = 6
};

NAMESPACE_ENUMERATIONEND
#endif
