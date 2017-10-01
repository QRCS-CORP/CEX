#ifndef CEX_SIMDPROFILES_H
#define CEX_SIMDPROFILES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// SIMD support flags
/// </summary>
enum class SimdProfiles : byte
{
	/// <summary>
	/// The system does not support SIMD instructions
	/// </summary>
	None = 0,
	/// <summary>
	/// The system supports SSE3 intrinsics
	/// </summary>
	Simd128 = 1,
	/// <summary>
	/// The system supports AVX2 intrinsics
	/// </summary>
	Simd256 = 2
};

NAMESPACE_ENUMERATIONEND
#endif
