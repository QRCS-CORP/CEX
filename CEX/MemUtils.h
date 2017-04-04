#ifndef _CEX_MEMUTILS_H
#define _CEX_MEMUTILS_H

#include "CexDomain.h"
#include "SimdProfiles.h"

NAMESPACE_UTILITY

using Enumeration::SimdProfiles;

/// <summary>
/// Memory functions class
/// http://stackoverflow.com/questions/26246040/whats-missing-sub-optimal-in-this-memcpy-implementation/26256216
/// </summary>
class MemUtils
{
public:

	/// <summary>
	/// Append an integer to an integer array
	/// </summary>
	/// 
	/// <param name="Output">The destination byte array</param>
	template <typename T>
	inline static void Clear(std::vector<T> &Destination)
	{

	}

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Source">The source array</param>
	/// <param name="Destination">The destination array</param>
	template <typename T, typename U>
	inline static void Copy(std::vector<T> &Source, std::vector<U> &Destination, size_t Length)
	{
		size_t offset1 = 0;
		size_t offset2 = 0;

		if (SimdProfile == SimdProfiles::Simd256)
		{
			while (Length >= 32)
			{
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Destination[offset1]), reinterpret_cast<__m256i*>(&Source[offset2]));
				Length -= 32;
				offset1 += 32 / sizeof(U);
				offset2 += 32 / sizeof(T);
			}
		}

		if (SimdProfile == SimdProfiles::Simd128)
		{
			while (Length >= 16)
			{
				_mm_storeu_si128(reinterpret_cast<__m128i*>(&Destination[offset1]), reinterpret_cast<__m128i*>(&Source[offset2]));
				Length -= 16;
				offset1 += 16 / sizeof(U);
				offset2 += 16 / sizeof(T);
			}
		}

		if (Length > 0)
			std::memcpy(Destination[offset1], Source[offset2], Length);
	}

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Source">The source array</param>
	/// <param name="Destination">The destination array</param>
	template <typename T, typename U>
	inline static void Move(std::vector<T> &Source, std::vector<U> &Destination)
	{

	}
};

NAMESPACE_UTILITYEND
#endif