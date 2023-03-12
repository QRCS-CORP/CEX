// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_ULONG256_H
#define CEX_ULONG256_H

#include "CexDomain.h"
#include "Intrinsics.h"
#include "SimdIntegers.h"

NAMESPACE_NUMERIC

using Enumeration::SimdIntegers;

/// <summary>
/// An AVX2 256bit SIMD intrinsics wrapper.
/// <para>Processes blocks of 64bit unsigned integers.</para>
/// </summary>
class ULong256
{
public:

	/// <summary>
	/// The internal m256i register value
	/// </summary>
	__m256i ymm;

	//~~~ Constants~~~//

	/// <summary>
	/// A ULong256 initialized with 4x 64bit integers to the value one
	/// </summary>
	inline static const ULong256 ONE()
	{
		return ULong256(_mm256_set1_epi64x(1));
	}

	/// <summary>
	/// A ULong256 initialized with 4x 64bit integers to the value zero
	/// </summary>
	inline static const ULong256 ZERO()
	{
		return ULong256(_mm256_set1_epi64x(0));
	}

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	ULong256()
		:
		ymm()
	{
	}

	/// <summary>
	/// Initialize with an __m256i integer
	/// </summary>
	///
	/// <param name="Y">The register to copy</param>
	explicit ULong256(__m256i const &Y)
	{
		ymm = Y;
	}

	/// <summary>
	/// Initialize with an integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits int64_t</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	explicit ULong256(const Array &Input, size_t Offset)
	{
		ymm = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 4 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64_t 0</param>
	/// <param name="X1">uint64_t 1</param>
	/// <param name="X2">uint64_t 2</param>
	/// <param name="X3">uint64_t 3</param>
	explicit ULong256(uint64_t X0, uint64_t X1, uint64_t X2, uint64_t X3)
	{
		ymm = _mm256_set_epi64x(X0, X1, X2, X3);
	}

	/// <summary>
	/// Initialize with 1 * 64bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint32_t to add</param>
	explicit ULong256(uint64_t X)
	{
		ymm = _mm256_set1_epi64x(X);
	}

	/// <summary>
	/// Read Only: The SIMD wrappers type name
	/// </summary>
	const SimdIntegers Enumeral()
	{
		return SimdIntegers::ULong256; //-V2571
	}

	//~~~Load and Store~~~//

	/// <summary>
	/// Load with 1 * 64bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">Set all uint64 integers to this value</param>
	inline void Load(uint64_t X)
	{
		ymm = _mm256_set1_epi64x(X);
	}

	/// <summary>
	/// Load an array into a register
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits int64_t</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	inline void Load(const Array &Input, size_t Offset)
	{
		ymm = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load with 4 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64 0</param>
	/// <param name="X1">uint64 1</param>
	/// <param name="X2">uint64 2</param>
	/// <param name="X3">uint64 3</param>
	inline void Load(uint64_t X0, uint64_t X1, uint64_t X2, uint64_t X3)
	{
		ymm = _mm256_set_epi64x(X0, X1, X2, X3);
	}

	/// <summary>
	/// Load an array of integers into a register.
	/// <para>Integers are loaded as 64bit integers regardless the natural size of T; but T must be less than or equal to 64bits in size</para>
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits int64_t</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	inline void LoadULL(const Array &Input, size_t Offset)
	{
		CEXASSERT(sizeof(uint32_t) <= sizeof(Array::value_type), "The input array integer size must be less or equal to uint32");

		zmm = _mm256_set_epi64x(static_cast<uint32_t>(Input[Offset]),
			static_cast<uint32_t>(Input[Offset + (sizeof(uint32_t) / sizeof(Array::value_type))]),
			static_cast<uint32_t>(Input[Offset + (sizeof(uint32_t) / sizeof(Array::value_type) * 2)]),
			static_cast<uint32_t>(Input[Offset + (sizeof(uint32_t) / sizeof(Array::value_type) * 3)]));
	}

	/// <summary>
	/// Store register in an integer array
	/// </summary>
	///
	/// <param name="Output">The source integer array; must be at least 256 bits int64_t</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	template<typename Array>
	inline void Store(Array &Output, size_t Offset) const
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), ymm);
	}

	/// <summary>
	/// Store 4 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64 0</param>
	/// <param name="X1">uint64 1</param>
	/// <param name="X2">uint64 2</param>
	/// <param name="X3">uint64 3</param>
	inline void Store(uint64_t &X0, uint64_t &X1, uint64_t &X2, uint64_t &X3) const
	{
		std::array<uint64_t, 4> tmp;

		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmp), ymm);

		X0 = tmp[0];
		X1 = tmp[1];
		X2 = tmp[2];
		X3 = tmp[3];
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Returns the absolute value.
	/// <para>Note: returns the absolute value of the 32 bit integers</para>
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed ULong256</returns>
	inline static ULong256 Abs(const ULong256 &Value)
	{
		return ULong256(_mm256_abs_epi32(Value.ymm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in X
	/// </summary>
	///
	/// <param name="X">The comparison integer</param>
	/// 
	/// <returns>The processed ULong256</returns>
	inline ULong256 AndNot(const ULong256 &X)
	{
		return ULong256(_mm256_andnot_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	static const size_t size()
	{
		return sizeof(__m256i);
	}

	/// <summary>
	/// Computes the 64 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 64</param>
	inline void RotL64(int32_t Shift)
	{
		CEXASSERT(Shift <= 64, "Shift size is too large");
		ymm = _mm256_or_si256(_mm256_slli_epi64(ymm, static_cast<int32_t>(Shift)), _mm256_srli_epi64(ymm, static_cast<int32_t>(64 - Shift)));
	}

	/// <summary>
	/// Computes the 64 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 64</param>
	/// 
	/// <returns>The rotated ULong256</returns>
	inline static ULong256 RotL64(const ULong256 &X, const int32_t Shift)
	{
		CEXASSERT(Shift <= 64, "Shift size is too large");
		return ULong256(_mm256_or_si256(_mm256_slli_epi64(X.ymm, static_cast<int32_t>(Shift)), _mm256_srli_epi64(X.ymm, static_cast<int32_t>(64 - Shift))));
	}

	/// <summary>
	/// Computes the 64 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 64</param>
	inline void RotR64(int32_t Shift)
	{
		CEXASSERT(Shift <= 64, "Shift size is too large");
		RotL64(64 - Shift);
	}

	/// <summary>
	/// Computes the 64 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 64</param>
	/// 
	/// <returns>The rotated ULong256</returns>
	static ULong256 RotR64(const ULong256 &X, const int32_t Shift)
	{
		CEXASSERT(Shift <= 64, "Shift size is too large");
		return RotL64(X, 64 - Shift);
	}

	/// <summary>
	/// Performs a uint8_t swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The uint8_t swapped ULong256</returns>
	inline ULong256 Swap() const
	{
		__m256i tmpX = ymm;

		tmpX = _mm256_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm256_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return ULong256(_mm256_or_si256(_mm256_srli_epi16(tmpX, 8), _mm256_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Performs a uint8_t swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The ULong256 to process</param>
	/// 
	/// <returns>The uint8_t swapped ULong256</returns>
	inline static ULong256 Swap(ULong256 &X)
	{
		__m256i tmpX = X.ymm;

		tmpX = _mm256_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm256_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return ULong256(_mm256_or_si256(_mm256_srli_epi16(tmpX, 8), _mm256_slli_epi16(tmpX, 8)));
	}

	//~~~Operators~~~//

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline ULong256 operator + (const ULong256 &X) const
	{
		return ULong256(_mm256_add_epi64(ymm, X.ymm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const ULong256 &X)
	{
		ymm = _mm256_add_epi64(ymm, X.ymm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline ULong256 operator ++ ()
	{
		return ULong256(ymm) + ULong256::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline ULong256 operator ++ (int32_t)
	{
		return ULong256(ymm) + ULong256::ONE();
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const ULong256 &X)
	{
		ymm = _mm256_sub_epi64(ymm, X.ymm);
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline ULong256 operator - (const ULong256 &X) const
	{
		return ULong256(_mm256_sub_epi64(ymm, X.ymm));
	}

	/// <summary>
	/// Multiply a value with this integer 
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const ULong256 &X)
	{
		// TODO: why is *= so slow?
#if defined (__AVX512DQ__) && defined (__AVX512VL__)
		ymm = _mm256_mullo_epi64(ymm, X.ymm);
#else
		__m256i tmp1 = _mm256_mul_epu32(ymm, X.ymm);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(ymm, 4), _mm256_srli_si256(X.ymm, 4));
		ymm = _mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
#endif
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline ULong256 operator * (const ULong256 &X) const
	{
#if defined (__AVX512DQ__) && defined (__AVX512VL__)
		return ULong256(_mm256_mullo_epi64(ymm, X.ymm));
#else
		__m256i tmp1 = _mm256_mul_epu32(ymm, X.ymm);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(ymm, 4), _mm256_srli_si256(X.ymm, 4));
		return ULong256(_mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
#endif
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline ULong256 operator / (const ULong256 &X) const
	{
		std::array<uint64_t, 4> tmpA;
		std::array<uint64_t, 4> tmpB;
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpA[0]), ymm);
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpB[0]), X.ymm);
		CEXASSERT(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0, "Division by zero");

		return ULong256(tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const ULong256 &X)
	{
		std::array<uint64_t, 4> tmpA;
		std::array<uint64_t, 4> tmpB;
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpA[0]), ymm);
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpB[0]), X.ymm);
		CEXASSERT(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0, "Division by zero");

		ymm = _mm256_set_epi64x(tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline ULong256 operator % (const ULong256 &X) const
	{
		return ULong256(ULong256(ymm) - ((ULong256(ymm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const ULong256 &X)
	{
		ymm = ULong256(ULong256(ymm) - ((ULong256(ymm) / X) * X)).ymm;
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const ULong256 &X)
	{
		ymm = _mm256_xor_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline ULong256 operator ^ (const ULong256 &X) const
	{
		return ULong256(_mm256_xor_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Biwise OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline ULong256 operator | (const ULong256 &X)
	{
		return ULong256(_mm256_or_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Biwise OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const ULong256 &X)
	{
		ymm = _mm256_or_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline ULong256 operator || (const ULong256 &X) const
	{
		return ULong256(ymm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline ULong256 operator & (const ULong256 &X)
	{
		return ULong256(_mm256_and_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const ULong256 &X)
	{
		ymm = _mm256_and_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline ULong256 operator && (const ULong256 &X) const //-V2569
	{
		return ULong256(ymm) & X;
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (int32_t Shift)
	{
		ymm = _mm256_slli_epi64(ymm, Shift);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline ULong256 operator << (int32_t Shift) const
	{
		return ULong256(_mm256_slli_epi64(ymm, Shift));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (int32_t Shift)
	{
		ymm = _mm256_srli_epi64(ymm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline ULong256 operator >> (int32_t Shift) const
	{
		return ULong256(_mm256_srli_epi64(ymm, Shift));
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline ULong256 operator ~ () const
	{
		return ULong256(_mm256_xor_si256(ymm, _mm256_set1_epi32(0xFFFFFFFFUL)));
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator > (ULong256 const &X) const
	{
		return ULong256(_mm256_cmpgt_epi64(ymm, X.ymm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator < (ULong256 const &X) const
	{
		return ULong256(_mm256_cmpgt_epi64(X.ymm, ymm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator >= (ULong256 const &X) const
	{
		return ULong256(ULong256(~(X > ULong256(ymm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator <= (ULong256 const &X) const
	{
		return X >= ULong256(ymm);
	}

	/// <summary>
	/// Equals assignment operator
	/// </summary>
	///
	/// <param name="X">The value to assign</param>
	inline void operator = (const ULong256 &X)
	{
		ymm = X.ymm;
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator == (ULong256 const &X) const
	{
		return ULong256(_mm256_cmpeq_epi64(ymm, X.ymm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline ULong256 operator ! () const
	{
		return ULong256(_mm256_cmpeq_epi64(ymm, _mm256_setzero_si256()));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong256 operator != (const ULong256 &X) const
	{
		return ~ULong256(_mm256_cmpeq_epi64(ymm, X.ymm));
	}
};

NAMESPACE_NUMERICEND
#endif