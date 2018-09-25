// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
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

#ifndef CEX_ULONG512_H
#define CEX_ULONG512_H

#include "CexDomain.h"
#include "SimdIntegers.h"

#if defined(__AVX512__)
#	include "Intrinsics.h"
#endif

NAMESPACE_NUMERIC

using Enumeration::SimdIntegers;

// TODO: None of this is tested!

/// <summary>
/// An AVX512 512bit SIMD intrinsics wrapper.
/// <para>Processes blocks of 64bit unsigned integers.</para>
/// </summary>
class ULong512
{
#if defined(__AVX512__)

public:

	/// <summary>
	/// The internal m512i register value
	/// </summary>
	__m512i zmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A ULong512 initialized with 8x 64bit integers to the value one
	/// </summary>
	inline static const ULong512 ONE()
	{
		return ULong512(_mm512_set1_epi64(1));
	}

	/// <summary>
	/// A ULong512 initialized with 16x 32bit integers to the value zero
	/// </summary>
	inline static const ULong512 ZERO()
	{
		return ULong512(_mm512_set1_epi64(0));
	}

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	ULong512()
	{
	}

	/// <summary>
	/// Initialize the register with an __m512i value
	/// </summary>
	///
	/// <param name="Z">The 512bit register</param>
	explicit UInt128(__m512i const &Z)
	{
		zmm = Z;
	}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 512 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	explicit ULong512(const Array &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 8 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64 0</param>
	/// <param name="X1">uint64 1</param>
	/// <param name="X2">uint64 2</param>
	/// <param name="X3">uint64 3</param>
	/// <param name="X4">uint64 4</param>
	/// <param name="X5">uint64 5</param>
	/// <param name="X6">uint64 6</param>
	/// <param name="X7">uint64 7</param>
	explicit ULong512(ulong X0, ulong X1, ulong X2, ulong X3, ulong X4, ulong X5, ulong X6, ulong X7)
	{
		zmm = _mm512_set_epi64(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 64bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint64 to add</param>
	explicit ULong512(ulong X)
	{
		zmm = _mm512_set1_epi64(X);
	}

	/// <summary>
	/// Read Only: The SIMD wrappers type name
	/// </summary>
	const SimdIntegers Enumeral()
	{
		return SimdIntegers::ULong512;
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load with 1 * 64bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">Set all uint64 integers to this value</param>
	inline void Load(ulong X)
	{
		zmm = _mm512_set1_epi64(X);
	}

	/// <summary>
	/// Load an array into a register
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 512 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	inline void Load(const Array &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load with 8 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64 0</param>
	/// <param name="X1">uint64 1</param>
	/// <param name="X2">uint64 2</param>
	/// <param name="X3">uint64 3</param>
	/// <param name="X4">uint64 4</param>
	/// <param name="X5">uint64 5</param>
	/// <param name="X6">uint64 6</param>
	/// <param name="X7">uint64 7</param>
	inline void Load(ulong X0, ulong X1, ulong X2, ulong X3, ulong X4, ulong X5, ulong X6, ulong X7)
	{
		zmm = _mm512_set_epi64(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Load an array of integers into a register.
	/// <para>Integers are loaded as 64bit integers regardless the natural size of T</para>
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 512 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	inline void LoadULL(const Array &Input, size_t Offset)
	{
		zmm = _mm512_set_epi64(static_cast<ulong>(Input[Offset]), 
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type))]), 
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 2)]),
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 3)]),
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 4)]),
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 5)]),
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 6)]),
			static_cast<ulong>(Input[Offset + (sizeof(ulong) / sizeof(Array::value_type) * 7)]));
	}

	/// <summary>
	/// Store register in an integer array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	template<typename Array>
	inline void Store(Array &Output, size_t Offset) const
	{
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), zmm);
	}

	/// <summary>
	/// Store 8 * 64bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint64 0</param>
	/// <param name="X1">uint64 1</param>
	/// <param name="X2">uint64 2</param>
	/// <param name="X3">uint64 3</param>
	/// <param name="X4">uint64 4</param>
	/// <param name="X5">uint64 5</param>
	/// <param name="X6">uint64 6</param>
	/// <param name="X7">uint64 7</param>
	inline void Store(ulong X0, ulong &X1, ulong &X2, ulong &X3, ulong &X4, ulong &X5, ulong &X6, ulong &X7) const
	{
		std::array<ulong, 8> tmp;

		_mm512_storeu_si512(reinterpret_cast<__m256i*>(&tmp), zmm);

		X0 = tmp[0];
		X1 = tmp[1];
		X2 = tmp[2];
		X3 = tmp[3];
		X4 = tmp[4];
		X5 = tmp[5];
		X6 = tmp[6];
		X7 = tmp[7];
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed ULong512</returns>
	inline static ULong512 Abs(const ULong512 &Value)
	{
		return ULong512(_mm512_abs_epi64(Value.zmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 512-bit value in *this* and the bitwise NOT of the 512-bit value in X
	/// </summary>
	///
	/// <param name="X">The comparison integer</param>
	/// 
	/// <returns>The processed ULong512</returns>
	inline ULong512 AndNot(const ULong512 &X)
	{
		return ULong512(_mm512_andnot_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	const size_t size() { return sizeof(__m512i); }

	/// <summary>
	/// Computes the 64 bit left rotation of eight unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 64</param>
	inline void RotL64(const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		zmm = _mm512_or_si512(_mm512_slli_epi64(zmm, static_cast<int>(Shift)), _mm512_srli_epi64(zmm, static_cast<int>(64 - Shift)));
	}

	/// <summary>
	/// Computes the 64 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated ULong512</returns>
	inline static ULong512 RotL64(const ULong512 &X, const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		return ULong512(_mm512_or_si512(_mm512_slli_epi64(X.zmm, static_cast<int>(Shift)), _mm512_srli_epi64(X.zmm, static_cast<int>(64 - Shift))));
	}

	/// <summary>
	/// Computes the 64 bit right rotation of eight unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 64</param>
	inline void RotR64(const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		RotL64(64 - Shift);
	}

	/// <summary>
	/// Computes the 64 bit right rotation of eight unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 64</param>
	/// 
	/// <returns>The rotated ULong512</returns>
	inline static ULong512 RotR64(const ULong512 &X, const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		return RotL64(X, 64 - Shift);
	}

	/// <summary>
	/// Shifts the 8 signed 64-bit integers right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 64</param>
	/// 
	/// <returns>The processed ULong512</returns>
	inline static ULong512 ShiftRA(const ULong512 &Value, const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		return ULong512(_mm512_sra_epi64(Value, _mm_set1_epi64(Shift)));
	}

	/// <summary>
	/// Shifts the 8 signed or unsigned 64-bit integers in a right by count bits while shifting in zeros
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 64</param>
	/// 
	/// <returns>The processed ULong512</returns>
	inline static ULong512 ShiftRL(const ULong512 &Value, const int Shift)
	{
		CexAssert(Shift <= 64, "Shift size is too large");
		return ULong512(_mm512_srl_epi64(Value, _mm_set1_epi64(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 8 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped ULong512</returns>
	inline ULong512 Swap() const
	{
		__m512i tmpX = zmm; // TODO: is mask right? test this

		tmpX = _mm512_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm512_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return ULong512(_mm512_or_si512(_mm512_srli_epi32(tmpX, 8), _mm512_slli_epi32(tmpX, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 8 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The ULong512 to process</param>
	/// 
	/// <returns>The byte swapped ULong512</returns>
	inline static ULong512 Swap(ULong512 &X)
	{
		__m512i tmpX = X.zmm;

		tmpX = _mm512_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm512_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return ULong512(_mm512_or_si512(_mm512_srli_epi32(tmpX, 8), _mm512_slli_epi32(tmpX, 8)));
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Type cast operator
	/// </summary>
	operator __m512i() const
	{
		return zmm;
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline ULong512 operator + (const ULong512 &X) const
	{
		return ULong512(_mm512_add_epi64(zmm, X.zmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const ULong512 &X)
	{
		zmm = _mm512_add_epi64(zmm, X.zmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline ULong512 operator ++ ()
	{
		return ULong512(zmm) + ULong512::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline ULong512 operator ++ (int)
	{
		return ULong512(zmm) + ULong512::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline ULong512 operator - (const ULong512 &X) const
	{
		return ULong512(_mm512_sub_epi64(zmm, X.zmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const ULong512 &X)
	{
		zmm = _mm512_sub_epi64(zmm, X.zmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline ULong512 operator -- ()
	{
		return ULong512(zmm) - ZMM1();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline ULong512 operator -- (int)
	{
		return ULong512(zmm) - ULong512::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline ULong512 operator * (const ULong512 &X) const
	{
		return ULong512(_mm512_mullo_epi64(zmm, X.zmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const ULong512 &X)
	{
		zmm = _mm512_mullo_epi64(zmm, X.zmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline ULong512 operator / (const ULong512 &X) const
	{
		std::array<ulong, 8> tmpA;
		std::array<ulong, 8> tmpB;

		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);

		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		return ULong512(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//return ULong512(_mm512_cvtps_epi64(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm))));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const ULong512 &X)
	{
		std::array<ulong, 8> tmpA;
		std::array<ulong, 8> tmpB;

		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);

		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		zmm = _mm512_set_epi64(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//zmm = _mm512_cvtps_epi32(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm)));
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline ULong512 operator % (const ULong512 &X) const
	{
		return ULong512(ULong512(zmm) - ((ULong512(zmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const ULong512 &X)
	{
		zmm = ULong512(ULong512(zmm) - ((ULong512(zmm) / X) * X)).zmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline ULong512 operator ^ (const ULong512 &X) const
	{
		return ULong512(_mm512_xor_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const ULong512 &X)
	{
		zmm = _mm512_xor_si512(zmm, X.zmm);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline ULong512 operator | (const ULong512 &X)
	{
		return ULong512(_mm512_or_si512(zmm, X.zmm));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const ULong512 &X)
	{
		zmm = _mm512_or_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline ULong512 operator || (const ULong512 &X) const
	{
		return ULong512(zmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline ULong512 operator & (const ULong512 &X)
	{
		return ULong512(_mm512_and_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const ULong512 &X)
	{
		zmm = _mm512_and_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline ULong512 operator && (const ULong512 &X) const
	{
		return ULong512(zmm) & X;
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline ULong512 operator << (const int Shift) const
	{
		return ULong512(_mm512_slli_epi64(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		zmm = _mm512_slli_epi64(zmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline ULong512 operator >> (const int Shift) const
	{
		return ULong512(_mm512_srli_epi64(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		zmm = _mm512_srli_epi64(zmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline ULong512 operator ~ () const
	{
		return ULong512(_mm512_xor_epi64(zmm, _mm512_set1_epi64(-1)));
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator > (ULong512 const &X) const
	{
		return ULong512(_mm512_cmpgt_epi64_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator < (ULong512 const &X) const
	{
		return ULong512(_mm512_cmpgt_epi64_mask(X.zmm, zmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator >= (ULong512 const &X) const
	{
		return ULong512(ULong512(~(X > ULong512(zmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator <= (ULong512 const &X) const
	{
		return X >= ULong512(zmm);
	}

	/// <summary>
	/// Equals assignment operator
	/// </summary>
	///
	/// <param name="X">The value to assign</param>
	inline void operator = (const ULong512 &X)
	{
		zmm = X.zmm;
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator == (ULong512 const &X) const
	{
		return ULong512(_mm512_cmpeq_epi64_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline ULong512 operator ! () const
	{
		return ULong512(_mm512_cmpeq_epi64(zmm, _mm512_setzero_si512()));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline ULong512 operator != (const ULong512 &X) const
	{
		return ~ULong512(_mm512_cmpneq_epi64_mask(zmm, X.zmm));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif