// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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

#ifndef CEX_USHORT128_H
#define CEX_USHORT128_H

#include "CexDomain.h"
#include "SimdIntegers.h"

#if defined(__AVX__)
#	include "Intrinsics.h"
#endif

NAMESPACE_NUMERIC

using Enumeration::SimdIntegers;

/// <summary>
/// An AVX 128bit intrinsics wrapper.
/// <para>Processes blocks of 16bit unsigned integers.</para>
/// </summary>
class UShort128
{
#if defined(__AVX__)

public:

	/// <summary>
	/// The internal m128i register value
	/// </summary>
	__m128i xmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UShort128 initialized with 8x 16bit integers to the value one
	/// </summary>
	inline static const UShort128 ONE()
	{
		return UShort128(_mm_set1_epi16(1));
	}

	/// <summary>
	/// A UShort128 initialized with 8x 16bit integers to the value zero
	/// </summary>
	inline static const UShort128 ZERO()
	{
		return UShort128(_mm_set1_epi16(0));
	}

	//~~~ Constructors~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UShort128() 
	{
	}

	/// <summary>
	/// Initialize the register with an __m128i value
	/// </summary>
	///
	/// <param name="X">The 128bit register</param>
	explicit UShort128(__m128i const &X)
	{
		xmm = X;
	}

	/// <summary>
	/// Initialize with an integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting position within the Input array</param>
	template<typename Array>
	explicit UShort128(const Array &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 8 * 16bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">ushort 0</param>
	/// <param name="X1">ushort 1</param>
	/// <param name="X2">ushort 2</param>
	/// <param name="X3">ushort 3</param>
	/// <param name="X4">ushort 4</param>
	/// <param name="X5">ushort 5</param>
	/// <param name="X6">ushort 6</param>
	/// <param name="X7">ushort 7</param>
	explicit UShort128(ushort X0, ushort X1, ushort X2, ushort X3, ushort X4, ushort X5, ushort X6, ushort X7)
	{
		xmm = _mm_set_epi16(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 16bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UShort128(ushort X)
	{
		xmm = _mm_set1_epi16(X);
	}

	/// <summary>
	/// Read Only: The SIMD wrappers type name
	/// </summary>
	const SimdIntegers Enumeral()
	{
		return SimdIntegers::UShort128;
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load an array into a register
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting position within the Input array</param>
	template<typename Array>
	inline void Load(const Array &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load with 8 * 16bit unsigned integers in Little Endian format
	/// </summary>
	///
	/// <param name="X0">ushort 0</param>
	/// <param name="X1">ushort 1</param>
	/// <param name="X2">ushort 2</param>
	/// <param name="X3">ushort 3</param>
	/// <param name="X4">ushort 4</param>
	/// <param name="X5">ushort 5</param>
	/// <param name="X6">ushort 6</param>
	/// <param name="X7">ushort 7</param>
	inline void Load(ushort X0, ushort X1, ushort X2, ushort X3, ushort X4, ushort X5, ushort X6, ushort X7)
	{
		xmm = _mm_set_epi16(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Store register in a T size integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The destination integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting position within the Output array</param>
	template<typename Array>
	inline void Store(Array &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), xmm);
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UShort128</returns>
	inline static UShort128 Abs(const UShort128 &Value)
	{
		return UShort128(_mm_abs_epi16(Value.xmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in X
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UShort128</returns>
	inline UShort128 AndNot(const UShort128 &Value)
	{
		return UShort128(_mm_andnot_si128(xmm, Value.xmm));
	}

	/// <summary>
	/// Returns the bitwise negation of 4 32bit integers
	/// </summary>
	///
	/// <param name="Value">The integers to negate</param>
	/// 
	/// <returns>The processed UShort128</returns>
	inline static UShort128 Negate(const UShort128 &Value)
	{
		return UShort128(_mm_sub_epi16(_mm_set1_epi16(0), Value.xmm));
	}

	/// <summary>
	/// Computes the 16 bit left rotation of eight 16bit unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 16</param>
	inline void RotL16(const int Shift)
	{
		CexAssert(Shift <= 16, "Shift size is too large");
		xmm = _mm_or_si128(_mm_slli_epi16(xmm, static_cast<int>(Shift)), _mm_srli_epi16(xmm, static_cast<int>(16 - Shift)));
	}

	/// <summary>
	/// Computes the 16 bit left rotation of eight 16bit unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 16</param>
	/// 
	/// <returns>The rotated UShort128</returns>
	inline static UShort128 RotL16(const UShort128 &Value, const int Shift)
	{
		CexAssert(Shift <= 16, "Shift size is too large");
		return UShort128(_mm_or_si128(_mm_slli_epi16(Value.xmm, static_cast<int>(Shift)), _mm_srli_epi16(Value.xmm, static_cast<int>(16 - Shift))));
	}

	/// <summary>
	/// Computes the 16 bit right rotation of eight 16bit unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 16</param>
	inline void RotR16(const int Shift)
	{
		CexAssert(Shift <= 16, "Shift size is too large");
		RotL16(16 - Shift);
	}

	/// <summary>
	/// Computes the 16 bit right rotation of eight 16bit unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 16</param>
	/// 
	/// <returns>The rotated UShort128</returns>
	inline static UShort128 RotR16(const UShort128 &Value, const int Shift)
	{
		CexAssert(Shift <= 16, "Shift size is too large");
		return RotL16(Value, 16 - Shift);
	}

	/// <summary>
	/// Performs a byte swap on 8 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UShort128</returns>
	inline UShort128 Swap() const
	{
		__m128i tmpX = xmm;

		tmpX = _mm_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1)); // ?
		tmpX = _mm_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UShort128(_mm_or_si128(_mm_srli_epi16(tmpX, 8), _mm_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 8 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UShort128 to process</param>
	/// 
	/// <returns>The byte swapped UShort128</returns>
	inline static UShort128 Swap(UShort128 &X)
	{
		__m128i tmpX = X.xmm;

		tmpX = _mm_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UShort128(_mm_or_si128(_mm_srli_epi16(tmpX, 8), _mm_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	inline static const size_t size() { return sizeof(__m128i); }

	/// <summary>
	/// Shuffles the registers in 8 * UShort128 structures
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	/// <param name="X4">Operand 4</param>
	/// <param name="X5">Operand 5</param>
	/// <param name="X6">Operand 6</param>
	/// <param name="X7">Operand 7</param>
	inline static void Transpose8(UShort128 &X0, UShort128 &X1, UShort128 &X2, UShort128 &X3, UShort128 &X4, UShort128 &X5, UShort128 &X6, UShort128 &X7)
	{
		__m128i T0 = _mm_unpacklo_epi16(X0.xmm, X1.xmm); // TODO: check this
		__m128i T1 = _mm_unpackhi_epi16(X0.xmm, X1.xmm);
		__m128i T2 = _mm_unpacklo_epi16(X2.xmm, X3.xmm);
		__m128i T3 = _mm_unpackhi_epi16(X2.xmm, X3.xmm);
		__m128i T4 = _mm_unpacklo_epi16(X4.xmm, X5.xmm);
		__m128i T5 = _mm_unpackhi_epi16(X4.xmm, X5.xmm);
		__m128i T6 = _mm_unpacklo_epi16(X6.xmm, X7.xmm);
		__m128i T7 = _mm_unpackhi_epi16(X6.xmm, X7.xmm);

		__m128i M0 = _mm_unpacklo_epi32(T0, T1);
		__m128i M1 = _mm_unpackhi_epi32(T0, T1);
		__m128i M2 = _mm_unpacklo_epi32(T2, T3);
		__m128i M3 = _mm_unpackhi_epi32(T2, T3);
		__m128i M4 = _mm_unpacklo_epi32(T4, T5);
		__m128i M5 = _mm_unpackhi_epi32(T4, T5);
		__m128i M6 = _mm_unpacklo_epi32(T6, T7);
		__m128i M7 = _mm_unpackhi_epi32(T6, T7);

		X0.xmm = _mm_unpacklo_epi64(M0, M1);
		X1.xmm = _mm_unpackhi_epi64(M0, M1);
		X2.xmm = _mm_unpacklo_epi64(M2, M3);
		X3.xmm = _mm_unpackhi_epi64(M2, M3);
		X4.xmm = _mm_unpacklo_epi64(M4, M5);
		X5.xmm = _mm_unpackhi_epi64(M4, M5);
		X6.xmm = _mm_unpacklo_epi64(M6, M7);
		X7.xmm = _mm_unpackhi_epi64(M6, M7);
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Type cast operator
	/// </summary>
	operator __m128i() const
	{
		return xmm;
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline UShort128 operator + (const UShort128 &X) const
	{
		return UShort128(_mm_add_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UShort128 &X)
	{
		xmm = _mm_add_epi16(xmm, X.xmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UShort128 operator ++ ()
	{
		return UShort128(xmm) + ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UShort128 operator ++ (int)
	{
		return UShort128(xmm) + ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UShort128 operator - (const UShort128 &X) const
	{
		return UShort128(_mm_sub_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UShort128 &X)
	{
		xmm = _mm_sub_epi16(xmm, X.xmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UShort128 operator -- ()
	{
		return UShort128(xmm) - ONE();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UShort128 operator -- (int)
	{
		return UShort128(xmm) - ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UShort128 operator * (const UShort128 &X) const
	{
		return UShort128(_mm_mullo_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UShort128 &X)
	{
		xmm = _mm_mullo_epi16(xmm, X.xmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UShort128 operator / (const UShort128 &X) const
	{
		std::array<ushort, 8> tmpA;
		std::array<ushort, 8> tmpB;
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpA[0]), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpB[0]), X.xmm);
		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		return UShort128(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4], tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UShort128 &X)
	{
		std::array<ushort, 8> tmpA;
		std::array<ushort, 8> tmpB;
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpA[0]), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&tmpB[0]), X.xmm);
		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		xmm = _mm_set_epi16(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4], tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UShort128 operator % (const UShort128 &X) const
	{
		return UShort128(UShort128(xmm) - ((UShort128(xmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UShort128 &X)
	{
		xmm = UShort128(UShort128(xmm) - ((UShort128(xmm) / X) * X)).xmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UShort128 operator ^ (const UShort128 &X) const
	{
		return UShort128(_mm_xor_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UShort128 &X)
	{
		xmm = _mm_xor_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Bitwise OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UShort128 operator | (const UShort128 &X) const
	{
		return UShort128(_mm_or_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UShort128 &X)
	{
		xmm = _mm_or_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UShort128 operator || (const UShort128 &X) const
	{
		return UShort128(xmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UShort128 operator & (const UShort128 &X) const
	{
		return UShort128(_mm_and_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UShort128 &X)
	{
		xmm = _mm_and_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UShort128 operator && (const UShort128 &X) const
	{
		return UShort128(xmm) & X;
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator > (UShort128 const &X) const
	{
		return UShort128(_mm_cmpgt_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator < (UShort128 const &X) const
	{
		return UShort128(_mm_cmplt_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator >= (UShort128 const &X) const
	{
		return UShort128(UShort128(~(X > UShort128(xmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator <= (UShort128 const &X) const
	{
		return X >= UShort128(xmm);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UShort128 operator << (const int Shift) const
	{
		return UShort128(_mm_slli_epi16(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		xmm = _mm_slli_epi16(xmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UShort128 operator >> (const int Shift) const
	{
		return UShort128(_mm_srli_epi16(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		xmm = _mm_srli_epi16(xmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UShort128 operator ~ () const
	{
		return UShort128(_mm_xor_si128(xmm, _mm_set1_epi32(0xFFFFFFFF)));
	}

	/// <summary>
	/// Equals assignment operator
	/// </summary>
	///
	/// <param name="X">The value to assign</param>
	inline void operator = (const UShort128 &X)
	{
		xmm = X.xmm;
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator == (UShort128 const &X) const
	{
		return UShort128(_mm_cmpeq_epi16(xmm, X.xmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UShort128 operator ! () const
	{
		return UShort128(_mm_cmpeq_epi16(xmm, _mm_setzero_si128()));
	}

	/// <summary>
	/// Compare this integer for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UShort128 operator != (const UShort128 &X) const
	{
		return ~UShort128(_mm_cmpeq_epi16(xmm, X.xmm));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif