// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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

#ifndef CEX_UINT128_H
#define CEX_UINT128_H

#include "CexDomain.h"
#include "Intrinsics.h"
#include "SimdIntegers.h"

NAMESPACE_NUMERIC

using Enumeration::SimdIntegers;

/// <summary>
/// An AVX 128bit SIMD intrinsics wrapper.
/// <para>Processes blocks of 32bit unsigned integers.</para>
/// </summary>
class UInt128
{
public:

	/// <summary>
	/// The internal m128i register value
	/// </summary>
	__m128i xmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UInt128 initialized with 4x 32bit integers to the value one
	/// </summary>
	inline static const UInt128 ONE() 
	{
		return UInt128(_mm_set1_epi32(1));
	}

	/// <summary>
	/// A UInt128 initialized with 4x 32bit integers to the value zero
	/// </summary>
	inline static const UInt128 ZERO()
	{
		return UInt128(_mm_set1_epi32(0));
	}

	//~~~ Constructors~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt128()
		:
		xmm()
	{
	}

	/// <summary>
	/// Initialize the register with an __m128i value
	/// </summary>
	///
	/// <param name="X">The 128bit register</param>
	explicit UInt128(__m128i const &X)
	{
		xmm = X;
	}

	/// <summary>
	/// Initialize with an integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	explicit UInt128(const Array &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 4 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint 0</param>
	/// <param name="X1">uint 1</param>
	/// <param name="X2">uint 2</param>
	/// <param name="X3">uint 3</param>
	explicit UInt128(uint X0, uint X1, uint X2, uint X3)
	{
		xmm = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt128(uint X)
	{
		xmm = _mm_set1_epi32(X);
	}

	/// <summary>
	/// Read Only: The SIMD wrappers type name
	/// </summary>
	const SimdIntegers Enumeral()
	{
		return SimdIntegers::UInt128; //-V2571
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">Set all uint32 integers to this value</param>
	inline void Load(uint X)
	{
		xmm = _mm_set1_epi32(X);
	}

	/// <summary>
	/// Load with 4 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint32 0</param>
	/// <param name="X1">uint32 1</param>
	/// <param name="X2">uint32 2</param>
	/// <param name="X3">uint32 3</param>
	inline void Load(uint X0, uint X1, uint X2, uint X3)
	{
		xmm = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename Array>
	inline void Load(const Array &Input, size_t Offset)
	{
		xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load an integer array into a register.
	/// <para>Integers are loaded as 32bit integers regardless the arrays integer size</para>
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename Array>
	inline void LoadUL(const Array &Input, size_t Offset)
	{
		xmm = _mm_set_epi32(static_cast<uint>(Input[Offset]), static_cast<uint>(Input[Offset + 1]), static_cast<uint>(Input[Offset + 2]), static_cast<uint>(Input[Offset + 3]));
	}

	/// <summary>
	/// Transposes and loads 4 * UInt128 at 32bit boundaries into an array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting position within the Input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename Array>
	inline static void Load4(const Array &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		X0.Load(Input, Offset);
		X1.Load(Input, Offset + (16 / sizeof(Input[0])));
		X2.Load(Input, Offset + (32 / sizeof(Input[0])));
		X3.Load(Input, Offset + (48 / sizeof(Input[0])));
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Store register in an integer array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	template <typename Array>
	inline void Store(Array &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), xmm);
	}

	/// <summary>
	/// Transposes and stores 4 * UInt128 to an array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 512 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename Array>
	inline static void Store4(Array &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (16 / sizeof(Output[0])));
		X2.Store(Output, Offset + (32 / sizeof(Output[0])));
		X3.Store(Output, Offset + (48 / sizeof(Output[0])));
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 Abs(const UInt128 &Value)
	{
		return UInt128(_mm_abs_epi32(Value.xmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in X
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline UInt128 AndNot(const UInt128 &Value)
	{
		return UInt128(_mm_andnot_si128(xmm, Value.xmm));
	}

	/// <summary>
	/// Returns the bitwise negation of 4 32bit integers
	/// </summary>
	///
	/// <param name="Value">The integers to negate</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 Negate(const UInt128 &Value)
	{
		return UInt128(_mm_sub_epi32(_mm_set1_epi32(0), Value.xmm));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotL32(int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		xmm = _mm_or_si128(_mm_slli_epi32(xmm, static_cast<int>(Shift)), _mm_srli_epi32(xmm, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	inline static UInt128 RotL32(const UInt128 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt128(_mm_or_si128(_mm_slli_epi32(Value.xmm, static_cast<int>(Shift)), _mm_srli_epi32(Value.xmm, static_cast<int>(32 - Shift))));
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotR32(int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		RotL32(32 - Shift);
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	inline static UInt128 RotR32(const UInt128 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return RotL32(Value, 32 - Shift);
	}

	/// <summary>
	/// Shifts the 4 signed 32-bit integers in a right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 ShiftRA(const UInt128 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt128(_mm_sra_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Shifts the 4 signed or unsigned 32-bit integers in a right by count bits while shifting in zeros.
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt128</returns>
	inline static UInt128 ShiftRL(const UInt128 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt128(_mm_srl_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	inline UInt128 Swap() const
	{
		__m128i tmpX = xmm;

		tmpX = _mm_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(tmpX, 8), _mm_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt128 to process</param>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	inline static UInt128 Swap(UInt128 &X)
	{
		__m128i tmpX = X.xmm;

		tmpX = _mm_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(tmpX, 8), _mm_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	inline static const size_t size() { return sizeof(__m128i); }

	/// <summary>
	/// Shuffles the registers in 4 * UInt128 structures; to create a sequential chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	inline static void Transpose(UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		__m128i T0 = _mm_unpacklo_epi32(X0.xmm, X1.xmm);
		__m128i T1 = _mm_unpacklo_epi32(X2.xmm, X3.xmm);
		__m128i T2 = _mm_unpackhi_epi32(X0.xmm, X1.xmm);
		__m128i T3 = _mm_unpackhi_epi32(X2.xmm, X3.xmm);
		X0.xmm = _mm_unpacklo_epi64(T0, T1);
		X1.xmm = _mm_unpackhi_epi64(T0, T1);
		X2.xmm = _mm_unpacklo_epi64(T2, T3);
		X3.xmm = _mm_unpackhi_epi64(T2, T3);
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
	inline UInt128 operator + (const UInt128 &X) const
	{
		return UInt128(_mm_add_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UInt128 &X)
	{
		xmm = _mm_add_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UInt128 operator ++ ()
	{
		return UInt128(xmm) + UInt128::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UInt128 operator ++ (int)
	{
		return UInt128(xmm) + UInt128::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UInt128 operator - (const UInt128 &X) const
	{
		return UInt128(_mm_sub_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UInt128 &X)
	{
		xmm = _mm_sub_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UInt128 operator -- ()
	{
		return UInt128(xmm) - UInt128::ONE();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UInt128 operator -- (int)
	{
		return UInt128(xmm) - UInt128::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UInt128 operator * (const UInt128 &X) const
	{
		return UInt128(_mm_mullo_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UInt128 &X)
	{
		xmm = _mm_mullo_epi32(xmm, X.xmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt128 operator / (const UInt128 &X) const
	{
		std::array<uint, 4> tmpa;
		std::array<uint, 4> tmpb;
		_mm_storeu_si128(reinterpret_cast<__m128i*>(tmpa.data()), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(tmpb.data()), X.xmm);
		CEXASSERT(tmpb[0] != 0 && tmpb[1] != 0 && tmpb[2] != 0 && tmpb[3] != 0, "Division by zero");

		return UInt128(tmpa[3] / tmpb[3], tmpa[2] / tmpb[2], tmpa[1] / tmpb[1], tmpa[0] / tmpb[0]);
		// TODO: optimize this
		//return UInt128(_mm_cvtps_epi32(_mm_round_ps(_mm_div_ps(_mm_cvtepi32_ps(xmm), _mm_cvtepi32_ps(X.xmm)), _MM_FROUND_TO_ZERO)));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UInt128 &X)
	{
		std::array<uint, 4> tmpa;
		std::array<uint, 4> tmpb;
		_mm_storeu_si128(reinterpret_cast<__m128i*>(tmpa.data()), xmm);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(tmpb.data()), X.xmm);
		CEXASSERT(tmpb[0] != 0 && tmpb[1] != 0 && tmpb[2] != 0 && tmpb[3] != 0, "Division by zero");

		xmm = _mm_set_epi32(tmpa[3] / tmpb[3], tmpa[2] / tmpb[2], tmpa[1] / tmpb[1], tmpa[0] / tmpb[0]);
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt128 operator % (const UInt128 &X) const
	{
		return UInt128(UInt128(xmm) - ((UInt128(xmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UInt128 &X)
	{
		xmm = UInt128(UInt128(xmm) - ((UInt128(xmm) / X) * X)).xmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UInt128 operator ^ (const UInt128 &X) const
	{
		return UInt128(_mm_xor_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UInt128 &X)
	{
		xmm = _mm_xor_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Bitwise OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt128 operator | (const UInt128 &X) const
	{
		return UInt128(_mm_or_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UInt128 &X)
	{
		xmm = _mm_or_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt128 operator || (const UInt128 &X) const
	{
		return UInt128(xmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt128 operator & (const UInt128 &X) const
	{
		return UInt128(_mm_and_si128(xmm, X.xmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UInt128 &X)
	{
		xmm = _mm_and_si128(xmm, X.xmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt128 operator && (const UInt128 &X) const
	{
		return UInt128(xmm) & X;
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator > (UInt128 const &X) const
	{
		return UInt128(_mm_cmpgt_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator < (UInt128 const &X) const
	{
		return UInt128(_mm_cmplt_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator >= (UInt128 const &X) const
	{
		return UInt128(UInt128(~(X > UInt128(xmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator <= (UInt128 const &X) const
	{
		return X >= UInt128(xmm);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator << (int Shift) const
	{
		return UInt128(_mm_slli_epi32(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (int Shift)
	{
		xmm = _mm_slli_epi32(xmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator >> (int Shift) const
	{
		return UInt128(_mm_srli_epi32(xmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (int Shift)
	{
		xmm = _mm_srli_epi32(xmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt128 operator ~ () const
	{
		return UInt128(_mm_xor_si128(xmm, _mm_set1_epi32(0xFFFFFFFFUL)));
	}

	/// <summary>
	/// Equals assignment operator
	/// </summary>
	///
	/// <param name="X">The value to assign</param>
	inline void operator = (const UInt128 &X)
	{
		xmm = X.xmm;
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator == (UInt128 const &X) const
	{
		return UInt128(_mm_cmpeq_epi32(xmm, X.xmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UInt128 operator ! () const
	{
		return UInt128(_mm_cmpeq_epi32(xmm, _mm_setzero_si128()));
	}

	/// <summary>
	/// Compare this integer for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt128 operator != (const UInt128 &X) const
	{
		return ~UInt128(_mm_cmpeq_epi32(xmm, X.xmm));
	}
};

NAMESPACE_NUMERICEND

#endif
