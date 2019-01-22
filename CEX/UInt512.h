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

#ifndef CEX_UINT512_H
#define CEX_UINT512_H

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
/// <para>Processes blocks of 32bit unsigned integers.</para>
/// </summary>
class UInt512
{
#if defined(__AVX512__)

public:

	/// <summary>
	/// The internal m512i register value
	/// </summary>
	__m512i zmm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UInt512 initialized with 16x 32bit integers to the value one
	/// </summary>
	inline static const UInt512 ONE()
	{
		return UInt512(_mm512_set1_epi32(1));
	}

	/// <summary>
	/// A UInt512 initialized with 16x 32bit integers to the value zero
	/// </summary>
	inline static const UInt512 ZERO()
	{
		return UInt512(_mm512_set1_epi32(0));
	}

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt512() 
	{
	}

	/// <summary>
	/// Initialize the register with an __m512i value
	/// </summary>
	///
	/// <param name="Z">The 256bit register</param>
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
	explicit UInt512(const Array &Input, size_t Offset)
	{
		zmm = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 16 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint32 0</param>
	/// <param name="X1">uint32 1</param>
	/// <param name="X2">uint32 2</param>
	/// <param name="X3">uint32 3</param>
	/// <param name="X4">uint32 4</param>
	/// <param name="X5">uint32 5</param>
	/// <param name="X6">uint32 6</param>
	/// <param name="X7">uint32 7</param>
	/// <param name="X8">uint32 8</param>
	/// <param name="X9">uint32 9</param>
	/// <param name="X10">uint32 10</param>
	/// <param name="X11">uint32 11</param>
	/// <param name="X12">uint32 12</param>
	/// <param name="X13">uint32 13</param>
	/// <param name="X14">uint32 14</param>
	/// <param name="X15">uint32 15</param>
	explicit UInt512(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7,
		uint X8, uint X9, uint X10, uint X11, uint X12, uint X13, uint X14, uint X15)
	{
		zmm = _mm512_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt512(uint X)
	{
		zmm = _mm512_set1_epi32(X);
	}

	/// <summary>
	/// Read Only: The SIMD wrappers type name
	/// </summary>
	const SimdIntegers Enumeral()
	{
		return SimdIntegers::UInt512;
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">Set all uint32 integers to this value</param>
	inline void Load(uint X)
	{
		zmm = _mm512_set1_epi32(X);
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
	/// Load with 16 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">uint32 0</param>
	/// <param name="X1">uint32 1</param>
	/// <param name="X2">uint32 2</param>
	/// <param name="X3">uint32 3</param>
	/// <param name="X4">uint32 4</param>
	/// <param name="X5">uint32 5</param>
	/// <param name="X6">uint32 6</param>
	/// <param name="X7">uint32 7</param>
	/// <param name="X8">uint32 8</param>
	/// <param name="X9">uint32 9</param>
	/// <param name="X10">uint32 10</param>
	/// <param name="X11">uint32 11</param>
	/// <param name="X12">uint32 12</param>
	/// <param name="X13">uint32 13</param>
	/// <param name="X14">uint32 14</param>
	/// <param name="X15">uint32 15</param>
	inline void Load(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7,
		uint X8, uint X9, uint X10, uint X11, uint X12, uint X13, uint X14, uint X15)
	{
		zmm = _mm512_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);
	}

	/// <summary>
	/// Load an array of integers into a register.
	/// <para>Integers are loaded as 32bit integers regardless the natural size of T</para>
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 512 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	inline void LoadUL(const Array &Input, size_t Offset)
	{
		zmm = _mm512_set_epi32(static_cast<uint>(Input[Offset]), static_cast<uint>(Input[Offset + 1]), static_cast<uint>(Input[Offset + 2]), static_cast<uint>(Input[Offset + 3]),
			static_cast<uint>(Input[Offset + 4]), static_cast<uint>(Input[Offset + 5]), static_cast<uint>(Input[Offset + 6]), static_cast<uint>(Input[Offset + 7]),
			static_cast<uint>(Input[Offset + 8]), static_cast<uint>(Input[Offset + 9]), static_cast<uint>(Input[Offset + 10]), static_cast<uint>(Input[Offset + 11]),
			static_cast<uint>(Input[Offset + 12]), static_cast<uint>(Input[Offset + 13]), static_cast<uint>(Input[Offset + 14]), static_cast<uint>(Input[Offset + 15]));
	}

	/// <summary>
	/// Transposes and loads 4 * UInt512 to an integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 2048 bits in length</param>
	/// <param name="Offset">The starting position within the Input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template<typename Array>
	inline static void Load4(const Array &Input, size_t Offset, UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		X0.Load(Input, Offset);
		X1.Load(Input, Offset + (64 / sizeof(Input[0])));
		X2.Load(Input, Offset + (128 / sizeof(Input[0])));
		X3.Load(Input, Offset + (192 / sizeof(Input[0])));
		Transpose(X0, X1, X2, X3);
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
	/// Transposes and stores 4 * UInt512 to an integer array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 2048 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template<typename Array>
	inline static void Store4(Array &Output, size_t Offset, UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (64 / sizeof(Output[0])));
		X2.Store(Output, Offset + (128 / sizeof(Output[0])));
		X3.Store(Output, Offset + (192 / sizeof(Output[0])));
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 Abs(const UInt512 &Value)
	{
		return UInt512(_mm512_abs_epi32(Value.zmm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 512-bit value in *this* and the bitwise NOT of the 512-bit value in X
	/// </summary>
	///
	/// <param name="X">The comparison integer</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline UInt512 AndNot(const UInt512 &X)
	{
		return UInt512(_mm512_andnot_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	const size_t size() { return sizeof(__m512i); }

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotL32(const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		zmm = _mm512_or_si512(_mm512_slli_epi32(zmm, static_cast<int>(Shift)), _mm512_srli_epi32(zmm, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt512</returns>
	inline static UInt512 RotL32(const UInt512 &X, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt512(_mm512_or_si512(_mm512_slli_epi32(X.zmm, static_cast<int>(Shift)), _mm512_srli_epi32(X.zmm, static_cast<int>(32 - Shift))));
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotR32(const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		RotL32(32 - Shift);
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt512</returns>
	inline static UInt512 RotR32(const UInt512 &X, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return RotL32(X, 32 - Shift);
	}

	/// <summary>
	/// Shifts the 16 signed 32-bit integers in a right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 ShiftRA(const UInt512 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt512(_mm512_sra_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Shifts the 16 signed or unsigned 32-bit integers in a right by count bits while shifting in zeros
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt512</returns>
	inline static UInt512 ShiftRL(const UInt512 &Value, const int Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");
		return UInt512(_mm512_srl_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt512</returns>
	inline UInt512 Swap() const
	{
		__m512i tmpX = zmm;

		tmpX = _mm512_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm512_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt512(_mm512_or_si512(_mm512_srli_epi16(tmpX, 8), _mm512_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt512 to process</param>
	/// 
	/// <returns>The byte swapped UInt512</returns>
	inline static UInt512 Swap(UInt512 &X)
	{
		__m512i tmpX = X.zmm;

		tmpX = _mm512_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm512_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt512(_mm512_or_si512(_mm512_srli_epi16(tmpX, 8), _mm512_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Shuffles the registers in 4 * UInt512 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void Transpose(UInt512 &X0, UInt512 &X1, UInt512 &X2, UInt512 &X3)
	{
		__m512i T0 = _mm512_unpacklo_epi32(X0.zmm, X1.zmm);
		__m512i T1 = _mm512_unpacklo_epi32(X2.zmm, X3.zmm);
		__m512i T2 = _mm512_unpackhi_epi32(X0.zmm, X1.zmm);
		__m512i T3 = _mm512_unpackhi_epi32(X2.zmm, X3.zmm);
		X0.zmm = _mm512_unpacklo_epi64(T0, T1);
		X1.zmm = _mm512_unpackhi_epi64(T0, T1);
		X2.zmm = _mm512_unpacklo_epi64(T2, T3);
		X3.zmm = _mm512_unpackhi_epi64(T2, T3);
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
	inline UInt512 operator + (const UInt512 &X) const
	{
		return UInt512(_mm512_add_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UInt512 &X)
	{
		zmm = _mm512_add_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UInt512 operator ++ ()
	{
		return UInt512(zmm) + UInt512::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UInt512 operator ++ (int)
	{
		return UInt512(zmm) + UInt512::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UInt512 operator - (const UInt512 &X) const
	{
		return UInt512(_mm512_sub_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UInt512 &X)
	{
		zmm = _mm512_sub_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UInt512 operator -- ()
	{
		return UInt512(zmm) - ZMM1();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UInt512 operator -- (int)
	{
		return UInt512(zmm) - UInt512::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UInt512 operator * (const UInt512 &X) const
	{
		return UInt512(_mm512_mullo_epi32(zmm, X.zmm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UInt512 &X)
	{
		zmm = _mm512_mullo_epi32(zmm, X.zmm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt512 operator / (const UInt512 &X) const
	{
		std::array<uint, 16> tmpA;
		std::array<uint, 16> tmpB;
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);
		CEXASSERT(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0 && 
			tmpB[8] != 0 && tmpB[9] != 0 && tmpB[10] != 0 && tmpB[11] != 0 && tmpB[12] != 0 && tmpB[13] != 0 && tmpB[14] != 0 && tmpB[15] != 0, "Division by zero");

		return UInt512(tmpA[15] / tmpB[15], tmpA[14] / tmpB[14], tmpA[13] / tmpB[13], tmpA[12] / tmpB[12],
			tmpA[11] / tmpB[11], tmpA[10] / tmpB[10], tmpA[9] / tmpB[9], tmpA[8] / tmpB[8],
			tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//return UInt512(_mm512_cvtps_epi32(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm))));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UInt512 &X)
	{
		std::array<uint, 16> tmpA;
		std::array<uint, 16> tmpB;
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpA[0]), zmm);
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&tmpB[0]), X.zmm);
		CEXASSERT(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0 &&
			tmpB[8] != 0 && tmpB[9] != 0 && tmpB[10] != 0 && tmpB[11] != 0 && tmpB[12] != 0 && tmpB[13] != 0 && tmpB[14] != 0 && tmpB[15] != 0, "Division by zero");

		zmm = _mm512_set_epi32(tmpA[15] / tmpB[15], tmpA[14] / tmpB[14], tmpA[13] / tmpB[13], tmpA[12] / tmpB[12],
			tmpA[11] / tmpB[11], tmpA[10] / tmpB[10], tmpA[9] / tmpB[9], tmpA[8] / tmpB[8],
			tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//zmm = _mm512_cvtps_epi32(_mm512_div_ps(_mm512_cvtepi32_ps(zmm), _mm512_cvtepi32_ps(X.zmm)));
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt512 operator % (const UInt512 &X) const
	{
		return UInt512(UInt512(zmm) - ((UInt512(zmm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UInt512 &X)
	{
		zmm = UInt512(UInt512(zmm) - ((UInt512(zmm) / X) * X)).zmm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UInt512 operator ^ (const UInt512 &X) const
	{
		return UInt512(_mm512_xor_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UInt512 &X)
	{
		zmm = _mm512_xor_si512(zmm, X.zmm);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt512 operator | (const UInt512 &X)
	{
		return UInt512(_mm512_or_si512(zmm, X.zmm));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UInt512 &X)
	{
		zmm = _mm512_or_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt512 operator || (const UInt512 &X) const
	{
		return UInt512(zmm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt512 operator & (const UInt512 &X)
	{
		return UInt512(_mm512_and_si512(zmm, X.zmm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UInt512 &X)
	{
		zmm = _mm512_and_si512(zmm, X.zmm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt512 operator && (const UInt512 &X) const
	{
		return UInt512(zmm) & X;
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt512 operator << (const int Shift) const
	{
		return UInt512(_mm512_slli_epi32(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		zmm = _mm512_slli_epi32(zmm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt512 operator >> (const int Shift) const
	{
		return UInt512(_mm512_srli_epi32(zmm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		zmm = _mm512_srli_epi32(zmm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt512 operator ~ () const
	{
		return UInt512(_mm512_xor_epi32(zmm, _mm512_set1_epi32(-1)));
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator > (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpgt_epi32_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator < (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpgt_epi32_mask(X.zmm, zmm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator >= (UInt512 const &X) const
	{
		return UInt512(UInt512(~(X > UInt512(zmm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator <= (UInt512 const &X) const
	{
		return X >= UInt512(zmm);
	}

	/// <summary>
	/// Equals assignment operator
	/// </summary>
	///
	/// <param name="X">The value to assign</param>
	inline void operator = (const UInt512 &X)
	{
		zmm = X.zmm;
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator == (UInt512 const &X) const
	{
		return UInt512(_mm512_cmpeq_epi32_mask(zmm, X.zmm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UInt512 operator ! () const
	{
		return UInt512(_mm512_cmpeq_epi32(zmm, _mm512_setzero_si512()));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt512 operator != (const UInt512 &X) const
	{
		return ~UInt512(_mm512_cmpneq_epi32_mask(zmm, X.zmm));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif