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

#ifndef CEX_UINT256_H
#define CEX_UINT256_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

/// <summary>
/// An AVX2 256bit SIMD intrinsics wrapper.
/// <para>Processes blocks of 32bit unsigned integers.</para>
/// </summary>
class UInt256
{
#if defined(__AVX2__)

public:

	/// <summary>
	/// The internal m256i register value
	/// </summary>
	__m256i ymm;

	//~~~ Constants~~~//

	/// <summary>
	/// A UInt256 initialized with 8x 32bit integers to the value one
	/// </summary>
	inline static const UInt256 ONE()
	{
		return UInt256(_mm256_set1_epi32(1));
	}

	/// <summary>
	/// A UInt256 initialized with 8x 32bit integers to the value zero
	/// </summary>
	inline static const UInt256 ZERO()
	{
		return UInt256(_mm256_set1_epi32(0));
	}

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt256() {}

	/// <summary>
	/// Initialize the register with an __m256i value
	/// </summary>
	///
	/// <param name="Y">The 256bit register</param>
	explicit UInt256(__m256i const &Y)
	{
		ymm = Y;
	}

	/// <summary>
	/// Initialize with an integer array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template<typename Array>
	explicit UInt256(const Array &Input, size_t Offset)
	{
		ymm = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 8 * 32bit unsigned integers
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
	explicit UInt256(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7)
	{
		ymm = _mm256_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt256(uint X)
	{
		ymm = _mm256_set1_epi32(X);
	}

	//~~~ Load and Store~~~//

	/// <summary>
	/// Load an integer array into a register
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits long</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename Array>
	inline void Load(const Array &Input, size_t Offset)
	{
		ymm = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load with 8 * 32bit unsigned integers
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
	inline void Load(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7)
	{
		ymm = _mm256_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Load an integer array into a register.
	/// <para>Integers are loaded as 32bit integers regardless the arrays integer size</para>
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename Array>
	inline void LoadUL(const Array &Input, size_t Offset)
	{
		ymm = _mm256_set_epi32(static_cast<uint>(Input[Offset]), static_cast<uint>(Input[Offset + 1]), static_cast<uint>(Input[Offset + 2]), static_cast<uint>(Input[Offset + 3]),
			static_cast<uint>(Input[Offset + 4]), static_cast<uint>(Input[Offset + 5]), static_cast<uint>(Input[Offset + 6]), static_cast<uint>(Input[Offset + 7]));
	}

	/// <summary>
	/// Transposes and loads 4 * UInt256 at 32bit boundaries into an array
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 1024 bits in length</param>
	/// <param name="Offset">The starting position within the Input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename Array>
	inline static void Load4(const Array &Input, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		X0.Load(Input, Offset);
		X1.Load(Input, Offset + (32 / sizeof(Input[0])));
		X2.Load(Input, Offset + (64 / sizeof(Input[0])));
		X3.Load(Input, Offset + (96 / sizeof(Input[0])));
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Store register in an integer array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	template <typename Array>
	inline void Store(Array &Output, size_t Offset) const
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), ymm);
	}

	/// <summary>
	/// Transposes and stores 4 * UInt256 to an array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 1024 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	template <typename Array>
	inline static void Store4(Array &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.Store(Output, Offset);
		X1.Store(Output, Offset + (32 / sizeof(Output[0])));
		X2.Store(Output, Offset + (64 / sizeof(Output[0])));
		X3.Store(Output, Offset + (96 / sizeof(Output[0])));
	}

	/// <summary>
	/// Transposes and stores 16 * UInt256 to an array
	/// </summary>
	///
	/// <param name="Output">The destination integer array; must be at least 4096 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	/// <param name="X4">Operand 4</param>
	/// <param name="X5">Operand 5</param>
	/// <param name="X6">Operand 6</param>
	/// <param name="X7">Operand 7</param>
	/// <param name="X8">Operand 8</param>
	/// <param name="X9">Operand 9</param>
	/// <param name="X10">Operand 10</param>
	/// <param name="X11">Operand 11</param>
	/// <param name="X12">Operand 12</param>
	/// <param name="X13">Operand 13</param>
	/// <param name="X14">Operand 14</param>
	/// <param name="X15">Operand 15</param>
	template <typename Array>
	inline static void Store16(Array &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3, UInt256 &X4, UInt256 &X5,
		UInt256 &X6, UInt256 &X7, UInt256 &X8, UInt256 &X9, UInt256 &X10, UInt256 &X11, UInt256 &X12, UInt256 &X13, UInt256 &X14, UInt256 &X15)
	{
		__m256i W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
		__m256i Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, Y15;

		_mm256_merge_epi32(X0.ymm, X1.ymm, W0, W1);
		_mm256_merge_epi32(X2.ymm, X3.ymm, W2, W3);
		_mm256_merge_epi32(X4.ymm, X5.ymm, W4, W5);
		_mm256_merge_epi32(X6.ymm, X7.ymm, W6, W7);
		_mm256_merge_epi32(X8.ymm, X9.ymm, W8, W9);
		_mm256_merge_epi32(X10.ymm, X11.ymm, W10, W11);
		_mm256_merge_epi32(X12.ymm, X13.ymm, W12, W13);
		_mm256_merge_epi32(X14.ymm, X15.ymm, W14, W15);

		_mm256_merge_epi64(W0, W2, Y0, Y1);
		_mm256_merge_epi64(W4, W6, Y2, Y3);
		_mm256_merge_epi64(W8, W10, Y4, Y5);
		_mm256_merge_epi64(W12, W14, Y6, Y7);
		_mm256_merge_epi64(W1, W3, Y8, Y9);
		_mm256_merge_epi64(W5, W7, Y10, Y11);
		_mm256_merge_epi64(W9, W11, Y12, Y13);
		_mm256_merge_epi64(W13, W15, Y14, Y15);

		_mm256_merge_si128(Y0, Y2, X0.ymm, X1.ymm);
		_mm256_merge_si128(Y1, Y3, X2.ymm, X3.ymm);
		_mm256_merge_si128(Y8, Y10, X4.ymm, X5.ymm);
		_mm256_merge_si128(Y9, Y11, X6.ymm, X7.ymm);
		_mm256_merge_si128(Y4, Y6, X8.ymm, X9.ymm);
		_mm256_merge_si128(Y5, Y7, X10.ymm, X11.ymm);
		_mm256_merge_si128(Y12, Y14, X12.ymm, X13.ymm);
		_mm256_merge_si128(Y13, Y15, X14.ymm, X15.ymm);

		X0.Store(Output, Offset);
		X8.Store(Output, Offset + (32 / sizeof(Output[0])));
		X1.Store(Output, Offset + (64 / sizeof(Output[0])));
		X9.Store(Output, Offset + (96 / sizeof(Output[0])));
		X2.Store(Output, Offset + (128 / sizeof(Output[0])));
		X10.Store(Output, Offset + (160 / sizeof(Output[0])));
		X3.Store(Output, Offset + (192 / sizeof(Output[0])));
		X11.Store(Output, Offset + (224 / sizeof(Output[0])));
		X4.Store(Output, Offset + (256 / sizeof(Output[0])));
		X12.Store(Output, Offset + (288 / sizeof(Output[0])));
		X5.Store(Output, Offset + (320 / sizeof(Output[0])));
		X13.Store(Output, Offset + (352 / sizeof(Output[0])));
		X6.Store(Output, Offset + (384 / sizeof(Output[0])));
		X14.Store(Output, Offset + (416 / sizeof(Output[0])));
		X7.Store(Output, Offset + (448 / sizeof(Output[0])));
		X15.Store(Output, Offset + (480 / sizeof(Output[0])));
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Returns the absolute value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt256</returns>
	inline static UInt256 Abs(const UInt256 &Value)
	{
		return UInt256(_mm256_abs_epi32(Value.ymm));
	}

	/// <summary>
	/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in X
	/// </summary>
	///
	/// <param name="X">The comparison integer</param>
	/// 
	/// <returns>The processed UInt256</returns>
	inline UInt256 AndNot(const UInt256 &X)
	{
		return UInt256(_mm256_andnot_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Returns the bitwise negation of 8 32bit integers
	/// </summary>
	///
	/// <param name="Value">The integers to negate</param>
	/// 
	/// <returns>The processed UInt256</returns>
	inline static UInt256 Negate(const UInt256 &Value)
	{
		return UInt256(_mm256_sub_epi32(_mm256_set1_epi32(0), Value.ymm));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	inline static const size_t size() 
	{ 
		return sizeof(__m256i); 
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotL32(const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		ymm = _mm256_or_si256(_mm256_slli_epi32(ymm, static_cast<int>(Shift)), _mm256_srli_epi32(ymm, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt256</returns>
	inline static UInt256 RotL32(const UInt256 &X, const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		return UInt256(_mm256_or_si256(_mm256_slli_epi32(X.ymm, static_cast<int>(Shift)), _mm256_srli_epi32(X.ymm, static_cast<int>(32 - Shift))));
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline void RotR32(const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		RotL32(32 - Shift);
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="X">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt256</returns>
	inline static UInt256 RotR32(const UInt256 &X, const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		return RotL32(X, 32 - Shift);
	}

	/// <summary>
	/// Shifts the 8 signed 32-bit integers in a right by count bits while shifting in the sign bit
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt256</returns>
	inline static UInt256 ShiftRA(const UInt256 &Value, const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		return UInt256(_mm256_sra_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Shifts the 8 signed or unsigned 32-bit integers in a right by count bits while shifting in zeros.
	/// </summary>
	///
	/// <param name="Value">The base integer</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The processed UInt256</returns>
	inline static UInt256 ShiftRL(const UInt256 &Value, const int Shift)
	{
		CexAssert(Shift <= 32, "Shift size is too large");
		return UInt256(_mm256_srl_epi32(Value, _mm_set1_epi32(Shift)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt256</returns>
	UInt256 Swap() const
	{
		__m256i tmpX = ymm;

		tmpX = _mm256_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm256_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt256(_mm256_or_si256(_mm256_srli_epi16(tmpX, 8), _mm256_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt256 to process</param>
	/// 
	/// <returns>The byte swapped UInt256</returns>
	inline static UInt256 Swap(UInt256 &X)
	{
		__m256i tmpX = X.ymm;

		tmpX = _mm256_shufflehi_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));
		tmpX = _mm256_shufflelo_epi16(tmpX, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt256(_mm256_or_si256(_mm256_srli_epi16(tmpX, 8), _mm256_slli_epi16(tmpX, 8)));
	}

	/// <summary>
	/// Shuffles the registers in 4 * UInt256 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	inline static void Transpose(UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		__m256i T0 = _mm256_unpacklo_epi32(X0.ymm, X1.ymm);
		__m256i T1 = _mm256_unpacklo_epi32(X2.ymm, X3.ymm);
		__m256i T2 = _mm256_unpackhi_epi32(X0.ymm, X1.ymm);
		__m256i T3 = _mm256_unpackhi_epi32(X2.ymm, X3.ymm);
		X0.ymm = _mm256_unpacklo_epi64(T0, T1);
		X1.ymm = _mm256_unpackhi_epi64(T0, T1);
		X2.ymm = _mm256_unpacklo_epi64(T2, T3);
		X3.ymm = _mm256_unpackhi_epi64(T2, T3);
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Type cast operator
	/// </summary>
	operator __m256i() const
	{
		return ymm;
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline UInt256 operator + (const UInt256 &X) const
	{
		return UInt256(_mm256_add_epi32(ymm, X.ymm));
	}

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="X">The value to add</param>
	inline void operator += (const UInt256 &X)
	{
		ymm = _mm256_add_epi32(ymm, X.ymm);
	}

	/// <summary>
	/// Increase prefix operator
	/// </summary>
	inline UInt256 operator ++ ()
	{
		return UInt256(ymm) + UInt256::ONE();
	}

	/// <summary>
	/// Increase postfix operator
	/// </summary>
	inline UInt256 operator ++ (int)
	{
		return UInt256(ymm) + UInt256::ONE();
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline UInt256 operator - (const UInt256 &X) const
	{
		return UInt256(_mm256_sub_epi32(ymm, X.ymm));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="X">The value to subtract</param>
	inline void operator -= (const UInt256 &X)
	{
		ymm = _mm256_sub_epi32(ymm, X.ymm);
	}

	/// <summary>
	/// Decrease prefix operator
	/// </summary>
	inline UInt256 operator -- ()
	{
		return UInt256(ymm) - UInt256::ONE();
	}

	/// <summary>
	/// Decrease postfix operator
	/// </summary>
	inline UInt256 operator -- (int)
	{
		return UInt256(ymm) - UInt256::ONE();
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline UInt256 operator * (const UInt256 &X) const
	{
		return UInt256(_mm256_mullo_epi32(ymm, X.ymm));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="X">The value to multiply</param>
	inline void operator *= (const UInt256 &X)
	{
		ymm = _mm256_mullo_epi32(ymm, X.ymm);
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt256 operator / (const UInt256 &X) const
	{
		std::array<uint, 8> tmpA;
		std::array<uint, 8> tmpB;
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpA[0]), ymm);
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpB[0]), X.ymm);
		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		return UInt256(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//return UInt256(_mm256_cvtps_epi32(_mm256_div_ps(_mm256_cvtepi32_ps(ymm), _mm256_cvtepi32_ps(X.ymm))));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator /= (const UInt256 &X)
	{
		std::array<uint, 8> tmpA;
		std::array<uint, 8> tmpB;
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpA[0]), ymm);
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&tmpB[0]), X.ymm);
		CexAssert(tmpB[0] != 0 && tmpB[1] != 0 && tmpB[2] != 0 && tmpB[3] != 0 && tmpB[4] != 0 && tmpB[5] != 0 && tmpB[6] != 0 && tmpB[7] != 0, "Division by zero");

		ymm = _mm256_set_epi32(tmpA[7] / tmpB[7], tmpA[6] / tmpB[6], tmpA[5] / tmpB[5], tmpA[4] / tmpB[4],
			tmpA[3] / tmpB[3], tmpA[2] / tmpB[2], tmpA[1] / tmpB[1], tmpA[0] / tmpB[0]);

		// TODO: finish this
		//ymm = _mm256_cvtps_epi32(_mm256_div_ps(_mm256_cvtepi32_ps(ymm), _mm256_cvtepi32_ps(X.ymm)));
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline UInt256 operator % (const UInt256 &X) const
	{
		return UInt256(UInt256(ymm) - ((UInt256(ymm) / X) * X));
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="X">The divisor value</param>
	inline void operator %= (const UInt256 &X)
	{
		ymm = UInt256(UInt256(ymm) - ((UInt256(ymm) / X) * X)).ymm;
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline UInt256 operator ^ (const UInt256 &X) const
	{
		return UInt256(_mm256_xor_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="X">The value to Xor</param>
	inline void operator ^= (const UInt256 &X)
	{
		ymm = _mm256_xor_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Bitwise OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt256 operator | (const UInt256 &X)
	{
		return UInt256(_mm256_or_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Bitwise OR this integer
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline void operator |= (const UInt256 &X)
	{
		ymm = _mm256_or_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Logical OR of two integers
	/// </summary>
	///
	/// <param name="X">The value to OR</param>
	inline UInt256 operator || (const UInt256 &X) const
	{
		return UInt256(ymm) | X;
	}

	/// <summary>
	/// Bitwise AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt256 operator & (const UInt256 &X)
	{
		return UInt256(_mm256_and_si256(ymm, X.ymm));
	}

	/// <summary>
	/// Bitwise AND this integer
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline void operator &= (const UInt256 &X)
	{
		ymm = _mm256_and_si256(ymm, X.ymm);
	}

	/// <summary>
	/// Logical AND of two integers
	/// </summary>
	///
	/// <param name="X">The value to AND</param>
	inline UInt256 operator && (const UInt256 &X) const
	{
		return UInt256(ymm) & X;
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt256 operator << (const int Shift) const
	{
		return UInt256(_mm256_slli_epi32(ymm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		ymm = _mm256_slli_epi32(ymm, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt256 operator >> (const int Shift) const
	{
		return UInt256(_mm256_srli_epi32(ymm, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		ymm = _mm256_srli_epi32(ymm, Shift);
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt256 operator ~ () const
	{
		return UInt256(_mm256_xor_si256(ymm, _mm256_set1_epi32(0xFFFFFFFF)));
	}

	/// <summary>
	/// Greater than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator > (UInt256 const &X) const
	{
		return UInt256(_mm256_cmpgt_epi32(ymm, X.ymm));
	}

	/// <summary>
	/// Less than operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator < (UInt256 const &X) const
	{
		return UInt256(_mm256_cmpgt_epi32(X.ymm, ymm));
	}

	/// <summary>
	/// Greater than or equal operator
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator >= (UInt256 const &X) const
	{
		return UInt256(UInt256(~(X > UInt256(ymm))));
	}

	/// <summary>
	/// Less than operator or equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator <= (UInt256 const &X) const
	{
		return X >= UInt256(ymm);
	}

	/// <summary>
	/// Compare two sets of integers for equality, returns max integer size if equal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator == (UInt256 const &X) const
	{
		return UInt256(_mm256_cmpeq_epi32(ymm, X.ymm));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	inline UInt256 operator ! () const
	{
		return UInt256(_mm256_cmpeq_epi32(ymm, _mm256_setzero_si256()));
	}

	/// <summary>
	/// Compare two sets of integers for inequality, returns max integer size if inequal
	/// </summary>
	///
	/// <param name="X">The values to compare</param>
	inline UInt256 operator != (const UInt256 &X) const
	{
		return ~UInt256(_mm256_cmpeq_epi32(ymm, X.ymm));
	}

private:

	inline static void _mm256_merge_epi32(const __m256i &X0, const __m256i &X1, __m256i &Xl, __m256i &Xh)
	{
		__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
		__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
		Xl = _mm256_unpacklo_epi32(va, vb);
		Xh = _mm256_unpackhi_epi32(va, vb);
	}

	inline static void _mm256_merge_epi64(const __m256i &X0, const __m256i &X1, __m256i &Xl, __m256i &Xh)
	{
		__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
		__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
		Xl = _mm256_unpacklo_epi64(va, vb);
		Xh = _mm256_unpackhi_epi64(va, vb);
	}

	inline static void _mm256_merge_si128(const __m256i &X0, const __m256i &X1, __m256i &Xl, __m256i &Xh)
	{
		Xl = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 2, 0, 0));
		Xh = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 3, 0, 1));
	}

#endif
};

NAMESPACE_NUMERICEND
#endif