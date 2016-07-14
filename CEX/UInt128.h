#ifndef _CEXENGINE_UINT128_H
#define _CEXENGINE_UINT128_H

#include "Common.h"
//#include <emmintrin.h>
#include "Intrinsics.h"

NAMESPACE_COMMON

/// <summary>
/// An SSE 128 intrinsics wrapper with operators
/// </summary>
class UInt128
{
private:
	UInt128(__m128i Input) 
	{
		Register = Input;
	}

public:
	/// <summary>
	/// 
	/// </summary>
	__m128i Register;

	/* Constructor */

	UInt128() {}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<byte> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<uint> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<ulong> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 4 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">Register 0</param>
	/// <param name="X1">Register 1</param>
	/// <param name="X2">Register 2</param>
	/// <param name="X3">Register 3</param>
	UInt128(uint X0, uint X1, uint X2, uint X3)
	{
		Register = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	UInt128(uint X)
	{
		Register = _mm_set1_epi32(X);
	}

	/* Load and Store */

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <class T>
	void LoadLE(const std::vector<T> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Load an array into a register in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <class T>
	void LoadBE(const std::vector<T> &Input, size_t Offset)
	{
		Swap().LoadLE(Input, Offset);
	}

	/// <summary>
	/// Store register in an integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <class T>
	void StoreLE(std::vector<T> &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), Register);
	}

	/// <summary>
	/// Store register in an integer array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <class T>
	void StoreBE(std::vector<T> &Output, size_t Offset) const
	{
		Swap().StoreLE(Output, Offset);
	}

	/* Methods */

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in Value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	UInt128 AndNot(const UInt128 &Value)
	{
		return UInt128(_mm_andnot_si128(Register, Value.Register));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	void Rotl32(const int Shift)
	{
		Register = _mm_or_si128(_mm_slli_epi32(Register, static_cast<int>(Shift)), _mm_srli_epi32(Register, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	static inline UInt128 Rotl32(const UInt128 &Value, const int Shift)
	{
		return UInt128(_mm_or_si128(_mm_slli_epi32(Value.Register, static_cast<int>(Shift)), _mm_srli_epi32(Value.Register, static_cast<int>(32 - Shift))));
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	void Rotr32(const int Shift)
	{
		Rotl32(32 - Shift);
	}

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	static inline UInt128 Rotr32(const UInt128 &Value, const int Shift)
	{
		return Rotl32(Value, 32 - Shift);
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	UInt128 Swap() const
	{
		__m128i T = Register;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1)); // ?
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Shuffles the registers in 4 * UInt128 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void Transpose(UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		__m128i T0 = _mm_unpacklo_epi32(X0.Register, X1.Register);
		__m128i T1 = _mm_unpacklo_epi32(X2.Register, X3.Register);
		__m128i T2 = _mm_unpackhi_epi32(X0.Register, X1.Register);
		__m128i T3 = _mm_unpackhi_epi32(X2.Register, X3.Register);
		X0.Register = _mm_unpacklo_epi64(T0, T1);
		X1.Register = _mm_unpackhi_epi64(T0, T1);
		X2.Register = _mm_unpacklo_epi64(T2, T3);
		X3.Register = _mm_unpackhi_epi64(T2, T3);
	}

	/* Operators */

	void operator += (const UInt128 &Value)
	{
		Register = _mm_add_epi32(Register, Value.Register);
	}

	UInt128 operator + (const UInt128 &Value) const
	{
		return UInt128(_mm_add_epi32(Register, Value.Register));
	}

	void operator -= (const UInt128 &Value)
	{
		Register = _mm_sub_epi32(Register, Value.Register);
	}

	UInt128 operator - (const UInt128 &Value) const
	{
		return UInt128(_mm_sub_epi32(Register, Value.Register));
	}

	void operator *= (const UInt128 &Value)
	{
#if defined(__SSE4_1__)
		Register = _mm_mullo_epi32(Register, Value.Register);
#else 
		__m128i tmp1 = _mm_mul_epu32(Register, Value.Register);
		__m128i tmp2 = _mm_mul_epu32(_mm_srli_si128(Register, 4), _mm_srli_si128(Value.Register, 4));
		Register = _mm_unpacklo_epi32(_mm_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
#endif
	}

	UInt128 operator * (const UInt128 &Value) const
	{
#if defined(__SSE4_1__)
		return UInt128(_mm_mullo_epi32(Register, Value.Register));
#else 
		__m128i tmp1 = _mm_mul_epu32(Register, Value.Register);
		__m128i tmp2 = _mm_mul_epu32(_mm_srli_si128(Register, 4), _mm_srli_si128(Value.Register, 4));
		return UInt128(_mm_unpacklo_epi32(_mm_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
#endif
	}

	void operator /= (const UInt128 &Value)
	{
		Register.m128i_u32[0] /= Value.Register.m128i_u32[0];
		Register.m128i_u32[1] /= Value.Register.m128i_u32[1];
		Register.m128i_u32[2] /= Value.Register.m128i_u32[2];
		Register.m128i_u32[3] /= Value.Register.m128i_u32[3];
	}

	UInt128 operator / (const UInt128 &Value) const
	{
		return UInt128(
			Register.m128i_u32[0] / Value.Register.m128i_u32[0],
			Register.m128i_u32[1] / Value.Register.m128i_u32[1],
			Register.m128i_u32[2] / Value.Register.m128i_u32[2],
			Register.m128i_u32[3] / Value.Register.m128i_u32[3]);
	}

	void operator %= (const UInt128 &Value)
	{
		Register.m128i_u32[0] %= Value.Register.m128i_u32[0];
		Register.m128i_u32[1] %= Value.Register.m128i_u32[1];
		Register.m128i_u32[2] %= Value.Register.m128i_u32[2];
		Register.m128i_u32[3] %= Value.Register.m128i_u32[3];
	}

	UInt128 operator % (const UInt128 &Value) const
	{
		return UInt128(
			Register.m128i_u32[0] % Value.Register.m128i_u32[0],
			Register.m128i_u32[1] % Value.Register.m128i_u32[1],
			Register.m128i_u32[2] % Value.Register.m128i_u32[2],
			Register.m128i_u32[3] % Value.Register.m128i_u32[3]);
	}

	void operator ^= (const UInt128 &Value)
	{
		Register = _mm_xor_si128(Register, Value.Register);
	}

	UInt128 operator ^ (const UInt128 &Value) const
	{
		return UInt128(_mm_xor_si128(Register, Value.Register));
	}

	void operator |= (const UInt128 &Value)
	{
		Register = _mm_or_si128(Register, Value.Register);
	}

	UInt128 operator | (const UInt128 &Value)
	{
		return UInt128(_mm_or_si128(Register, Value.Register));
	}

	void operator &= (const UInt128 &Value)
	{
		Register = _mm_and_si128(Register, Value.Register);
	}

	UInt128 operator & (const UInt128 &Value)
	{
		return UInt128(_mm_and_si128(Register, Value.Register));
	}

	void operator <<= (const int Shift)
	{
		Register = _mm_slli_epi32(Register, Shift);
	}

	UInt128 operator << (const int Shift) const
	{
		return UInt128(_mm_slli_epi32(Register, static_cast<int>(Shift)));
	}

	void operator >>= (const int Shift)
	{
		Register = _mm_srli_epi32(Register, Shift);
	}

	UInt128 operator >> (const int Shift) const
	{
		return UInt128(_mm_srli_epi32(Register, static_cast<int>(Shift)));
	}

	UInt128 operator ~ () const
	{
		return UInt128(_mm_xor_si128(Register, _mm_set1_epi32(0xFFFFFFFF)));
	}
};

NAMESPACE_COMMONEND
#endif