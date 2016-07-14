#ifndef _CEXENGINE_UINT256_H
#define _CEXENGINE_UINT256_H

#include "Common.h"
//#include <emmintrin.h>
#include "Intrinsics.h"

NAMESPACE_COMMON

/// <summary>
/// An SSE 256 intrinsics wrapper with operators
/// </summary>
class UInt256
{
private:
	UInt256(__m256i Input)
	{
		Register = Input;
	}

public:
	/// <summary>
	/// 
	/// </summary>
	__m256i Register;

	/* Constructor */

	UInt256() {}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt256(const std::vector<byte> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt256(const std::vector<uint> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt256(const std::vector<ulong> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with 4 * 32bit unsigned integers
	/// </summary>
	///
	/// <param name="X0">Register 0</param>
	/// <param name="X1">Register 1</param>
	/// <param name="X2">Register 2</param>
	/// <param name="X3">Register 3</param>
	/// <param name="X4">Register 4</param>
	/// <param name="X5">Register 5</param>
	/// <param name="X6">Register 6</param>
	/// <param name="X7">Register 7</param>
	UInt256(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7)
	{
		Register = _mm256_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	UInt256(uint X)
	{
		Register = _mm256_set1_epi32(X);
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
		Register = _mm256_loadu_si128(reinterpret_cast<const __m256i*>(&Input[Offset]));
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
		_mm256_storeu_si128(reinterpret_cast<__m256i*>(&Output[Offset]), Register);
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
	UInt256 AndNot(const UInt256 &Value)
	{
		return UInt256(_mm256_andnot_si256(Register, Value.Register));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	void Rotl32(const int Shift)
	{
		Register = _mm256_or_si256(_mm256_slli_epi32(Register, static_cast<int>(Shift)), _mm256_srli_epi32(Register, static_cast<int>(32 - Shift)));
	}

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	static inline UInt256 Rotl32(const UInt256 &Value, const int Shift)
	{
		return UInt256(_mm256_or_si256(_mm256_slli_epi32(Value.Register, static_cast<int>(Shift)), _mm256_srli_epi32(Value.Register, static_cast<int>(32 - Shift))));
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
	static inline UInt256 Rotr32(const UInt256 &Value, const int Shift)
	{
		return Rotl32(Value, 32 - Shift);
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	UInt256 Swap() const
	{
		__m256i T = Register;

		T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8))); // ?
	}

	/// <summary>
	/// Shuffles the registers in 4 * UInt256 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X0">Operand 1</param>
	/// <param name="X0">Operand 2</param>
	/// <param name="X0">Operand 3</param>
	static inline void Transpose(UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		__m256i T0 = _mm256_unpacklo_epi32(X0.Register, X1.Register); // ?
		__m256i T1 = _mm256_unpacklo_epi32(X2.Register, X3.Register);
		__m256i T2 = _mm256_unpackhi_epi32(X0.Register, X1.Register);
		__m256i T3 = _mm256_unpackhi_epi32(X2.Register, X3.Register);
		X0.Register = _mm256_unpacklo_epi64(T0, T1);
		X1.Register = _mm256_unpackhi_epi64(T0, T1);
		X2.Register = _mm256_unpacklo_epi64(T2, T3);
		X3.Register = _mm256_unpackhi_epi64(T2, T3);
	}

	/* Operators */

	void operator += (const UInt256 &Value)
	{
		Register = _mm256_add_epi32(Register, Value.Register);
	}

	UInt256 operator + (const UInt256 &Value) const
	{
		return UInt256(_mm256_add_epi32(Register, Value.Register));
	}

	void operator -= (const UInt256 &Value)
	{
		Register = _mm256_sub_epi32(Register, Value.Register);
	}

	UInt256 operator - (const UInt256 &Value) const
	{
		return UInt256(_mm256_sub_epi32(Register, Value.Register));
	}

	void operator *= (const UInt256 &Value)
	{
#if defined(__SSE4_1__)
		Register = _mm256_mullo_epi32(Register, Value.Register);
#else 
		__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
		Register = _mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
#endif
	}

	UInt256 operator * (const UInt256 &Value) const
	{
#if defined(__SSE4_1__)
		return UInt256(_mm_mullo_epi32(Register, Value.Register));
#else 
		__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
		return UInt256(_mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
#endif
	}

	void operator /= (const UInt256 &Value)
	{
		Register.m256i_u32[0] /= Value.Register.m256i_u32[0];
		Register.m256i_u32[1] /= Value.Register.m256i_u32[1];
		Register.m256i_u32[2] /= Value.Register.m256i_u32[2];
		Register.m256i_u32[3] /= Value.Register.m256i_u32[3];
		Register.m256i_u32[4] /= Value.Register.m256i_u32[4];
		Register.m256i_u32[5] /= Value.Register.m256i_u32[5];
		Register.m256i_u32[6] /= Value.Register.m256i_u32[6];
		Register.m256i_u32[7] /= Value.Register.m256i_u32[7];
	}

	UInt256 operator / (const UInt256 &Value) const
	{
		return UInt256(
			Register.m256i_u32[0] / Value.Register.m256i_u32[0],
			Register.m256i_u32[1] / Value.Register.m256i_u32[1],
			Register.m256i_u32[2] / Value.Register.m256i_u32[2],
			Register.m256i_u32[3] / Value.Register.m256i_u32[3],
			Register.m256i_u32[4] / Value.Register.m256i_u32[4],
			Register.m256i_u32[5] / Value.Register.m256i_u32[5],
			Register.m256i_u32[6] / Value.Register.m256i_u32[6],
			Register.m256i_u32[7] / Value.Register.m256i_u32[7]
		);
	}

	void operator %= (const UInt256 &Value)
	{
		Register.m256i_u32[0] %= Value.Register.m256i_u32[0];
		Register.m256i_u32[1] %= Value.Register.m256i_u32[1];
		Register.m256i_u32[2] %= Value.Register.m256i_u32[2];
		Register.m256i_u32[3] %= Value.Register.m256i_u32[3];
		Register.m256i_u32[4] %= Value.Register.m256i_u32[4];
		Register.m256i_u32[5] %= Value.Register.m256i_u32[5];
		Register.m256i_u32[6] %= Value.Register.m256i_u32[6];
		Register.m256i_u32[7] %= Value.Register.m256i_u32[7];
	}

	UInt256 operator % (const UInt256 &Value) const
	{
		return UInt256(
			Register.m256i_u32[0] % Value.Register.m256i_u32[0],
			Register.m256i_u32[1] % Value.Register.m256i_u32[1],
			Register.m256i_u32[2] % Value.Register.m256i_u32[2],
			Register.m256i_u32[3] % Value.Register.m256i_u32[3],
			Register.m256i_u32[4] % Value.Register.m256i_u32[4],
			Register.m256i_u32[5] % Value.Register.m256i_u32[5],
			Register.m256i_u32[6] % Value.Register.m256i_u32[6],
			Register.m256i_u32[7] % Value.Register.m256i_u32[7]
		);
	}

	void operator ^= (const UInt256 &Value)
	{
		Register = _mm256_xor_si256(Register, Value.Register);
	}

	UInt256 operator ^ (const UInt256 &Value) const
	{
		return UInt256(_mm256_xor_si256(Register, Value.Register));
	}

	void operator |= (const UInt256 &Value)
	{
		Register = _mm256_or_si256(Register, Value.Register);
	}

	UInt256 operator | (const UInt256 &Value)
	{
		return UInt256(_mm256_or_si256(Register, Value.Register));
	}

	void operator &= (const UInt256 &Value)
	{
		Register = _mm256_and_si256(Register, Value.Register);
	}

	UInt256 operator & (const UInt256 &Value)
	{
		return UInt256(_mm256_and_si256(Register, Value.Register));
	}

	void operator <<= (const int Shift)
	{
		Register = _mm256_slli_epi32(Register, Shift);
	}

	UInt256 operator << (const int Shift) const
	{
		return UInt256(_mm256_slli_epi32(Register, static_cast<int>(Shift)));
	}

	void operator >>= (const int Shift)
	{
		Register = _mm256_srli_epi32(Register, Shift);
	}

	UInt256 operator >> (const int Shift) const
	{
		return UInt256(_mm256_srli_epi32(Register, static_cast<int>(Shift)));
	}

	UInt256 operator ~ () const
	{
		return UInt256(_mm256_xor_si256(Register, _mm256_set1_epi32(0xFFFFFFFF)));
	}
};

NAMESPACE_COMMONEND
#endif