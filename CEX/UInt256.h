#ifndef _CEXENGINE_UINT256_H
#define _CEXENGINE_UINT256_H

#include "Common.h"
#include "Intrinsics.h"

NAMESPACE_COMMON

/// <summary>
/// An AVX 256 intrinsics wrapper
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
	/// Initialize with 8 * 32bit unsigned integers
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
	/// Load an array into a register in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void LoadBE(const std::vector<T> &Input, size_t Offset)
	{
		Swap().LoadLE(Input, Offset);
	}

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void LoadLE(const std::vector<T> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Transposes and stores 32 * 32bit integers in little endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X0">Operand 2</param>
	/// <param name="X1">Operand 3</param>
	static inline void StoreLE32(std::vector<byte> &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		memcpy(&Output[Offset], &X0.Register.m256i_u32[0], 4);
		memcpy(&Output[Offset + 16], &X0.Register.m256i_u32[1], 4);
		memcpy(&Output[Offset + 32], &X0.Register.m256i_u32[2], 4);
		memcpy(&Output[Offset + 48], &X0.Register.m256i_u32[3], 4);
		memcpy(&Output[Offset + 64], &X0.Register.m256i_u32[4], 4);
		memcpy(&Output[Offset + 80], &X0.Register.m256i_u32[5], 4);
		memcpy(&Output[Offset + 96], &X0.Register.m256i_u32[6], 4);
		memcpy(&Output[Offset + 112], &X0.Register.m256i_u32[7], 4);

		memcpy(&Output[Offset + 4], &X1.Register.m256i_u32[0], 4);
		memcpy(&Output[Offset + 20], &X1.Register.m256i_u32[1], 4);
		memcpy(&Output[Offset + 36], &X1.Register.m256i_u32[2], 4);
		memcpy(&Output[Offset + 52], &X1.Register.m256i_u32[3], 4);
		memcpy(&Output[Offset + 68], &X1.Register.m256i_u32[4], 4);
		memcpy(&Output[Offset + 84], &X1.Register.m256i_u32[5], 4);
		memcpy(&Output[Offset + 100], &X1.Register.m256i_u32[6], 4);
		memcpy(&Output[Offset + 116], &X1.Register.m256i_u32[7], 4);

		memcpy(&Output[Offset + 8], &X2.Register.m256i_u32[0], 4);
		memcpy(&Output[Offset + 24], &X2.Register.m256i_u32[1], 4);
		memcpy(&Output[Offset + 40], &X2.Register.m256i_u32[2], 4);
		memcpy(&Output[Offset + 56], &X2.Register.m256i_u32[3], 4);
		memcpy(&Output[Offset + 72], &X2.Register.m256i_u32[4], 4);
		memcpy(&Output[Offset + 88], &X2.Register.m256i_u32[5], 4);
		memcpy(&Output[Offset + 104], &X2.Register.m256i_u32[6], 4);
		memcpy(&Output[Offset + 120], &X2.Register.m256i_u32[7], 4);

		memcpy(&Output[Offset + 12], &X3.Register.m256i_u32[0], 4);
		memcpy(&Output[Offset + 28], &X3.Register.m256i_u32[1], 4);
		memcpy(&Output[Offset + 44], &X3.Register.m256i_u32[2], 4);
		memcpy(&Output[Offset + 60], &X3.Register.m256i_u32[3], 4);
		memcpy(&Output[Offset + 76], &X3.Register.m256i_u32[4], 4);
		memcpy(&Output[Offset + 92], &X3.Register.m256i_u32[5], 4);
		memcpy(&Output[Offset + 108], &X3.Register.m256i_u32[6], 4);
		memcpy(&Output[Offset + 124], &X3.Register.m256i_u32[7], 4);
	}

	/// <summary>
	/// Transposes and copies 128 * 32bit integers to an output array
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X0">Operand 2</param>
	/// <param name="X1">Operand 3</param>
	/// <param name="X0">Operand 4</param>
	/// <param name="X1">Operand 5</param>
	/// <param name="X0">Operand 6</param>
	/// <param name="X1">Operand 7</param>
	/// <param name="X0">Operand 8</param>
	/// <param name="X1">Operand 9</param>
	/// <param name="X0">Operand 10</param>
	/// <param name="X1">Operand 11</param>
	/// <param name="X0">Operand 12</param>
	/// <param name="X1">Operand 13</param>
	/// <param name="X0">Operand 14</param>
	/// <param name="X1">Operand 15</param>
	static inline void StoreLE512(std::vector<byte> &Output, size_t Offset,
		UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3,
		UInt256 &X4, UInt256 &X5, UInt256 &X6, UInt256 &X7,
		UInt256 &X8, UInt256 &X9, UInt256 &X10, UInt256 &X11,
		UInt256 &X12, UInt256 &X13, UInt256 &X14, UInt256 &X15)
	{
		__m256i W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
		__m256i Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, Y15;

		_mm256_merge_epi32(X0.Register, X1.Register, W0, W1);
		_mm256_merge_epi32(X2.Register, X3.Register, W2, W3);
		_mm256_merge_epi32(X4.Register, X5.Register, W4, W5);
		_mm256_merge_epi32(X6.Register, X7.Register, W6, W7);
		_mm256_merge_epi32(X8.Register, X9.Register, W8, W9);
		_mm256_merge_epi32(X10.Register, X11.Register, W10, W11);
		_mm256_merge_epi32(X12.Register, X13.Register, W12, W13);
		_mm256_merge_epi32(X14.Register, X15.Register, W14, W15);

		_mm256_merge_epi64(W0, W2, Y0, Y1);
		_mm256_merge_epi64(W4, W6, Y2, Y3);
		_mm256_merge_epi64(W8, W10, Y4, Y5);
		_mm256_merge_epi64(W12, W14, Y6, Y7);
		_mm256_merge_epi64(W1, W3, Y8, Y9);
		_mm256_merge_epi64(W5, W7, Y10, Y11);
		_mm256_merge_epi64(W9, W11, Y12, Y13);
		_mm256_merge_epi64(W13, W15, Y14, Y15);

		_mm256_merge_si128(Y0, Y2, X0.Register, X1.Register);
		_mm256_merge_si128(Y1, Y3, X2.Register, X3.Register);
		_mm256_merge_si128(Y8, Y10, X4.Register, X5.Register);
		_mm256_merge_si128(Y9, Y11, X6.Register, X7.Register);
		_mm256_merge_si128(Y4, Y6, X8.Register, X9.Register);
		_mm256_merge_si128(Y5, Y7, X10.Register, X11.Register);
		_mm256_merge_si128(Y12, Y14, X12.Register, X13.Register);
		_mm256_merge_si128(Y13, Y15, X14.Register, X15.Register);


		memcpy(&Output[Offset], &X0, 32);
		memcpy(&Output[Offset + 32], &X8, 32);
		memcpy(&Output[Offset + 64], &X1, 32);
		memcpy(&Output[Offset + 96], &X9, 32);
		memcpy(&Output[Offset + 128], &X2, 32);
		memcpy(&Output[Offset + 160], &X10, 32);
		memcpy(&Output[Offset + 192], &X3, 32);
		memcpy(&Output[Offset + 224], &X11, 32);
		memcpy(&Output[Offset + 256], &X4, 32);
		memcpy(&Output[Offset + 288], &X12, 32);
		memcpy(&Output[Offset + 320], &X5, 32);
		memcpy(&Output[Offset + 352], &X13, 32);
		memcpy(&Output[Offset + 384], &X6, 32);
		memcpy(&Output[Offset + 416], &X14, 32);
		memcpy(&Output[Offset + 448], &X7, 32);
		memcpy(&Output[Offset + 480], &X15, 32);
	}

	/// <summary>
	/// Store register in an integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreLE(std::vector<T> &Output, size_t Offset) const
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), Register);
	}

	/// <summary>
	/// Store register in an integer array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreBE(std::vector<T> &Output, size_t Offset) const
	{
		Swap().StoreLE(Output, Offset);
	}

	/* Methods */

	/// <summary>
	/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in Value
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
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void Transpose(UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3)
	{
		__m256i T0 = _mm256_unpacklo_epi32(X0.Register, X1.Register);
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

private:
		static inline void _mm256_merge_epi32(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
		{
			__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
			__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
			Xl = _mm256_unpacklo_epi32(va, vb);
			Xh = _mm256_unpackhi_epi32(va, vb);
		}

		static inline void _mm256_merge_epi64(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
		{
			__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
			__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
			Xl = _mm256_unpacklo_epi64(va, vb);
			Xh = _mm256_unpackhi_epi64(va, vb);
		}

		static inline void _mm256_merge_si128(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
		{
			Xl = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 2, 0, 0));
			Xh = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 3, 0, 1));
		}

};

NAMESPACE_COMMONEND
#endif




/*inline void transpose8_ps(__m256 &row0, __m256 &row1, __m256 &row2, __m256 &row3, __m256 &row4, __m256 &row5, __m256 &row6, __m256 &row7)
{
	__m256 __t0, __t1, __t2, __t3, __t4, __t5, __t6, __t7;
	__m256 __tt0, __tt1, __tt2, __tt3, __tt4, __tt5, __tt6, __tt7;
	__t0 = _mm256_unpacklo_ps(row0, row1);
	__t1 = _mm256_unpackhi_ps(row0, row1);
	__t2 = _mm256_unpacklo_ps(row2, row3);
	__t3 = _mm256_unpackhi_ps(row2, row3);
	__t4 = _mm256_unpacklo_ps(row4, row5);
	__t5 = _mm256_unpackhi_ps(row4, row5);
	__t6 = _mm256_unpacklo_ps(row6, row7);
	__t7 = _mm256_unpackhi_ps(row6, row7);
	__tt0 = _mm256_shuffle_ps(__t0, __t2, _MM_SHUFFLE(1, 0, 1, 0));
	__tt1 = _mm256_shuffle_ps(__t0, __t2, _MM_SHUFFLE(3, 2, 3, 2));
	__tt2 = _mm256_shuffle_ps(__t1, __t3, _MM_SHUFFLE(1, 0, 1, 0));
	__tt3 = _mm256_shuffle_ps(__t1, __t3, _MM_SHUFFLE(3, 2, 3, 2));
	__tt4 = _mm256_shuffle_ps(__t4, __t6, _MM_SHUFFLE(1, 0, 1, 0));
	__tt5 = _mm256_shuffle_ps(__t4, __t6, _MM_SHUFFLE(3, 2, 3, 2));
	__tt6 = _mm256_shuffle_ps(__t5, __t7, _MM_SHUFFLE(1, 0, 1, 0));
	__tt7 = _mm256_shuffle_ps(__t5, __t7, _MM_SHUFFLE(3, 2, 3, 2));
}

static inline void _mm256_merge_epi32(const __m256i v0, const __m256i v1, __m256i *vl, __m256i *vh)
{
	__m256i va = _mm256_permute4x64_epi64(v0, _MM_SHUFFLE(3, 1, 2, 0));
	__m256i vb = _mm256_permute4x64_epi64(v1, _MM_SHUFFLE(3, 1, 2, 0));
	*vl = _mm256_unpacklo_epi32(va, vb);
	*vh = _mm256_unpackhi_epi32(va, vb);
}

static inline void _mm256_merge_epi64(const __m256i v0, const __m256i v1, __m256i *vl, __m256i *vh)
{
	__m256i va = _mm256_permute4x64_epi64(v0, _MM_SHUFFLE(3, 1, 2, 0));
	__m256i vb = _mm256_permute4x64_epi64(v1, _MM_SHUFFLE(3, 1, 2, 0));
	*vl = _mm256_unpacklo_epi64(va, vb);
	*vh = _mm256_unpackhi_epi64(va, vb);
}

static inline void _mm256_merge_si128(const __m256i v0, const __m256i v1, __m256i *vl, __m256i *vh)
{
	*vl = _mm256_permute2x128_si256(v0, v1, _MM_SHUFFLE(0, 2, 0, 0));
	*vh = _mm256_permute2x128_si256(v0, v1, _MM_SHUFFLE(0, 3, 0, 1));
}

static void Transpose_8_8(__m256i *v0, __m256i *v1, __m256i *v2, __m256i *v3, __m256i *v4, __m256i *v5, __m256i *v6, __m256i *v7,
	__m256i *v8, __m256i *v9, __m256i *v10, __m256i *v11, __m256i *v12, __m256i *v13, __m256i *v14, __m256i *v15)
{
	__m256i w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
	__m256i x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

	_mm256_merge_epi32(*v0, *v1, &w0, &w1);
	_mm256_merge_epi32(*v2, *v3, &w2, &w3);
	_mm256_merge_epi32(*v4, *v5, &w4, &w5);
	_mm256_merge_epi32(*v6, *v7, &w6, &w7);

	_mm256_merge_epi32(*v8, *v9, &w8, &w9);
	_mm256_merge_epi32(*v10, *v11, &w10, &w11);
	_mm256_merge_epi32(*v12, *v13, &w12, &w13);
	_mm256_merge_epi32(*v14, *v15, &w14, &w15);


	_mm256_merge_epi64(w0, w2, &x0, &x1);
	_mm256_merge_epi64(w1, w3, &x2, &x3);
	_mm256_merge_epi64(w4, w6, &x4, &x5);
	_mm256_merge_epi64(w5, w7, &x6, &x7);

	_mm256_merge_epi64(w8, w10, &x8, &x9);
	_mm256_merge_epi64(w9, w11, &x10, &x11);
	_mm256_merge_epi64(w12, w14, &x12, &x13);
	_mm256_merge_epi64(w13, w14, &x14, &x15);


	_mm256_merge_si128(x0, x4, v0, v1);
	_mm256_merge_si128(x1, x5, v2, v3);
	_mm256_merge_si128(x2, x6, v4, v5);
	_mm256_merge_si128(x3, x7, v6, v7);

	_mm256_merge_si128(x8, x12, v8, v9);
	_mm256_merge_si128(x9, x13, v10, v11);
	_mm256_merge_si128(x10, x14, v12, v13);
	_mm256_merge_si128(x11, x15, v14, v15);
}
*/