#ifndef _CEXENGINE_UINT128_H
#define _CEXENGINE_UINT128_H

#include "Common.h"
//#include <emmintrin.h>
#include "Intrinsics.h"

NAMESPACE_COMMON

/// <summary>
/// An SSE 128 intrinsics wrapper
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
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	UInt128(uint X)
	{
		Register = _mm_set1_epi32(X);
	}

	/* Load and Store */

	/// <summary>
	/// Store register in an integer array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreBE(std::vector<T> &Output, size_t Offset) const
	{
		Swap().StoreLE(Output, Offset);
	}

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void LoadLE(const std::vector<T> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Transposes and loads 4 * UInt128 at 32bit boundaries
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X0">Operand 2</param>
	/// <param name="X1">Operand 3</param>
	static inline void LoadLE16(const std::vector<byte> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		memcpy(&X0.Register.m128i_u32[0], &Input[Offset], 4);
		memcpy(&X0.Register.m128i_u32[1], &Input[Offset + 16], 4);
		memcpy(&X0.Register.m128i_u32[2], &Input[Offset + 32], 4);
		memcpy(&X0.Register.m128i_u32[3], &Input[Offset + 48], 4);

		memcpy(&X1.Register.m128i_u32[0], &Input[Offset + 4], 4);
		memcpy(&X1.Register.m128i_u32[1], &Input[Offset + 20], 4);
		memcpy(&X1.Register.m128i_u32[2], &Input[Offset + 36], 4);
		memcpy(&X1.Register.m128i_u32[3], &Input[Offset + 52], 4);

		memcpy(&X2.Register.m128i_u32[0], &Input[Offset + 8], 4);
		memcpy(&X2.Register.m128i_u32[1], &Input[Offset + 24], 4);
		memcpy(&X2.Register.m128i_u32[2], &Input[Offset + 40], 4);
		memcpy(&X2.Register.m128i_u32[3], &Input[Offset + 56], 4);

		memcpy(&X3.Register.m128i_u32[0], &Input[Offset + 12], 4);
		memcpy(&X3.Register.m128i_u32[1], &Input[Offset + 28], 4);
		memcpy(&X3.Register.m128i_u32[2], &Input[Offset + 44], 4);
		memcpy(&X3.Register.m128i_u32[3], &Input[Offset + 60], 4);
	}

	/// <summary>
	/// Load an array into a register in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
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
	template <typename T>
	void StoreLE(std::vector<T> &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), Register);
	}

	/// <summary>
	/// Transposes and stores 16 * 32bit integers in little endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X0">Operand 2</param>
	/// <param name="X1">Operand 3</param>
	static inline void StoreLE16(std::vector<byte> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		memcpy(&Output[Offset], &X0.Register.m128i_u32[0], 4);
		memcpy(&Output[Offset + 16], &X0.Register.m128i_u32[1], 4);
		memcpy(&Output[Offset + 32], &X0.Register.m128i_u32[2], 4);
		memcpy(&Output[Offset + 48], &X0.Register.m128i_u32[3], 4);

		memcpy(&Output[Offset + 4], &X1.Register.m128i_u32[0], 4);
		memcpy(&Output[Offset + 20], &X1.Register.m128i_u32[1], 4);
		memcpy(&Output[Offset + 36], &X1.Register.m128i_u32[2], 4);
		memcpy(&Output[Offset + 52], &X1.Register.m128i_u32[3], 4);

		memcpy(&Output[Offset + 8], &X2.Register.m128i_u32[0], 4);
		memcpy(&Output[Offset + 24], &X2.Register.m128i_u32[1], 4);
		memcpy(&Output[Offset + 40], &X2.Register.m128i_u32[2], 4);
		memcpy(&Output[Offset + 56], &X2.Register.m128i_u32[3], 4);

		memcpy(&Output[Offset + 12], &X3.Register.m128i_u32[0], 4);
		memcpy(&Output[Offset + 28], &X3.Register.m128i_u32[1], 4);
		memcpy(&Output[Offset + 44], &X3.Register.m128i_u32[2], 4);
		memcpy(&Output[Offset + 60], &X3.Register.m128i_u32[3], 4);
	}

	/// <summary>
	/// Transposes and copies 64 * 32bit integers to an output array
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
	static inline void StoreLE256(std::vector<byte> &Output, size_t Offset,
		UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3,
		UInt128 &X4, UInt128 &X5, UInt128 &X6, UInt128 &X7,
		UInt128 &X8, UInt128 &X9, UInt128 &X10, UInt128 &X11,
		UInt128 &X12, UInt128 &X13, UInt128 &X14, UInt128 &X15)
	{
		__m128i T0 = _mm_unpacklo_epi32(X0.Register, X1.Register);
		__m128i T1 = _mm_unpacklo_epi32(X2.Register, X3.Register);
		__m128i T2 = _mm_unpacklo_epi32(X4.Register, X5.Register);
		__m128i T3 = _mm_unpacklo_epi32(X6.Register, X7.Register);
		__m128i T4 = _mm_unpacklo_epi32(X8.Register, X9.Register);
		__m128i T5 = _mm_unpacklo_epi32(X10.Register, X11.Register);
		__m128i T6 = _mm_unpacklo_epi32(X12.Register, X13.Register);
		__m128i T7 = _mm_unpacklo_epi32(X14.Register, X15.Register);

		__m128i T8 = _mm_unpackhi_epi32(X0.Register, X1.Register);
		__m128i T9 = _mm_unpackhi_epi32(X2.Register, X3.Register);
		__m128i T10 = _mm_unpackhi_epi32(X4.Register, X5.Register);
		__m128i T11 = _mm_unpackhi_epi32(X6.Register, X7.Register);
		__m128i T12 = _mm_unpackhi_epi32(X8.Register, X9.Register);
		__m128i T13 = _mm_unpackhi_epi32(X10.Register, X11.Register);
		__m128i T14 = _mm_unpackhi_epi32(X12.Register, X13.Register);
		__m128i T15 = _mm_unpackhi_epi32(X14.Register, X15.Register);

		X0.Register = _mm_unpacklo_epi64(T0, T1);
		X1.Register = _mm_unpacklo_epi64(T2, T3);
		X2.Register = _mm_unpacklo_epi64(T4, T5);
		X3.Register = _mm_unpacklo_epi64(T6, T7);

		X4.Register = _mm_unpackhi_epi64(T0, T1);
		X5.Register = _mm_unpackhi_epi64(T2, T3);
		X6.Register = _mm_unpackhi_epi64(T4, T5);
		X7.Register = _mm_unpackhi_epi64(T6, T7);

		X8.Register = _mm_unpacklo_epi64(T8, T9);
		X9.Register = _mm_unpacklo_epi64(T10, T11);
		X10.Register = _mm_unpacklo_epi64(T12, T13);
		X11.Register = _mm_unpacklo_epi64(T14, T15);

		X12.Register = _mm_unpackhi_epi64(T8, T9);
		X13.Register = _mm_unpackhi_epi64(T10, T11);
		X14.Register = _mm_unpackhi_epi64(T12, T13);
		X15.Register = _mm_unpackhi_epi64(T14, T15);

		memcpy(&Output[Offset], &X0, 16);
		memcpy(&Output[Offset + 16], &X1, 16);
		memcpy(&Output[Offset + 32], &X2, 16);
		memcpy(&Output[Offset + 48], &X3, 16);
		memcpy(&Output[Offset + 64], &X4, 16);
		memcpy(&Output[Offset + 80], &X5, 16);
		memcpy(&Output[Offset + 96], &X6, 16);
		memcpy(&Output[Offset + 112], &X7, 16);
		memcpy(&Output[Offset + 128], &X8, 16);
		memcpy(&Output[Offset + 144], &X9, 16);
		memcpy(&Output[Offset + 160], &X10, 16);
		memcpy(&Output[Offset + 176], &X11, 16);
		memcpy(&Output[Offset + 192], &X12, 16);
		memcpy(&Output[Offset + 208], &X13, 16);
		memcpy(&Output[Offset + 224], &X14, 16);
		memcpy(&Output[Offset + 240], &X15, 16);
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
	/// Interleaves 32bit integers at the specified distance
	/// </summary>
	///
	/// <param name="Input">The UInt128 to interleave</param>
	/// <param name="Distance">The distance offset between sequential registers</param>
	static inline void InterLeave32(std::vector<UInt128> &Input, size_t Distance)
	{
		std::vector<uint> X(Input.size() * 4);
		memcpy(&X[0], &Input[0], Input.size() * 16);

		for (size_t i = 0; i < Input.size(); ++i)
		{
			memcpy(&Input[i].Register.m128i_u32[0], &X[i], 4);
			memcpy(&Input[i].Register.m128i_u32[1], &X[Distance + i], 4);
			memcpy(&Input[i].Register.m128i_u32[2], &X[Distance * 2 + i], 4);
			memcpy(&Input[i].Register.m128i_u32[3], &X[Distance * 3 + i], 4);
		}
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
	/// Shuffles the registers in 4 * UInt128 structures; to create a sequential chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void Transpose(UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{


		__m128i T0 = _mm_unpacklo_epi32(X0.Register, X1.Register); // get [0 + 1] uints put in t0
		__m128i T1 = _mm_unpacklo_epi32(X2.Register, X3.Register); // get [0 + 1] uints put in 0 and 1 of t1
		__m128i T2 = _mm_unpackhi_epi32(X0.Register, X1.Register); // get [2 + 3] uints put in 2 and 3 of t2
		__m128i T3 = _mm_unpackhi_epi32(X2.Register, X3.Register); // get [2 + 3] uints put in 2 and 3 of t3
		X0.Register = _mm_unpacklo_epi64(T0, T1); // copy first 8 bytes of t0 and t1 to x0
		X1.Register = _mm_unpackhi_epi64(T0, T1); // copy last 8 bytes of t0 and t1 to x1
		X2.Register = _mm_unpacklo_epi64(T2, T3); // copy first 8 bytes of t2 and t3 to x2
		X3.Register = _mm_unpackhi_epi64(T2, T3); // copy last 8 bytes of t2 and t3 to x3
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