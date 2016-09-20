#ifndef _CEXENGINE_UINT128_H
#define _CEXENGINE_UINT128_H

#include "Common.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

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

	//~~~ Constructor~~~//

	UInt128() {}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<byte> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 16bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 8 * 16bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<ushort> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	UInt128(const std::vector<uint> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array in Little Endian format
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
	/// <param name="X0">uint 0</param>
	/// <param name="X1">uint 1</param>
	/// <param name="X2">uint 2</param>
	/// <param name="X3">uint 3</param>
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

	//~~~ Load and Store~~~//

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
	/// Load with 4 * 32bit unsigned integers in Big Endian format
	/// </summary>
	///
	/// <param name="X0">uint 0</param>
	/// <param name="X1">uint 1</param>
	/// <param name="X2">uint 2</param>
	/// <param name="X3">uint 3</param>
	void LoadBE(uint X0, uint X1, uint X2, uint X3)
	{
		Swap().LoadLE(X0, X1, X2, X3);
	}

	/// <summary>
	/// Transposes and loads 4 * UInt128 at 32bit boundaries in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void LoadBE16(const std::vector<byte> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		X0.LoadBE(Input, Offset);
		X1.LoadBE(Input, Offset + 16);
		X2.LoadBE(Input, Offset + 32);
		X3.LoadBE(Input, Offset + 48);
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Loads 64 * 32bit integers to a UInt128 array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt128 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static inline void LoadBE256(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt128> &Output, size_t OutOffset)
	{
		Output[OutOffset].LoadBE(Input, InOffset);
		Output[OutOffset + 1].LoadBE(Input, InOffset + 16);
		Output[OutOffset + 2].LoadBE(Input, InOffset + 32);
		Output[OutOffset + 3].LoadBE(Input, InOffset + 48);
		Output[OutOffset + 4].LoadBE(Input, InOffset + 64);
		Output[OutOffset + 5].LoadBE(Input, InOffset + 80);
		Output[OutOffset + 6].LoadBE(Input, InOffset + 96);
		Output[OutOffset + 7].LoadBE(Input, InOffset + 112);
		Output[OutOffset + 8].LoadBE(Input, InOffset + 128);
		Output[OutOffset + 9].LoadBE(Input, InOffset + 144);
		Output[OutOffset + 10].LoadBE(Input, InOffset + 160);
		Output[OutOffset + 11].LoadBE(Input, InOffset + 176);
		Output[OutOffset + 12].LoadBE(Input, InOffset + 192);
		Output[OutOffset + 13].LoadBE(Input, InOffset + 208);
		Output[OutOffset + 14].LoadBE(Input, InOffset + 224);
		Output[OutOffset + 15].LoadBE(Input, InOffset + 240);
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
	/// Load with 4 * 32bit unsigned integers in Little Endian format
	/// </summary>
	///
	/// <param name="X0">uint 0</param>
	/// <param name="X1">uint 1</param>
	/// <param name="X2">uint 2</param>
	/// <param name="X3">uint 3</param>
	void LoadLE(uint X0, uint X1, uint X2, uint X3)
	{
		Register = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Transposes and loads 4 * UInt128 at 32bit boundaries in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void LoadLE16(const std::vector<byte> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		X0.LoadLE(Input, Offset);
		X1.LoadLE(Input, Offset + 16);
		X2.LoadLE(Input, Offset + 32);
		X3.LoadLE(Input, Offset + 48);
		Transpose(X0, X1, X2, X3);
	}

	/// <summary>
	/// Loads 64 * 32bit integers to a UInt128 array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt128 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static inline void LoadLE256(std::vector<byte> &Input, size_t InOffset, std::vector<UInt128> &Output, size_t OutOffset)
	{
		Output[OutOffset].LoadLE(Input, InOffset);
		Output[OutOffset + 1].LoadLE(Input, InOffset + 16);
		Output[OutOffset + 2].LoadLE(Input, InOffset + 32);
		Output[OutOffset + 3].LoadLE(Input, InOffset + 48);
		Output[OutOffset + 4].LoadLE(Input, InOffset + 64);
		Output[OutOffset + 5].LoadLE(Input, InOffset + 80);
		Output[OutOffset + 6].LoadLE(Input, InOffset + 96);
		Output[OutOffset + 7].LoadLE(Input, InOffset + 112);
		Output[OutOffset + 8].LoadLE(Input, InOffset + 128);
		Output[OutOffset + 9].LoadLE(Input, InOffset + 144);
		Output[OutOffset + 10].LoadLE(Input, InOffset + 160);
		Output[OutOffset + 11].LoadLE(Input, InOffset + 176);
		Output[OutOffset + 12].LoadLE(Input, InOffset + 192);
		Output[OutOffset + 13].LoadLE(Input, InOffset + 208);
		Output[OutOffset + 14].LoadLE(Input, InOffset + 224);
		Output[OutOffset + 15].LoadLE(Input, InOffset + 240);
	}

	/// <summary>
	/// Store register in an integer array in Big Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreBE(std::vector<T> &Output, size_t Offset) const
	{
		Swap().StoreLE(Output, Offset);
	}

	/// <summary>
	/// Transposes and stores 16 * 32bit integers in Big Endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void StoreBE16(std::vector<byte> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.StoreBE(Output, Offset);
		X1.StoreBE(Output, Offset + 16);
		X2.StoreBE(Output, Offset + 32);
		X3.StoreBE(Output, Offset + 48);
	}

	/// <summary>
	/// Transposes and loads 64 * 32bit integers to an output array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt128 array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static inline void StoreBE256(std::vector<UInt128> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		__m128i T0 = _mm_unpacklo_epi32(Input[InOffset].Register, Input[InOffset + 1].Register);
		__m128i T1 = _mm_unpacklo_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register);
		__m128i T2 = _mm_unpacklo_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register);
		__m128i T3 = _mm_unpacklo_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register);
		__m128i T4 = _mm_unpacklo_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register);
		__m128i T5 = _mm_unpacklo_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register);
		__m128i T6 = _mm_unpacklo_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register);
		__m128i T7 = _mm_unpacklo_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register);
		__m128i T8 = _mm_unpackhi_epi32(Input[InOffset].Register, Input[InOffset + 1].Register);
		__m128i T9 = _mm_unpackhi_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register);
		__m128i T10 = _mm_unpackhi_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register);
		__m128i T11 = _mm_unpackhi_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register);
		__m128i T12 = _mm_unpackhi_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register);
		__m128i T13 = _mm_unpackhi_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register);
		__m128i T14 = _mm_unpackhi_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register);
		__m128i T15 = _mm_unpackhi_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register);

		Input[InOffset].Register = _mm_unpacklo_epi64(T0, T1);
		Input[InOffset + 1].Register = _mm_unpacklo_epi64(T2, T3);
		Input[InOffset + 2].Register = _mm_unpacklo_epi64(T4, T5);
		Input[InOffset + 3].Register = _mm_unpacklo_epi64(T6, T7);
		Input[InOffset + 4].Register = _mm_unpackhi_epi64(T0, T1);
		Input[InOffset + 5].Register = _mm_unpackhi_epi64(T2, T3);
		Input[InOffset + 6].Register = _mm_unpackhi_epi64(T4, T5);
		Input[InOffset + 7].Register = _mm_unpackhi_epi64(T6, T7);
		Input[InOffset + 8].Register = _mm_unpacklo_epi64(T8, T9);
		Input[InOffset + 9].Register = _mm_unpacklo_epi64(T10, T11);
		Input[InOffset + 10].Register = _mm_unpacklo_epi64(T12, T13);
		Input[InOffset + 11].Register = _mm_unpacklo_epi64(T14, T15);
		Input[InOffset + 12].Register = _mm_unpackhi_epi64(T8, T9);
		Input[InOffset + 13].Register = _mm_unpackhi_epi64(T10, T11);
		Input[InOffset + 14].Register = _mm_unpackhi_epi64(T12, T13);
		Input[InOffset + 15].Register = _mm_unpackhi_epi64(T14, T15);

		Input[InOffset].StoreBE(Output, OutOffset);
		Input[InOffset + 1].StoreBE(Output, OutOffset + 16);
		Input[InOffset + 2].StoreBE(Output, OutOffset + 32);
		Input[InOffset + 3].StoreBE(Output, OutOffset + 48);
		Input[InOffset + 4].StoreBE(Output, OutOffset + 64);
		Input[InOffset + 5].StoreBE(Output, OutOffset + 80);
		Input[InOffset + 6].StoreBE(Output, OutOffset + 96);
		Input[InOffset + 7].StoreBE(Output, OutOffset + 112);
		Input[InOffset + 8].StoreBE(Output, OutOffset + 128);
		Input[InOffset + 9].StoreBE(Output, OutOffset + 144);
		Input[InOffset + 10].StoreBE(Output, OutOffset + 160);
		Input[InOffset + 11].StoreBE(Output, OutOffset + 176);
		Input[InOffset + 12].StoreBE(Output, OutOffset + 192);
		Input[InOffset + 13].StoreBE(Output, OutOffset + 208);
		Input[InOffset + 14].StoreBE(Output, OutOffset + 224);
		Input[InOffset + 15].StoreBE(Output, OutOffset + 240);
	}

	/// <summary>
	/// Store register in an integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreLE(std::vector<T> &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), Register);
	}

	/// <summary>
	/// Transposes and stores 16 * 32bit integers in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static inline void StoreLE16(std::vector<byte> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3)
	{
		Transpose(X0, X1, X2, X3);
		X0.StoreLE(Output, Offset);
		X1.StoreLE(Output, Offset + 16);
		X2.StoreLE(Output, Offset + 32);
		X3.StoreLE(Output, Offset + 48);
	}

	/// <summary>
	/// Transposes and copies 64 * 32bit integers to an output array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt128 array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	static inline void StoreLE256(std::vector<UInt128> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		__m128i T0 = _mm_unpacklo_epi32(Input[InOffset].Register, Input[InOffset + 1].Register);
		__m128i T1 = _mm_unpacklo_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register);
		__m128i T2 = _mm_unpacklo_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register);
		__m128i T3 = _mm_unpacklo_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register);
		__m128i T4 = _mm_unpacklo_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register);
		__m128i T5 = _mm_unpacklo_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register);
		__m128i T6 = _mm_unpacklo_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register);
		__m128i T7 = _mm_unpacklo_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register);
		__m128i T8 = _mm_unpackhi_epi32(Input[InOffset].Register, Input[InOffset + 1].Register);
		__m128i T9 = _mm_unpackhi_epi32(Input[InOffset + 2].Register, Input[InOffset + 3].Register);
		__m128i T10 = _mm_unpackhi_epi32(Input[InOffset + 4].Register, Input[InOffset + 5].Register);
		__m128i T11 = _mm_unpackhi_epi32(Input[InOffset + 6].Register, Input[InOffset + 7].Register);
		__m128i T12 = _mm_unpackhi_epi32(Input[InOffset + 8].Register, Input[InOffset + 9].Register);
		__m128i T13 = _mm_unpackhi_epi32(Input[InOffset + 10].Register, Input[InOffset + 11].Register);
		__m128i T14 = _mm_unpackhi_epi32(Input[InOffset + 12].Register, Input[InOffset + 13].Register);
		__m128i T15 = _mm_unpackhi_epi32(Input[InOffset + 14].Register, Input[InOffset + 15].Register);

		Input[InOffset].Register = _mm_unpacklo_epi64(T0, T1);
		Input[InOffset + 1].Register = _mm_unpacklo_epi64(T2, T3);
		Input[InOffset + 2].Register = _mm_unpacklo_epi64(T4, T5);
		Input[InOffset + 3].Register = _mm_unpacklo_epi64(T6, T7);
		Input[InOffset + 4].Register = _mm_unpackhi_epi64(T0, T1);
		Input[InOffset + 5].Register = _mm_unpackhi_epi64(T2, T3);
		Input[InOffset + 6].Register = _mm_unpackhi_epi64(T4, T5);
		Input[InOffset + 7].Register = _mm_unpackhi_epi64(T6, T7);
		Input[InOffset + 8].Register = _mm_unpacklo_epi64(T8, T9);
		Input[InOffset + 9].Register = _mm_unpacklo_epi64(T10, T11);
		Input[InOffset + 10].Register = _mm_unpacklo_epi64(T12, T13);
		Input[InOffset + 11].Register = _mm_unpacklo_epi64(T14, T15);
		Input[InOffset + 12].Register = _mm_unpackhi_epi64(T8, T9);
		Input[InOffset + 13].Register = _mm_unpackhi_epi64(T10, T11);
		Input[InOffset + 14].Register = _mm_unpackhi_epi64(T12, T13);
		Input[InOffset + 15].Register = _mm_unpackhi_epi64(T14, T15);

		Input[InOffset].StoreLE(Output, OutOffset);
		Input[InOffset + 1].StoreLE(Output, OutOffset + 16);
		Input[InOffset + 2].StoreLE(Output, OutOffset + 32);
		Input[InOffset + 3].StoreLE(Output, OutOffset + 48);
		Input[InOffset + 4].StoreLE(Output, OutOffset + 64);
		Input[InOffset + 5].StoreLE(Output, OutOffset + 80);
		Input[InOffset + 6].StoreLE(Output, OutOffset + 96);
		Input[InOffset + 7].StoreLE(Output, OutOffset + 112);
		Input[InOffset + 8].StoreLE(Output, OutOffset + 128);
		Input[InOffset + 9].StoreLE(Output, OutOffset + 144);
		Input[InOffset + 10].StoreLE(Output, OutOffset + 160);
		Input[InOffset + 11].StoreLE(Output, OutOffset + 176);
		Input[InOffset + 12].StoreLE(Output, OutOffset + 192);
		Input[InOffset + 13].StoreLE(Output, OutOffset + 208);
		Input[InOffset + 14].StoreLE(Output, OutOffset + 224);
		Input[InOffset + 15].StoreLE(Output, OutOffset + 240);
	}

	//~~~ Methods~~~//

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in Value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	UInt128 AndNot(const UInt128 &Value)
	{
		return UInt128(_mm_andnot_si128(Register, Value.Register));
	}

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	static inline const size_t Length()
	{
		return 16;
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
	/// 
	/// <returns>The rotated UInt128</returns>
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
	/// 
	/// <returns>The rotated UInt128</returns>
	static inline UInt128 Rotr32(const UInt128 &Value, const int Shift)
	{
		return Rotl32(Value, 32 - Shift);
	}

	/// <summary>
	/// Load a Uint128 in Big Endian format using 32bit uints staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static inline UInt128 ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
	{
		return UInt128(
			(Input[Offset] << 24) | (Input[Offset + 1] << 16) | (Input[Offset + 2] << 8) | Input[Offset + 3],
			(Input[Offset + Shift] << 24) | (Input[Offset + 1 + Shift] << 16) | (Input[Offset + 2 + Shift] << 8) | Input[Offset + 3 + Shift],
			(Input[Offset + Shift * 2] << 24) | (Input[Offset + 1 + Shift * 2] << 16) | (Input[Offset + 2 + Shift * 2] << 8) | Input[Offset + 3 + Shift * 2],
			(Input[Offset + Shift * 3] << 24) | (Input[Offset + 1 + Shift * 3] << 16) | (Input[Offset + 2 + Shift * 3] << 8) | Input[Offset + 3 + Shift * 3]);
	}

	/// <summary>
	/// Load a Uint128 in Big Endian format using a 32bit uint array staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input uint32 array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static inline UInt128 ShuffleLoad32(const std::vector<uint> &Input, size_t Offset, size_t Shift)
	{
		return UInt128(Input[Offset], Input[Offset + Shift], Input[Offset + Shift * 2], Input[Offset + Shift * 3]);
	}

	/// <summary>
	/// Load a Uint128 in Little Endian format using uint staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static inline UInt128 ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
	{
		return UInt128(
			Input[Offset] | (Input[Offset + 1] << 8) | (Input[Offset + 2] << 16) | (Input[Offset + 3] << 24),
			Input[Offset + Shift] | (Input[Offset + 1 + Shift] << 8) | (Input[Offset + 2 + Shift] << 16) | (Input[Offset + 3 + Shift] << 24),
			Input[Offset + Shift * 2] | (Input[Offset + 1 + Shift * 2] << 8) | (Input[Offset + 2 + Shift * 2] << 16) | (Input[Offset + 3 + Shift * 2] << 24),
			Input[Offset + Shift * 3] | (Input[Offset + 1 + Shift * 3] << 8) | (Input[Offset + 2 + Shift * 3] << 16) | (Input[Offset + 3 + Shift * 3] << 24));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	UInt128 Swap() const
	{
		__m128i T = Register;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1)); // ?
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt128 to process</param>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	static inline UInt128 Swap(UInt128 &X)
	{
		__m128i T = X.Register;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return UInt128(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));
	}

	/// <summary>
	/// Copies the register uint8 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint8(std::vector<byte> &Output, size_t Offset)
	{
		memcpy(&Output[Offset], &Register.m128i_u8[0], 16);
	}

	/// <summary>
	/// Copies the register uint16 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint16(std::vector<ushort> &Output, size_t Offset)
	{
		memcpy(&Output[Offset], &Register.m128i_u16[0], 16);
	}

	/// <summary>
	/// Copies the register uint32 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint32(std::vector<uint> &Output, size_t Offset)
	{
		memcpy(&Output[Offset], &Register.m128i_u32[0], 16);
	}

	/// <summary>
	/// Copies the register uint64 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint64(std::vector<ulong> &Output, size_t Offset)
	{
		memcpy(&Output[Offset], &Register.m128i_u64[0], 16);
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
		__m128i T0 = _mm_unpacklo_epi32(X0.Register, X1.Register);
		__m128i T1 = _mm_unpacklo_epi32(X2.Register, X3.Register);
		__m128i T2 = _mm_unpackhi_epi32(X0.Register, X1.Register);
		__m128i T3 = _mm_unpackhi_epi32(X2.Register, X3.Register);
		X0.Register = _mm_unpacklo_epi64(T0, T1);
		X1.Register = _mm_unpackhi_epi64(T0, T1);
		X2.Register = _mm_unpacklo_epi64(T2, T3);
		X3.Register = _mm_unpackhi_epi64(T2, T3);
	}

	//~~~ Operators~~~//

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	void operator += (const UInt128 &Value)
	{
		Register = _mm_add_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	UInt128 operator + (const UInt128 &Value) const
	{
		return UInt128(_mm_add_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	void operator -= (const UInt128 &Value)
	{
		Register = _mm_sub_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	UInt128 operator - (const UInt128 &Value) const
	{
		return UInt128(_mm_sub_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="Value">The value to multiply</param>
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

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="Value">The value to multiply</param>
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

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	void operator /= (const UInt128 &Value)
	{
		// ToDo: finish this (rounded floating point ops)
		Register.m128i_u32[0] /= Value.Register.m128i_u32[0];
		Register.m128i_u32[1] /= Value.Register.m128i_u32[1];
		Register.m128i_u32[2] /= Value.Register.m128i_u32[2];
		Register.m128i_u32[3] /= Value.Register.m128i_u32[3];
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	UInt128 operator / (const UInt128 &Value) const
	{
		// ToDo: finish this
		return UInt128(
			Register.m128i_u32[0] / Value.Register.m128i_u32[0],
			Register.m128i_u32[1] / Value.Register.m128i_u32[1],
			Register.m128i_u32[2] / Value.Register.m128i_u32[2],
			Register.m128i_u32[3] / Value.Register.m128i_u32[3]);
	}

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	void operator %= (const UInt128 &Value)
	{
		// ToDo: finish this
		Register.m128i_u32[0] %= Value.Register.m128i_u32[0];
		Register.m128i_u32[1] %= Value.Register.m128i_u32[1];
		Register.m128i_u32[2] %= Value.Register.m128i_u32[2];
		Register.m128i_u32[3] %= Value.Register.m128i_u32[3];
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	UInt128 operator % (const UInt128 &Value) const
	{
		// ToDo: finish this
		return UInt128(
			Register.m128i_u32[0] % Value.Register.m128i_u32[0],
			Register.m128i_u32[1] % Value.Register.m128i_u32[1],
			Register.m128i_u32[2] % Value.Register.m128i_u32[2],
			Register.m128i_u32[3] % Value.Register.m128i_u32[3]);
	}

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="Value">The value to Xor</param>
	void operator ^= (const UInt128 &Value)
	{
		Register = _mm_xor_si128(Register, Value.Register);
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="Value">The value to Xor</param>
	UInt128 operator ^ (const UInt128 &Value) const
	{
		return UInt128(_mm_xor_si128(Register, Value.Register));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	void operator |= (const UInt128 &Value)
	{
		Register = _mm_or_si128(Register, Value.Register);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	UInt128 operator | (const UInt128 &Value)
	{
		return UInt128(_mm_or_si128(Register, Value.Register));
	}

	/// <summary>
	/// AND this integer
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	void operator &= (const UInt128 &Value)
	{
		Register = _mm_and_si128(Register, Value.Register);
	}

	/// <summary>
	/// AND two integers
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	UInt128 operator & (const UInt128 &Value)
	{
		return UInt128(_mm_and_si128(Register, Value.Register));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	void operator <<= (const int Shift)
	{
		Register = _mm_slli_epi32(Register, Shift);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	UInt128 operator << (const int Shift) const
	{
		return UInt128(_mm_slli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	void operator >>= (const int Shift)
	{
		Register = _mm_srli_epi32(Register, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	UInt128 operator >> (const int Shift) const
	{
		return UInt128(_mm_srli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	UInt128 operator ~ () const
	{
		return UInt128(_mm_xor_si128(Register, _mm_set1_epi32(0xFFFFFFFF)));
	}
};

NAMESPACE_NUMERICEND
#endif