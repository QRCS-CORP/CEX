#ifndef _CEX_UINT128_H
#define _CEX_UINT128_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

/// <summary>
/// An SSE 128 intrinsics wrapper
/// </summary>
class UInt128
{
private:
	explicit UInt128(__m128i Input)
	{
		Register = Input;
	}

public:
	/// <summary>
	/// The internal m128i register value
	/// </summary>
	__m128i Register;

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt128() {}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<byte> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 16bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 8 * 16bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<ushort> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<uint> &Input, size_t Offset)
	{
		Register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt128(const std::vector<ulong> &Input, size_t Offset)
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
	explicit UInt128(uint X0, uint X1, uint X2, uint X3)
	{
		Register = _mm_set_epi32(X0, X1, X2, X3);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer; copied to every register
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt128(uint X)
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
	void LoadBE(uint X0, uint X1, uint X2, uint X3);

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
	static void LoadBE16(const std::vector<byte> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3);

	/// <summary>
	/// Loads 64 * 32bit integers to a UInt128 array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt128 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void LoadBE256(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt128> &Output, size_t OutOffset);

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
	void LoadLE(uint X0, uint X1, uint X2, uint X3);

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
	static void LoadLE16(const std::vector<byte> &Input, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3);

	/// <summary>
	/// Loads 64 * 32bit integers to a UInt128 array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt128 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void LoadLE256(std::vector<byte> &Input, size_t InOffset, std::vector<UInt128> &Output, size_t OutOffset);

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
	static void StoreBE16(std::vector<byte> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3);

	/// <summary>
	/// Transposes and loads 64 * 32bit integers to an output array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt128 array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void StoreBE256(std::vector<UInt128> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

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
	static void StoreLE16(std::vector<byte> &Output, size_t Offset, UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3);

	/// <summary>
	/// Transposes and copies 64 * 32bit integers to an output array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt128 array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	static void StoreLE256(std::vector<UInt128> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

	//~~~ Methods~~~//

	/// <summary>
	/// Computes the bitwise AND of the 128-bit value in *this* and the bitwise NOT of the 128-bit value in Value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt128</returns>
	UInt128 AndNot(const UInt128 &Value);

	/// <summary>
	/// Returns the length of the register in bytes
	/// </summary>
	///
	/// <returns>The registers size</returns>
	static const size_t Length();

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	void RotL32(const int Shift);

	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	static UInt128 RotL32(const UInt128 &Value, const int Shift);

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Shift">The shift degree; maximum is 32</param>
	void RotR32(const int Shift);

	/// <summary>
	/// Computes the 32 bit right rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="Value">The integer to rotate</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	/// 
	/// <returns>The rotated UInt128</returns>
	static UInt128 RotR32(const UInt128 &Value, const int Shift);

	/// <summary>
	/// Load a Uint128 in Big Endian format using 32bit uints staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static UInt128 ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

	/// <summary>
	/// Load a Uint128 in Big Endian format using a 32bit uint array staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input uint32 array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static UInt128 ShuffleLoad32(const std::vector<uint> &Input, size_t Offset, size_t Shift);

	/// <summary>
	/// Load a Uint128 in Little Endian format using uint staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static UInt128 ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	UInt128 Swap() const;

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt128 to process</param>
	/// 
	/// <returns>The byte swapped UInt128</returns>
	static UInt128 Swap(UInt128 &X);

	/// <summary>
	/// Copies the register uint8 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint8(std::vector<byte> &Output, size_t Offset);

	/// <summary>
	/// Copies the register uint16 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint16(std::vector<ushort> &Output, size_t Offset);

	/// <summary>
	/// Copies the register uint32 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint32(std::vector<uint> &Output, size_t Offset);

	/// <summary>
	/// Copies the register uint64 array to an output array
	/// </summary>
	///
	/// <param name="Output">The output byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	void ToUint64(std::vector<ulong> &Output, size_t Offset);

	/// <summary>
	/// Shuffles the registers in 4 * UInt128 structures; to create a sequential chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void Transpose(UInt128 &X0, UInt128 &X1, UInt128 &X2, UInt128 &X3);

	//~~~ Operators~~~//

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	inline void operator += (const UInt128 &Value)
	{
		Register = _mm_add_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	inline UInt128 operator + (const UInt128 &Value) const
	{
		return UInt128(_mm_add_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	inline void operator -= (const UInt128 &Value)
	{
		Register = _mm_sub_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	inline UInt128 operator - (const UInt128 &Value) const
	{
		return UInt128(_mm_sub_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="Value">The value to multiply</param>
	inline void operator *= (const UInt128 &Value)
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
	inline UInt128 operator * (const UInt128 &Value) const
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
	inline void operator /= (const UInt128 &Value)
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
	inline UInt128 operator / (const UInt128 &Value) const
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
	inline void operator %= (const UInt128 &Value)
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
	inline UInt128 operator % (const UInt128 &Value) const
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
	inline void operator ^= (const UInt128 &Value)
	{
		Register = _mm_xor_si128(Register, Value.Register);
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="Value">The value to Xor</param>
	inline UInt128 operator ^ (const UInt128 &Value) const
	{
		return UInt128(_mm_xor_si128(Register, Value.Register));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	inline void operator |= (const UInt128 &Value)
	{
		Register = _mm_or_si128(Register, Value.Register);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	inline UInt128 operator | (const UInt128 &Value)
	{
		return UInt128(_mm_or_si128(Register, Value.Register));
	}

	/// <summary>
	/// AND this integer
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	inline void operator &= (const UInt128 &Value)
	{
		Register = _mm_and_si128(Register, Value.Register);
	}

	/// <summary>
	/// AND two integers
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	inline UInt128 operator & (const UInt128 &Value)
	{
		return UInt128(_mm_and_si128(Register, Value.Register));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		Register = _mm_slli_epi32(Register, Shift);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator << (const int Shift) const
	{
		return UInt128(_mm_slli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		Register = _mm_srli_epi32(Register, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt128 operator >> (const int Shift) const
	{
		return UInt128(_mm_srli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt128 operator ~ () const
	{
		return UInt128(_mm_xor_si128(Register, _mm_set1_epi32(0xFFFFFFFF)));
	}
};

NAMESPACE_NUMERICEND
#endif