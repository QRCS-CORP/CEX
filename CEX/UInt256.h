#ifndef _CEX_UINT256_H
#define _CEX_UINT256_H

#include "CexDomain.h"
#include "Intrinsics.h"

NAMESPACE_NUMERIC

/// <summary>
/// An AVX 256 intrinsics wrapper
/// </summary>
class UInt256
{
private:
	explicit UInt256(__m256i Input)
	{
		Register = Input;
	}

public:
	/// <summary>
	/// The internal m256i register value
	/// </summary>
	__m256i Register;

	//~~~ Constructor~~~//

	/// <summary>
	/// Default constructor; does not initialize the register
	/// </summary>
	UInt256() {}

	/// <summary>
	/// Initialize with an 8bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt256(const std::vector<byte> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 16bit unsigned integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 16 * 16bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt256(const std::vector<ushort> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 32bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 4 * 32bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt256(const std::vector<uint> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
	}

	/// <summary>
	/// Initialize with a 64bit unsigned integer array
	/// </summary>
	///
	/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	explicit UInt256(const std::vector<ulong> &Input, size_t Offset)
	{
		Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
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
		Register = _mm256_set_epi32(X0, X1, X2, X3, X4, X5, X6, X7);
	}

	/// <summary>
	/// Initialize with 1 * 32bit unsigned integer
	/// </summary>
	///
	/// <param name="X">The uint to add</param>
	explicit UInt256(uint X)
	{
		Register = _mm256_set1_epi32(X);
	}

	//~~~ Load and Store~~~//

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
	/// Initialize with 8 * 32bit unsigned integers in Big Endian format
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
	void LoadBE(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7);

	/// <summary>
	/// Loads 4 * UInt128 at 32bit boundaries in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The data input array</param>
	/// <param name="Offset">The starting position within the input array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void LoadBE32(const std::vector<byte> &Input, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3);

	/// <summary>
	/// Loads 128 * 32bit integers to an output array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt256 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void LoadBE512(std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &Output, size_t OutOffset);

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
	/// Load with 8 * 32bit unsigned integers in Little Endian format
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
	void LoadLE(uint X0, uint X1, uint X2, uint X3, uint X4, uint X5, uint X6, uint X7);

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
	static void LoadLE32(const std::vector<byte> &Input, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3);

	/// <summary>
	/// Loads 128 * 32bit integers to an output array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination UInt256 array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void LoadLE512(std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &Output, size_t OutOffset);

	/// <summary>
	/// Store register in an integer array in Big Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreBE(std::vector<T> &Output, size_t Offset) const
	{
		Swap().StoreLE(Output, Offset);
	}

	/// <summary>
	/// Transposes and stores 64 * 32bit integers in Big Endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void StoreBE32(std::vector<byte> &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3);

	/// <summary>
	/// Transposes and copies 128 * 32bit integers to an output array in Big Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt256 array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void StoreBE512(std::vector<UInt256> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Store register in an integer array in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The array containing the data; must be at least 256 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	template <typename T>
	void StoreLE(std::vector<T> &Output, size_t Offset) const
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), Register);
	}

	/// <summary>
	/// Transposes and stores 32 * 32bit integers in Little Endian format
	/// </summary>
	///
	/// <param name="Output">The destination byte array</param>
	/// <param name="Offset">The starting offset within the output array</param>
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void StoreLE32(std::vector<byte> &Output, size_t Offset, UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3);

	/// <summary>
	/// Transposes and copies 128 * 32bit integers to an output array in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The input UInt256 array</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	static void StoreLE512(std::vector<UInt256> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

	//~~~ Methods~~~//

	/// <summary>
	/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in Value
	/// </summary>
	///
	/// <param name="Value">The comparison integer</param>
	/// 
	/// <returns>The processed UInt256</returns>
	UInt256 AndNot(const UInt256 &Value);

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
	/// <returns>The rotated UInt256</returns>
	static UInt256 RotL32(const UInt256 &Value, const int Shift);

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
	/// <returns>The rotated UInt256</returns>
	static UInt256 RotR32(const UInt256 &Value, const int Shift);

	/// <summary>
	/// Load a Uint256 in Big Endian format using uint staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static UInt256 ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

	/// <summary>
	/// Load a Uint256 in Little Endian format using uint staggered at multiples of the shift factor
	/// </summary>
	///
	/// <param name="Input">The input byte array</param>
	/// <param name="Offset">The starting offset within the input array</param>
	/// <param name="Shift">The shift factor</param>
	/// 
	/// <returns>A populated UInt128</returns>
	static UInt256 ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift);

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 
	/// <returns>The byte swapped UInt256</returns>
	UInt256 Swap() const;

	/// <summary>
	/// Performs a byte swap on 4 unsigned integers
	/// </summary>
	/// 		
	/// <param name="X">The UInt256 to process</param>
	/// 
	/// <returns>The byte swapped UInt256</returns>
	static UInt256 Swap(UInt256 &X);

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
	/// Shuffles the registers in 4 * UInt256 structures; to create a linear chain
	/// </summary>
	///
	/// <param name="X0">Operand 0</param>
	/// <param name="X1">Operand 1</param>
	/// <param name="X2">Operand 2</param>
	/// <param name="X3">Operand 3</param>
	static void Transpose(UInt256 &X0, UInt256 &X1, UInt256 &X2, UInt256 &X3);

	//~~~ Operators~~~//

	/// <summary>
	/// Add a value to this integer
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	inline void operator += (const UInt256 &Value)
	{
		Register = _mm256_add_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Add two integers
	/// </summary>
	///
	/// <param name="Value">The value to add</param>
	inline UInt256 operator + (const UInt256 &Value) const
	{
		return UInt256(_mm256_add_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Subtract a value from this integer
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	inline void operator -= (const UInt256 &Value)
	{
		Register = _mm256_sub_epi32(Register, Value.Register);
	}

	/// <summary>
	/// Subtract two integers
	/// </summary>
	///
	/// <param name="Value">The value to subtract</param>
	inline UInt256 operator - (const UInt256 &Value) const
	{
		return UInt256(_mm256_sub_epi32(Register, Value.Register));
	}

	/// <summary>
	/// Multiply a value with this integer
	/// </summary>
	///
	/// <param name="Value">The value to multiply</param>
	inline void operator *= (const UInt256 &Value)
	{
		__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
		Register = _mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
	}

	/// <summary>
	/// Multiply two integers
	/// </summary>
	///
	/// <param name="Value">The value to multiply</param>
	inline UInt256 operator * (const UInt256 &Value) const
	{
		__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
		__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
		return UInt256(_mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
	}

	/// <summary>
	/// Divide this integer by a value
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	inline void operator /= (const UInt256 &Value)
	{
		// ToDo: finish this (rounded floating point ops)
		Register.m256i_u32[0] /= Value.Register.m256i_u32[0];
		Register.m256i_u32[1] /= Value.Register.m256i_u32[1];
		Register.m256i_u32[2] /= Value.Register.m256i_u32[2];
		Register.m256i_u32[3] /= Value.Register.m256i_u32[3];
		Register.m256i_u32[4] /= Value.Register.m256i_u32[4];
		Register.m256i_u32[5] /= Value.Register.m256i_u32[5];
		Register.m256i_u32[6] /= Value.Register.m256i_u32[6];
		Register.m256i_u32[7] /= Value.Register.m256i_u32[7];
	}

	/// <summary>
	/// Divide two integers
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	inline UInt256 operator / (const UInt256 &Value) const
	{
		// ToDo: finish this
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

	/// <summary>
	/// Get the remainder from a division operation
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	inline void operator %= (const UInt256 &Value)
	{
		// ToDo: finish this
		Register.m256i_u32[0] %= Value.Register.m256i_u32[0];
		Register.m256i_u32[1] %= Value.Register.m256i_u32[1];
		Register.m256i_u32[2] %= Value.Register.m256i_u32[2];
		Register.m256i_u32[3] %= Value.Register.m256i_u32[3];
		Register.m256i_u32[4] %= Value.Register.m256i_u32[4];
		Register.m256i_u32[5] %= Value.Register.m256i_u32[5];
		Register.m256i_u32[6] %= Value.Register.m256i_u32[6];
		Register.m256i_u32[7] %= Value.Register.m256i_u32[7];
	}

	/// <summary>
	/// Get the remainder from a division operation between two integers
	/// </summary>
	///
	/// <param name="Value">The divisor value</param>
	inline UInt256 operator % (const UInt256 &Value) const
	{
		// ToDo: finish this
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

	/// <summary>
	/// Xor this integer by a value
	/// </summary>
	///
	/// <param name="Value">The value to Xor</param>
	inline void operator ^= (const UInt256 &Value)
	{
		Register = _mm256_xor_si256(Register, Value.Register);
	}

	/// <summary>
	/// Xor two integers
	/// </summary>
	///
	/// <param name="Value">The value to Xor</param>
	inline UInt256 operator ^ (const UInt256 &Value) const
	{
		return UInt256(_mm256_xor_si256(Register, Value.Register));
	}

	/// <summary>
	/// OR this integer
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	inline void operator |= (const UInt256 &Value)
	{
		Register = _mm256_or_si256(Register, Value.Register);
	}

	/// <summary>
	/// OR two integers
	/// </summary>
	///
	/// <param name="Value">The value to OR</param>
	inline UInt256 operator | (const UInt256 &Value)
	{
		return UInt256(_mm256_or_si256(Register, Value.Register));
	}

	/// <summary>
	/// AND this integer
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	inline void operator &= (const UInt256 &Value)
	{
		Register = _mm256_and_si256(Register, Value.Register);
	}

	/// <summary>
	/// AND two integers
	/// </summary>
	///
	/// <param name="Value">The value to AND</param>
	inline UInt256 operator & (const UInt256 &Value)
	{
		return UInt256(_mm256_and_si256(Register, Value.Register));
	}

	/// <summary>
	/// Left shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator <<= (const int Shift)
	{
		Register = _mm256_slli_epi32(Register, Shift);
	}

	/// <summary>
	/// Left shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt256 operator << (const int Shift) const
	{
		return UInt256(_mm256_slli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Right shift this integer
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline void operator >>= (const int Shift)
	{
		Register = _mm256_srli_epi32(Register, Shift);
	}

	/// <summary>
	/// Right shift two integers
	/// </summary>
	///
	/// <param name="Shift">The shift position</param>
	inline UInt256 operator >> (const int Shift) const
	{
		return UInt256(_mm256_srli_epi32(Register, static_cast<int>(Shift)));
	}

	/// <summary>
	/// Bitwise NOT this integer
	/// </summary>
	inline UInt256 operator ~ () const
	{
		return UInt256(_mm256_xor_si256(Register, _mm256_set1_epi32(0xFFFFFFFF)));
	}

private:
	inline static void _mm256_merge_epi32(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
	{
		__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
		__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
		Xl = _mm256_unpacklo_epi32(va, vb);
		Xh = _mm256_unpackhi_epi32(va, vb);
	}

	inline static void _mm256_merge_epi64(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
	{
		__m256i va = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
		__m256i vb = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));
		Xl = _mm256_unpacklo_epi64(va, vb);
		Xh = _mm256_unpackhi_epi64(va, vb);
	}

	inline static void _mm256_merge_si128(const __m256i X0, const __m256i X1, __m256i &Xl, __m256i &Xh)
	{
		Xl = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 2, 0, 0));
		Xh = _mm256_permute2x128_si256(X0, X1, _MM_SHUFFLE(0, 3, 0, 1));
	}
};

NAMESPACE_NUMERICEND
#endif