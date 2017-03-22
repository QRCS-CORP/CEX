#ifndef _CEX_INTUTILS_H
#define _CEX_INTUTILS_H

#include "CexDomain.h"
#include "CexDomain.h"
#include "SimdProfiles.h"
#include <algorithm>
#include <sstream>

NAMESPACE_UTILITY

using Enumeration::SimdProfiles;

/// <summary>
/// An integer utility functions class
/// </summary>
class IntUtils
{
public:

	//~~~Macros~~~//

	/// <summary>
	/// Get a byte value from a 32 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// <param name="Shift">The number of bytes to shift</param>
	/// 
	/// <returns>Bit precision</returns>
	#define GETBYTE(Value, Shift) (uint)byte((Value)>>(8*(Shift)))
	// these may be faster on other CPUs/compilers
	// #define GETBYTE(Value, Shift) (uint)(((Value)>>(8*(Shift)))&255)
	// #define GETBYTE(Value, Shift) (((byte *)&(Value))[Shift])
	// this version of the macro is fastest on Pentium 3 and Pentium 4 with MSVC 6 SP5 w/ Processor Pack

	//~~~Templates~~~//

	/// <summary>
	/// Return the absolute positive value difference between two integers
	/// </summary>
	/// 
	/// <param name="A">The first integer for comparison</param>
	/// <param name="B">The second integer for comparison</param>
	/// 
	/// <returns>The difference between integers</returns>
	template <typename T>
	static T Abs(T A, T B)
	{
		return A > B ? A - B : B - A;
	}

	/// <summary>
	/// Get a byte from an integer
	/// </summary>
	///
	/// <param name="Value">The integer value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The cropped integer</returns>
	template <typename T>
	static byte GetByte(T Value, uint Shift)
	{
#ifdef IS_LITTLE_ENDIAN
		return GETBYTE(Value, Shift);
#else
		return GETBYTE(Value, sizeof(T) - Shift - 1);
#endif
	}

	/// <summary>
	/// Test for power of 2
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>True if the value is a power of 2</returns>
	template <typename T>
	static bool IsPowerOf2(T Value)
	{
		return Value > 0 && (Value & (Value - 1)) == 0;
	}

	/// <summary>
	/// Return the smaller of two values
	/// </summary>
	/// 
	/// <param name="A">The first comparison value</param>
	/// <param name="B">The second comparison value</param>
	/// 
	/// <returns>The smaller value</returns>
	template <typename T>
	static T Min(T A, T B)
	{
		return ((A) < (B) ? (A) : (B));
	}

	/// <summary>
	/// Mod a power of two integer
	/// </summary>
	/// 
	/// <param name="A">The initial value</param>
	/// <param name="B">The modulus</param>
	/// 
	/// <returns>The new value</returns>
	template <typename T1, typename T2>
	static T2 ModPowerOf2(T1 A, T2 B)
	{
		assert(IsPowerOf2(B));
		return T2(A) & (B - 1);
	}

	/// <summary>
	/// Convert an integer to a string
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The string representation</returns>
	template<typename T>
	static std::string ToString(const T &Value)
	{
		std::ostringstream oss;
		oss << Value;
		return oss.str();
	}

	// ** Misc Bits ** //

	/// <summary>
	/// Get the bit precision value
	/// </summary>
	/// 
	/// <param name="Value">initial value</param>
	/// 
	/// <returns>Bit precision</returns>
	static uint BitPrecision(ulong Value);

	/// <summary>
	/// Reverse a byte
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The revered byte</returns>
	static byte BitReverse(byte Value);

	/// <summary>
	/// Reverse an unsigned 16 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed ushort</returns>
	static ushort BitReverse(ushort Value);

	/// <summary>
	/// Reverse an unsigned 32 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed uint</returns>
	static uint BitReverse(uint Value);

#ifdef WORD64_AVAILABLE
	/// <summary>
	/// Reverse an unsigned 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed ulong</returns>
	static ulong BitReverse(ulong Value);
#endif

	//~~~Miscellaneous Byte~~~//

	/// <summary>
	/// Get the byte precision
	/// </summary>
	/// 
	/// <param name="Value">The sample value</param>
	/// 
	/// <returns>The byte precision</returns>
	static uint BytePrecision(ulong Value);

	/// <summary>
	/// Reverse a 16 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed ushort</returns>
	static ushort ByteReverse(ushort Value);

	/// <summary>
	/// Reverse a 32 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed uint</returns>
	static uint ByteReverse(uint Value);

	/// <summary>
	/// Reverse a 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed ulong</returns>
	static ulong ByteReverse(ulong Value);

	// Different computer architectures store data using different byte orders. "Big-endian"
	// means the most significant byte is on the left end of a word. "Little-endian" means the 
	// most significant byte is on the right end of a word. i.e.: 
	// BE: uint(block[3]) | (uint(block[2]) << 8) | (uint(block[1]) << 16) | (uint(block[0]) << 24)
	// LE: uint(block[0]) | (uint(block[1]) << 8) | (uint(block[2]) << 16) | (uint(block[3]) << 24)

	//~~~Big Endian~~~//

	/// <summary>
	/// Run time check for Little Endian byte order
	/// </summary>
	static bool IsBigEndian();

	/// <summary>
	/// Convert bytes to a Big Endian N bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="Offset">Offset within the input block</param>
	/// <returns>A T size word in Big Endian format</returns>
	template<typename T>
	inline static T LoadBE(const std::vector<byte> &Input, size_t Offset)
	{
		Offset *= sizeof(T);
		T out = 0;
		for (size_t i = 0; i != sizeof(T); ++i)
			out = (out << 8) | Input[Offset + i];
		return out;
	}

	/// <summary>
	/// Convert a Big Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static void Be16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Big Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static void Be32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Big Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static void Be64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Big Endian 8 * 32bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void BeUL256ToBlock(std::vector<uint> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a Big Endian 8 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void BeULL512ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a byte array to a Big Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Big Endian format</returns>
	static ushort BytesToBe16(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a Big Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Big Endian format</returns>
	static uint BytesToBe32(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a Big Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Big Endian format</returns>
	static ulong BytesToBe64(const std::vector<byte> &Input, const size_t InOffset);

	//~~~Little Endian~~~//

	/// <summary>
	/// Run time check for Little Endian byte order
	/// </summary>
	static bool IsLittleEndian();

	/// <summary>
	/// Convert bytes to a Little Endian N bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="Offset">Offset within the input block</param>
	/// <returns>A T size word in Little Endian format</returns>
	template<typename T>
	inline T LoadLE(const std::vector<byte> &Input, size_t Offset)
	{
		Offset *= sizeof(T);
		T out = 0;
		for (size_t i = 0; i != sizeof(T); ++i)
			out = (out << 8) | Input[Offset + (sizeof(T) - 1 - i)];
		return out;
	}

	/// <summary>
	/// Convert a Little Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Le16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Le32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Le64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 8 * 32bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void LeUL256ToBlock(std::vector<uint> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 4 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void LeULL256ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 8 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void LeULL512ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a Little Endian 16 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void LeULL1024ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Little Endian format</returns>
	static ushort BytesToLe16(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Little Endian format</returns>
	static uint BytesToLe32(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Little Endian format</returns>
	static ulong BytesToLe64(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 16 * 32bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	static void BytesToLeUL512(const std::vector<byte> &Input, const size_t InOffset, std::vector<uint> &Output, const size_t OutOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 4 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	static void BytesToLeULL256(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 8 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 64 bit dwords in Little Endian format</returns>
	static void BytesToLeULL512(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a byte array to a Little Endian 16 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	static void BytesToLeULL1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset);

	//~~~Endian Neutral~~~//

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 16 bit word in native Endian format</returns>
	static ushort BytesToWord16(const std::vector<byte> &Input);

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 16 bit word in native Endian format</returns>
	static ushort BytesToWord16(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 32 bit word in native Endian format</returns>
	static uint BytesToWord32(const std::vector<byte> &Input);

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 32 bit word in native Endian format</returns>
	static uint BytesToWord32(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 64 bit word in native Endian format</returns>
	static ulong BytesToWord64(const std::vector<byte> &Input);

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 64 bit word in native Endian format</returns>
	static ulong BytesToWord64(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static void Word16ToBytes(const ushort Value, std::vector<byte> &Output);

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Word16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static void Word32ToBytes(const uint Value, std::vector<byte> &Output);

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Word32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static void Word64ToBytes(const ulong Value, std::vector<byte> &Output);

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static void Word64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset);

	//~~~Miscellaneous and Constant Time~~~//

	/// <summary>
	/// Crop a 64 bit integer value
	/// </summary>
	///
	/// <param name="Value">The initial value</param>
	/// <param name="Size">The number of bits in the new integer</param>
	/// 
	/// <returns>The cropped integer</returns>
	static ulong Crop(ulong Value, uint Size);

	/// <summary>
	/// Expand an integer mask in constant time
	/// </summary>
	/// 
	/// <param name="X">The N bit word</param>
	/// 
	/// <returns>A N bit expanded word</returns>
	template<typename T>
	static T ExpandMask(T X)
	{
		T r = X;
		// fold r down to a single bit
		for (size_t i = 1; i != sizeof(T) * 8; i *= 2)
			r |= r >> i;

		r &= 1;
		r = ~(r - 1);

		return r;
	}

	/// <summary>
	/// Get the parity bit from a 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The parity value</returns>
	static uint Parity(ulong Value);

	/// <summary>
	/// Combine the bits from two integers filtered by a mask value
	/// </summary>
	/// 
	/// <param name="Mask">The mask value</param>
	/// <param name="A">The first value</param>
	/// <param name="B">The second value</param>
	/// 
	/// <returns>A combined N bit integer</returns>
	template<typename T>
	static T Select(T Mask, T A, T B)
	{
		return (A & Mask) | (B & ~Mask);
	}

	/// <summary>
	/// Select an integer based on a mask
	/// </summary>
	/// 
	/// <param name="Pred">The mask value</param>
	/// <param name="Value">The value</param>
	/// 
	/// <returns>A masked N bit integer</returns>
	template<typename P, typename V>
	static V ValueOrZero(P Pred, V Value)
	{
		return Select<V>(ExpandMask<V>(Pred), Value, static_cast<V>(0));
	}

	/// <summary>
	/// Constant time zero value check
	/// </summary>
	/// 
	/// <param name="X">The value to test</param>
	/// 
	/// <returns>A positive integer if non-zero</returns>
	template<typename T>
	static T IsZero(T X)
	{
		return ~ExpandMask<T>(X);
	}

	/// <summary>
	/// Constant time comparison of two integers for equality
	/// </summary>
	/// 
	/// <param name="X">The first value to test</param>
	/// <param name="Y">The second value to test</param>
	/// 
	/// <returns>A positive integer if equal</returns>
	template<typename T>
	static T IsEqual(T X, T Y)
	{
		return IsZero<T>(X ^ Y);
	}

	/// <summary>
	/// Constant time test if X < Y
	/// </summary>
	/// 
	/// <param name="X">The first value to test</param>
	/// <param name="Y">The second value to test</param>
	/// 
	/// <returns>A positive integer if less</returns>
	template<typename T>
	static T IsLess(T X, T Y)
	{
		return ExpandMask<T>(X < Y);
	}

	/// <summary>
	/// Constant time test if X <= Y
	/// </summary>
	/// 
	/// <param name="X">The first value to test</param>
	/// <param name="Y">The second value to test</param>
	/// 
	/// <returns>A positive integer if less</returns>
	template<typename T>
	static T IsLte(T X, T Y)
	{
		return ExpandMask<T>(X <= Y);
	}

	/// <summary>
	/// Constant time conditional bit copy
	/// </summary>
	/// 
	/// <param name="Value">The destination value</param>
	/// <param name="From0">The first value to copy</param>
	/// <param name="From1">The second value to copy</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	static void ConditionalCopy(T Value, T* To, const T* From0, const T* From1, size_t Length)
	{
		const T MASK = ExpandMask<T>(Value);

		for (size_t i = 0; i != Length; ++i)
			To[i] = Select<T>(MASK, From0[i], From1[i]);
	}

	/// <summary>
	/// Constant time conditional zeroize memory
	/// </summary>
	/// 
	/// <param name="Condition">The condition</param>
	/// <param name="From0">The first value to copy</param>
	/// <param name="From1">The second value to copy</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	static void ConditionalZeroMem(T Condition, T* Array, size_t Length)
	{
		const T MASK = ExpandMask<T>(Condition);
		const T ZERO(0);

		for (size_t i = 0; i != Length; ++i)
			Array[i] = Select<T>(MASK, ZERO, Array[i]);
	}

	/// <summary>
	/// Constant time last bit expansion
	/// </summary>
	/// 
	/// <param name="A">The value to expand</param>
	/// 
	/// <returns>A expanded N bit integer</returns>
	template<typename T>
	static T ExpandTopBit(T A)
	{
		return ExpandMask<T>(A >> (sizeof(T) * 8 - 1));
	}

	/// <summary>
	/// Constant time return the larger value of the two integers
	/// </summary>
	/// 
	/// <param name="A">The first value to compare</param>
	/// <param name="B">The second value to compare</param>
	/// 
	/// <returns>The larger value</returns>
	template<typename T>
	static T CMax(T A, T B)
	{
		return Select<T>(ExpandTopBit<T>(A), A, B);
	}

	/// <summary>
	/// Constant time return the lesser value of the two integers
	/// </summary>
	/// 
	/// <param name="A">The first value to compare</param>
	/// <param name="B">The second value to compare</param>
	/// 
	/// <returns>The lesser value</returns>
	template<typename T>
	static T CMin(T A, T B)
	{
		return Select<T>(ExpandTopBit<T>(B), B, A);
	}

	static std::vector<byte> StripLeadingZeros(const std::vector<byte> &Input, size_t Length);

	//~~~Rotate~~~//

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static uint RotL32(uint Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static ulong RotL64(ulong Value, uint Shift);

	/// <summary>
	/// Rotate shift a 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static uint RotR32(uint Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static ulong RotR64(ulong Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static uint RotFL32(uint Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static ulong RotFL64(ulong Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static uint RotFR32(uint Value, uint Shift);

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static ulong RotFR64(ulong Value, uint Shift);

	//~~~Byte Conversions~~~//

	/// <summary>
	/// Copy an unsigned short to bytes
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static std::vector<byte> ToBit16(ushort Value);

	/// <summary>
	/// Copy an unsigned int to bytes
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static std::vector<byte> ToBit32(uint Value);

	/// <summary>
	/// Copy an unsigned long to bytes
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static std::vector<byte> ToBit64(ulong Value);

	/// <summary>
	/// Copy bytes to an unsigned short
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static ushort ToInt16(std::vector<byte> Input);

	/// <summary>
	/// Copy bytes to an unsigned int
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 32 bit integer</returns>
	static uint ToInt32(std::vector<byte> Input);

	/// <summary>
	/// Copy bytes to an unsigned long
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 64 bit integer</returns>
	static ulong ToInt64(std::vector<byte> Input);

	/// <summary>
	/// Copy bytes to an unsigned short
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static ushort ToInt16(std::vector<byte> Input, size_t InOffset);

	/// <summary>
	/// Copy bytes to an unsigned int
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 32bit integer</returns>
	static uint ToInt32(std::vector<byte> Input, size_t InOffset);

	/// <summary>
	/// Copy bytes to an unsigned long
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 64 bit integer</returns>
	static ulong ToInt64(std::vector<byte> Input, size_t InOffset);

	/// <summary>
	/// Convert an array of 64 bit words into a byte array
	/// </summary>
	/// 
	/// <param name="Input">The input integer array</param>
	/// <param name="Output">The output byte array</param>
	static void Word64sToBytes(const std::vector<ulong> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Convert an array of 64 bit words into a byte array
	/// </summary>
	/// 
	/// <param name="Input">The input integer array</param>
	/// <param name="InOffset">The input arrays starting offset</param>
	/// <param name="Length">The number of bytes to return</param>
	/// <param name="Output">The input integer array</param>
	static void BytesToWord64s(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<ulong> &Output);

	//~~~Block XOR~~~//

	/// <summary>
	/// Block XOR 16 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// Block XOR 32 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR256(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// Block XOR 8 * 32bit unsigned integers
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="SimdProfile">System supported SIMD instructions</param>
	static void XORUL256(const std::vector<uint> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// Block XOR 4 * 64bit unsigned integers
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="SimdProfile">System supported SIMD instructions</param>
	static void XORULL256(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// Block XOR 8 * 64bit unsigned integers
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="SimdProfile">System supported SIMD instructions</param>
	static void XORULL512(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// Block XOR 16 * 64bit unsigned integers
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="SimdProfile">System supported SIMD instructions</param>
	static void XORULL1024(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile);

	/// <summary>
	/// XOR contiguous 16 byte blocks in an array.
	/// <para>The array must be evenly aligned to 16 bytes</para>
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="Length">The number of (16 byte block aligned) bytes to process</param>
	/// <param name="SimdProfile">System supported SIMD instructions</param>
	static void XORBLK(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length, SimdProfiles SimdProfile);

	/// <summary>
	/// XOR a partial byte block.
	/// <para>The length should be less than 16 bytes, otherwise use the parallel methods and process the last block with this (sequential) function.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="Length">The number of (16 byte block aligned) bytes to process</param>
	static void XORPRT(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
};

NAMESPACE_UTILITYEND
#endif

