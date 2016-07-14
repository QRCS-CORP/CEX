#ifndef _CEXENGINE_INTUTILS_H
#define _CEXENGINE_INTUTILS_H

#include "Common.h"
#include <sstream>

#if defined(HAS_MINSSE)
#	include "Intrinsics.h"
#endif

NAMESPACE_UTILITY

/// <summary>
/// Integer functions class
/// </summary>
class IntUtils
{
public:

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
	static inline byte BitReverse(byte Value)
	{
		Value = ((Value & 0xAA) >> 1) | ((Value & 0x55) << 1);
		Value = ((Value & 0xCC) >> 2) | ((Value & 0x33) << 2);
		return static_cast<byte>(RotateFixLeft(Value, 4));
	}

	/// <summary>
	/// Reverse an unsigned 16 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed ushort</returns>
	static inline ushort BitReverse(ushort Value)
	{
		Value = ((Value & 0xAAAA) >> 1) | ((Value & 0x5555) << 1);
		Value = ((Value & 0xCCCC) >> 2) | ((Value & 0x3333) << 2);
		Value = ((Value & 0xF0F0) >> 4) | ((Value & 0x0F0F) << 4);
		return ByteReverse(Value);
	}

	/// <summary>
	/// Reverse an unsigned 32 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed uint</returns>
	static inline uint BitReverse(uint Value)
	{
		Value = ((Value & 0xAAAAAAAA) >> 1) | ((Value & 0x55555555) << 1);
		Value = ((Value & 0xCCCCCCCC) >> 2) | ((Value & 0x33333333) << 2);
		Value = ((Value & 0xF0F0F0F0) >> 4) | ((Value & 0x0F0F0F0F) << 4);
		return ByteReverse(Value);
	}

#ifdef WORD64_AVAILABLE
	/// <summary>
	/// Reverse an unsigned 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The reversed ulong</returns>
	static inline ulong BitReverse(ulong Value)
	{
#ifdef SLOW_WORD64
		return (ulong(BitReverse(uint(Value))) << 32) | BitReverse(uint(Value >> 32));
#else
		Value = ((Value & W64LIT(0xAAAAAAAAAAAAAAAA)) >> 1) | ((Value & W64LIT(0x5555555555555555)) << 1);
		Value = ((Value & W64LIT(0xCCCCCCCCCCCCCCCC)) >> 2) | ((Value & W64LIT(0x3333333333333333)) << 2);
		Value = ((Value & W64LIT(0xF0F0F0F0F0F0F0F0)) >> 4) | ((Value & W64LIT(0x0F0F0F0F0F0F0F0F)) << 4);
		return ByteReverse(Value);
#endif
	}
#endif

	// ** Misc Byte ** //

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
	static inline ushort ByteReverse(ushort Value)
	{
		return static_cast<ushort>(RotateFixLeft(Value, 8U));
	}

	/// <summary>
	/// Reverse a 32 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed uint</returns>
	static inline uint ByteReverse(uint Value)
	{
#ifdef PPC_INTRINSICS
		// PPC: load reverse indexed instruction
		return (uint)__lwbrx(&Value, 0);
#elif defined(FAST_ROTATE)
		// 5 instructions with rotate instruction, 9 without
		return (RotateFixRight(Value, 8U) & 0xff00ff00) | (RotateFixLeft(Value, 8U) & 0x00ff00ff);
#else
		// 6 instructions with rotate instruction, 8 without
		Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
		return RotateFixLeft(Value, 16U);
#endif
	}

	/// <summary>
	/// Reverse a 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed ulong</returns>
	static inline ulong ByteReverse(ulong Value)
	{
#ifdef PPC_INTRINSICS
		// PPC: load reverse indexed instruction
		return static_cast<uint>(__lwbrx(&Value, 0));
#elif defined(FAST_ROTATE)
		// 5 instructions with rotate instruction, 9 without
		return (RotateFixRight(Value, 8U) & 0xff00ff00) | (RotateFixLeft(Value, 8U) & 0x00ff00ff);
#else
		// 6 instructions with rotate instruction, 8 without
		Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
		return RotateFixLeft(Value, 16U);
#endif
	}

	// Different computer architectures store data using different byte orders. "Big-endian"
	// means the most significant byte is on the left end of a word. "Little-endian" means the 
	// most significant byte is on the right end of a word. i.e.: 
	// BE: uint(block[3]) | (uint(block[2]) << 8) | (uint(block[1]) << 16) | (uint(block[0]) << 24)
	// LE: uint(block[0]) | (uint(block[1]) << 8) | (uint(block[2]) << 16) | (uint(block[3]) << 24)

	// ** Big Endian ** //

	/// <summary>
	/// Convert a Big Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static inline void Be16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(IS_BIG_ENDIAN)
		memcpy(&Output[OutOffset], &Value, sizeof(ushort));
#else
		Output[OutOffset + 1] = static_cast<byte>(Value);
		Output[OutOffset] = static_cast<byte>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static inline void Be32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined IS_BIG_ENDIAN
		memcpy(&Output[OutOffset], &Value, sizeof(uint));
#else
		Output[OutOffset + 3] = static_cast<byte>(Value);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
		Output[OutOffset] = static_cast<byte>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static inline void Be64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(IS_BIG_ENDIAN)
		memcpy(&Output[OutOffset], &Value, sizeof(ulong));
#else
		Output[OutOffset + 7] = static_cast<byte>(Value);
		Output[OutOffset + 6] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 5] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 4] = static_cast<byte>(Value >> 24);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 32);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 40);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 48);
		Output[OutOffset] = static_cast<byte>(Value >> 56);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Big Endian format</returns>
	static inline ushort BytesToBe16(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_BIG_ENDIAN)
		ushort value = 0;
		memcpy(&value, &Input[InOffset], sizeof(ushort));
		return value;
#else
		return
			(static_cast<ushort>(Input[InOffset] << 8)) |
			(static_cast<ushort>(Input[InOffset + 1]));
#endif
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Big Endian format</returns>
	static inline uint BytesToBe32(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_BIG_ENDIAN)
		uint value = 0;
		memcpy(&value, &Input[InOffset], sizeof(uint));
		return value;
#else
		return
			(static_cast<uint>(Input[InOffset] << 24)) |
			(static_cast<uint>(Input[InOffset + 1] << 16)) |
			(static_cast<uint>(Input[InOffset + 2] << 8)) |
			(static_cast<uint>(Input[InOffset + 3]));
#endif
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Big Endian format</returns>
	static inline ulong BytesToBe64(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_BIG_ENDIAN)
		ulong value = 0;
		memcpy(&value, &Input[InOffset], sizeof(ulong));
		return value;
#else
		return
			((ulong)Input[InOffset] << 56) |
			((ulong)Input[InOffset + 1] << 48) |
			((ulong)Input[InOffset + 2] << 40) |
			((ulong)Input[InOffset + 3] << 32) |
			((ulong)Input[InOffset + 4] << 24) |
			((ulong)Input[InOffset + 5] << 16) |
			((ulong)Input[InOffset + 6] << 8) |
			((ulong)Input[InOffset + 7]);
#endif
	}

	// ** Little Endian ** //

	/// <summary>
	/// Convert a Little Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Value, sizeof(ushort));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Value, sizeof(uint));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Value, sizeof(ulong));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
		Output[OutOffset + 4] = static_cast<byte>(Value >> 32);
		Output[OutOffset + 5] = static_cast<byte>(Value >> 40);
		Output[OutOffset + 6] = static_cast<byte>(Value >> 48);
		Output[OutOffset + 7] = static_cast<byte>(Value >> 56);
#endif
	}

	static inline void Le256ToBlock(std::vector<uint32_t> &Input, std::vector<uint8_t> &Output, size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Input[0], Input.size() * sizeof(uint32_t));
#else
		Le32ToBytes(Input[0], Output, OutOffset);
		Le32ToBytes(Input[1], Output, OutOffset + 4);
		Le32ToBytes(Input[2], Output, OutOffset + 8);
		Le32ToBytes(Input[3], Output, OutOffset + 12);
		Le32ToBytes(Input[4], Output, OutOffset + 16);
		Le32ToBytes(Input[5], Output, OutOffset + 20);
		Le32ToBytes(Input[6], Output, OutOffset + 24);
		Le32ToBytes(Input[7], Output, OutOffset + 28);
#endif
	}

	static inline void Le512ToBlock(std::vector<uint64_t> &Input, std::vector<uint8_t> &Output, size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Input[0], Input.size() * sizeof(uint64_t));
#else
		Le64ToBytes(Input[0], Output, OutOffset);
		Le64ToBytes(Input[1], Output, OutOffset + 8);
		Le64ToBytes(Input[2], Output, OutOffset + 16);
		Le64ToBytes(Input[3], Output, OutOffset + 24);
		Le64ToBytes(Input[4], Output, OutOffset + 32);
		Le64ToBytes(Input[5], Output, OutOffset + 40);
		Le64ToBytes(Input[6], Output, OutOffset + 48);
		Le64ToBytes(Input[7], Output, OutOffset + 56);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Little Endian format</returns>
	static inline ushort BytesToLe16(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		ushort value = 0;
		memcpy(&value, &Input[InOffset], sizeof(ushort));
		return value;
#else
		return
			(static_cast<ushort>(Input[InOffset]) |
			(static_cast<ushort>(Input[InOffset + 1] << 8)));
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Little Endian format</returns>
	static inline uint BytesToLe32(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		uint value = 0;
		memcpy(&value, &Input[InOffset], sizeof(uint));
		return value;
#else
		return
			(static_cast<uint>(Input[InOffset]) |
			(static_cast<uint>(Input[InOffset + 1] << 8)) |
			(static_cast<uint>(Input[InOffset + 2] << 16)) |
			(static_cast<uint>(Input[InOffset + 3] << 24)));
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Little Endian format</returns>
	static inline ulong BytesToLe64(const std::vector<byte> &Input, const size_t InOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		ulong value = 0;
		memcpy(&value, &Input[InOffset], sizeof(ulong));
		return value;
#else
		return
			((ulong)Input[InOffset]) |
			((ulong)Input[InOffset + 1] << 8) |
			((ulong)Input[InOffset + 2] << 16) |
			((ulong)Input[InOffset + 3] << 24) |
			((ulong)Input[InOffset + 4] << 32) |
			((ulong)Input[InOffset + 5] << 40) |
			((ulong)Input[InOffset + 6] << 48) |
			((ulong)Input[InOffset + 7] << 56);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 32 bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	static inline void BytesToLeUL512(const std::vector<uint8_t> &Input, const size_t InOffset, std::vector<uint32_t> &Output, const size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(uint32_t));
#else
		Output[OutOffset] = BytesToLe32(Input, InOffset);
		Output[OutOffset + 1] = BytesToLe32(Input, InOffset + 4);
		Output[OutOffset + 2] = BytesToLe32(Input, InOffset + 8);
		Output[OutOffset + 3] = BytesToLe32(Input, InOffset + 12);
		Output[OutOffset + 4] = BytesToLe32(Input, InOffset + 16);
		Output[OutOffset + 5] = BytesToLe32(Input, InOffset + 20);
		Output[OutOffset + 6] = BytesToLe32(Input, InOffset + 24);
		Output[OutOffset + 7] = BytesToLe32(Input, InOffset + 28);
		Output[OutOffset + 8] = BytesToLe32(Input, InOffset + 32);
		Output[OutOffset + 9] = BytesToLe32(Input, InOffset + 36);
		Output[OutOffset + 10] = BytesToLe32(Input, InOffset + 40);
		Output[OutOffset + 11] = BytesToLe32(Input, InOffset + 44);
		Output[OutOffset + 12] = BytesToLe32(Input, InOffset + 48);
		Output[OutOffset + 13] = BytesToLe32(Input, InOffset + 52);
		Output[OutOffset + 14] = BytesToLe32(Input, InOffset + 56);
		Output[OutOffset + 15] = BytesToLe32(Input, InOffset + 60);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 64 bit dword array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 64 bit dwords in Little Endian format</returns>
	static inline void BytesToLeULL512(const std::vector<uint8_t> &Input, const size_t InOffset, std::vector<uint64_t> &Output, size_t OutOffset)
	{
#if defined(IS_LITTLE_ENDIAN)
		memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(uint64_t));
#else
		Output[OutOffset] = BytesToLe64(Input, InOffset);
		Output[OutOffset + 1] = BytesToLe64(Input, InOffset + 8);
		Output[OutOffset + 2] = BytesToLe64(Input, InOffset + 16);
		Output[OutOffset + 3] = BytesToLe64(Input, InOffset + 24);
		Output[OutOffset + 4] = BytesToLe64(Input, InOffset + 32);
		Output[OutOffset + 5] = BytesToLe64(Input, InOffset + 40);
		Output[OutOffset + 6] = BytesToLe64(Input, InOffset + 48);
		Output[OutOffset + 7] = BytesToLe64(Input, InOffset + 56);
		Output[OutOffset + 8] = BytesToLe64(Input, InOffset + 64);
		Output[OutOffset + 9] = BytesToLe64(Input, InOffset + 72);
		Output[OutOffset + 10] = BytesToLe64(Input, InOffset + 80);
		Output[OutOffset + 11] = BytesToLe64(Input, InOffset + 88);
		Output[OutOffset + 12] = BytesToLe64(Input, InOffset + 96);
		Output[OutOffset + 13] = BytesToLe64(Input, InOffset + 104);
		Output[OutOffset + 14] = BytesToLe64(Input, InOffset + 112);
		Output[OutOffset + 15] = BytesToLe64(Input, InOffset + 120);
#endif
	}

#if defined(IS_LITTLE_ENDIAN)
	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline ushort BytesToWord16(const std::vector<byte> &Input)
	{
		return
			(static_cast<ushort>(Input[0]) |
			(static_cast<ushort>(Input[1] << 8)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline ushort BytesToWord16(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			(static_cast<ushort>(Input[InOffset]) |
			(static_cast<ushort>(Input[InOffset + 1] << 8)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input)
	{
		return
			(static_cast<uint>(Input[0]) |
			(static_cast<uint>(Input[1] << 8)) |
			(static_cast<uint>(Input[2] << 16)) |
			(static_cast<uint>(Input[3] << 24)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			(static_cast<uint>(Input[InOffset]) |
			(static_cast<uint>(Input[InOffset + 1] << 8)) |
			(static_cast<uint>(Input[InOffset + 2] << 16)) |
			(static_cast<uint>(Input[InOffset + 3] << 24)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input)
	{
		return
			((ulong)Input[0]) |
			((ulong)Input[1] << 8) |
			((ulong)Input[2] << 16) |
			((ulong)Input[3] << 24) |
			((ulong)Input[4] << 32) |
			((ulong)Input[5] << 40) |
			((ulong)Input[6] << 48) |
			((ulong)Input[7] << 56);
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			((ulong)Input[InOffset]) |
			((ulong)Input[InOffset + 1] << 8) |
			((ulong)Input[InOffset + 2] << 16) |
			((ulong)Input[InOffset + 3] << 24) |
			((ulong)Input[InOffset + 4] << 32) |
			((ulong)Input[InOffset + 5] << 40) |
			((ulong)Input[InOffset + 6] << 48) |
			((ulong)Input[InOffset + 7] << 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word16ToBytes(const ushort Value, std::vector<byte> &Output)
	{
		Output[0] = static_cast<byte>(Value);
		Output[1] = static_cast<byte>(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output)
	{
		Output[0] = static_cast<byte>(Value);
		Output[1] = static_cast<byte>(Value >> 8);
		Output[2] = static_cast<byte>(Value >> 16);
		Output[3] = static_cast<byte>(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output)
	{
		Output[0] = static_cast<byte>(Value);
		Output[1] = static_cast<byte>(Value >> 8);
		Output[2] = static_cast<byte>(Value >> 16);
		Output[3] = static_cast<byte>(Value >> 24);
		Output[4] = static_cast<byte>(Value >> 32);
		Output[5] = static_cast<byte>(Value >> 40);
		Output[6] = static_cast<byte>(Value >> 48);
		Output[7] = static_cast<byte>(Value >> 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
		Output[OutOffset + 4] = static_cast<byte>(Value >> 32);
		Output[OutOffset + 5] = static_cast<byte>(Value >> 40);
		Output[OutOffset + 6] = static_cast<byte>(Value >> 48);
		Output[OutOffset + 7] = static_cast<byte>(Value >> 56);
	}
#else
	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline ushort BytesToWord16(const std::vector<byte> &Input)
	{
		return
			(static_cast<ushort>(Input[1]) |
			(static_cast<ushort>(Input[0] << 8)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline ushort BytesToWord16(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			(static_cast<ushort>(Input[InOffset + 1]) |
			(static_cast<ushort>(Input[InOffset] << 8)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input)
	{
		return
			(static_cast<uint>(Input[3]) |
			(static_cast<uint>(Input[2] << 8)) |
			(static_cast<uint>(Input[1] << 16)) |
			(static_cast<uint>(Input[0] << 24)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			(static_cast<uint>(Input[InOffset + 3]) |
			(static_cast<uint>(Input[InOffset + 2] << 8)) |
			(static_cast<uint>(Input[InOffset + 1] << 16)) |
			(static_cast<uint>(Input[InOffset] << 24)));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input)
	{
		return
			((ulong)Input[7]) |
			((ulong)Input[6] << 8) |
			((ulong)Input[5] << 16) |
			((ulong)Input[4] << 24) |
			((ulong)Input[3] << 32) |
			((ulong)Input[2] << 40) |
			((ulong)Input[1] << 48) |
			((ulong)Input[0] << 56);
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input, const size_t InOffset)
	{
		return
			((ulong)Input[InOffset + 7]) |
			((ulong)Input[InOffset + 6] << 8) |
			((ulong)Input[InOffset + 5] << 16) |
			((ulong)Input[InOffset + 4] << 24) |
			((ulong)Input[InOffset + 3] << 32) |
			((ulong)Input[InOffset + 2] << 40) |
			((ulong)Input[InOffset + 1] << 48) |
			((ulong)Input[InOffset] << 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word16ToBytes(const ushort Value, std::vector<byte> &Output)
	{
		Output[1] = static_cast<byte>(Value);
		Output[0] = static_cast<byte>(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset + 1] = static_cast<byte>(Value);
		Output[OutOffset] = static_cast<byte>(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output)
	{
		Output[3] = static_cast<byte>(Value);
		Output[2] = static_cast<byte>(Value >> 8);
		Output[1] = static_cast<byte>(Value >> 16);
		Output[0] = static_cast<byte>(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset + 3] = static_cast<byte>(Value);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
		Output[OutOffset] = static_cast<byte>(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output)
	{
		Output[7] = static_cast<byte>(Value);
		Output[6] = static_cast<byte>(Value >> 8);
		Output[5] = static_cast<byte>(Value >> 16);
		Output[4] = static_cast<byte>(Value >> 24);
		Output[3] = static_cast<byte>(Value >> 32);
		Output[2] = static_cast<byte>(Value >> 40);
		Output[1] = static_cast<byte>(Value >> 48);
		Output[0] = static_cast<byte>(Value >> 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
	{
		Output[OutOffset + 7] = static_cast<byte>(Value);
		Output[OutOffset + 6] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 5] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 4] = static_cast<byte>(Value >> 24);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 32);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 40);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 48);
		Output[OutOffset] = static_cast<byte>(Value >> 56);
	}
#endif

	template <typename T>
	/// <summary>
	/// Clear nested arrays of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	static inline void ClearArray(std::vector<std::vector<T>> &Obj)
	{
		if (Obj.size() == 0)
			return;

		for (size_t i = 0; i < Obj.size(); i++)
			ClearVector(Obj[i]);

		Obj.clear();
	}
    
	/// <summary>
	/// Clear an array of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	template <typename T>
	static void ClearVector(std::vector<T> &Obj)
	{
		if (Obj.capacity() == 0)
			return;

		static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
		memset_v(Obj.data(), 0, Obj.size() * sizeof(T));
		Obj.clear();
	}

	/// <summary>
	/// Crop a 64 bit integer value
	/// </summary>
	///
	/// <param name="Value">The initial value</param>
	/// <param name="Size">The number of bits in the new integer</param>
	/// 
	/// <returns>The cropped integer</returns>
	static ulong Crop(ulong Value, uint Size);

	template <class T>
	/// <summary>
	/// Get a byte from an integer
	/// </summary>
	///
	/// <param name="Value">The integer value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The cropped integer</returns>
	static inline byte GetByte(T Value, uint Shift)
	{
#ifdef IS_LITTLE_ENDIAN
		return GETBYTE(Value, Shift);
#else
		return GETBYTE(Value, sizeof(T) - Shift - 1);
#endif
	}

	template <class T>
	/// <summary>
	/// Test for power of 2
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>True if the value is a power of 2</returns>
	static inline bool IsPowerOf2(T Value)
	{
		return Value > 0 && (Value & (Value - 1)) == 0;
	}

	template <class T>
	/// <summary>
	/// Return the smaller of two values
	/// </summary>
	/// 
	/// <param name="A">The first comparison value</param>
	/// <param name="B">The second comparison value</param>
	/// 
	/// <returns>The smaller value</returns>
	static inline T Min(T A, T B)
	{
		return ((A) < (B) ? (A) : (B));
	}

	template <class T1, class T2>
	/// <summary>
	/// Mod a power of two integer
	/// </summary>
	/// 
	/// <param name="A">The initial value</param>
	/// <param name="B">The modulus</param>
	/// 
	/// <returns>The new value</returns>
	static inline T2 ModPowerOf2(T1 A, T2 B)
	{
		assert(IsPowerOf2(B));
		return T2(A) & (B - 1);
	}

	/// <summary>
	/// Get the parity bit from a 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The parity value</returns>
	static uint Parity(ulong Value);

	// ** Rotate ** //

#if defined(HAS_MINSSE) && defined(FORCE_ROTATION_INTRENSICS)
#pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateLeft(uint Value, uint Shift)
	{
		return Shift ? _rotl(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateLeft64(ulong Value, uint Shift)
	{
		return Shift ? _rotl64(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift a 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateRight(uint Value, uint Shift)
	{
		return Shift ? _rotr(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline ulong RotateRight64(ulong Value, uint Shift)
	{
		return Shift ? _rotr64(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Y">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateFixLeft(uint Value, uint Shift)
	{
		return _lrotl(Value, Shift);
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateFixLeft64(ulong Value, uint Shift)
	{
		return _rotl64(Value, Shift);
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateFixRight(uint Value, uint Shift)
	{
		return _lrotr(Value, Shift);
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotateFixRight64(ulong Value, uint Shift)
	{
		return _rotr64(Value, Shift);
	}

#elif defined(PPC_INTRINSICS) && defined(FORCE_ROTATION_INTRENSICS)
	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateLeft(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateLeft64(ulong Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 63) : Value;
	}

	/// <summary>
	/// Rotate shift a 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateRight(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
	}

	/// <summary>
	/// Rotate shift a 64 bit long integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline ulong RotateRight64(ulong Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, 64 - Shift, 0, 63) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateFixLeft(uint Value, uint Shift)
	{
		return __rlwinm(Value, Shift, 0, 31);
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateFixLeft64(ulong Value, uint Shift)
	{
		return (Value << Shift) | ((long)((ulong)Value >> -Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateFixRight(uint Value, uint Shift)
	{
		return __rlwinm(Value, 32 - Shift, 0, 31);
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotateFixRight64(ulong Value, uint Shift)
	{
		return ((Value >> Shift) | (Value << (64 - Shift)));
	}

#else
	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateLeft(uint Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateLeft64(ulong Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(ulong) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift a 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateRight(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift a 64 bit long integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline ulong RotateRight64(ulong Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(ulong) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateFixLeft(uint Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotateFixLeft64(ulong Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (64 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotateFixRight(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotateFixRight64(ulong Value, uint Shift)
	{
		return ((Value >> Shift) | (Value << (64 - Shift)));
	}
#endif

	// ** Little Endian Aligned Conversions ** //

	/// <summary>
	/// Copy an unsigned short to bytes
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static inline std::vector<byte> ToBit16(ushort Value)
	{
		std::vector<byte> data(2);
		Le16ToBytes(Value, data, 0);
		return data;	
	}

	/// <summary>
	/// Copy an unsigned int to bytes
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static inline std::vector<byte> ToBit32(uint Value)
	{
		std::vector<byte> data(4);
		Le32ToBytes(Value, data, 0);
		return data;
	}

	/// <summary>
	/// Copy an unsigned long to bytes
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The value copied to a byte array</returns>
	static inline std::vector<byte> ToBit64(ulong Value)
	{
		std::vector<byte> data(8);
		Le64ToBytes(Value, data, 0);
		return data;
	}

	/// <summary>
	/// Copy bytes to an unsigned short
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static inline ushort ToInt16(std::vector<byte> Input)
	{
		return BytesToLe16(Input, 0);
	}

	/// <summary>
	/// Copy bytes to an unsigned int
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 32 bit integer</returns>
	static inline uint ToInt32(std::vector<byte> Input)
	{
		return BytesToLe32(Input, 0);
	}

	/// <summary>
	/// Copy bytes to an unsigned long
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 64 bit integer</returns>
	static inline ulong ToInt64(std::vector<byte> Input)
	{
		return BytesToLe64(Input, 0);
	}

	/// <summary>
	/// Copy bytes to an unsigned short
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static inline ushort ToInt16(std::vector<byte> Input, size_t InOffset)
	{
		return BytesToLe16(Input, InOffset);
	}

	/// <summary>
	/// Copy bytes to an unsigned int
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 32bit integer</returns>
	static inline uint ToInt32(std::vector<byte> Input, size_t InOffset)
	{
		return BytesToLe32(Input, InOffset);
	}

	/// <summary>
	/// Copy bytes to an unsigned long
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 64 bit integer</returns>
	static inline ulong ToInt64(std::vector<byte> Input, size_t InOffset)
	{
		return BytesToLe64(Input, InOffset);
	}

	template<typename T>
	/// <summary>
	/// Convert an integer to a string
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The string representation</returns>
	static inline std::string ToString(const T& Value)
	{
		std::ostringstream oss;
		oss << Value;
		return oss.str();
	}

	/// <summary>
	/// Convert an array of 64 bit words into a byte array
	/// </summary>
	/// 
	/// <param name="Input">The input integer array</param>
	/// <param name="Output">The output byte array</param>
	static inline void Word64sToBytes(const std::vector<ulong> &Input, std::vector<byte> &Output)
	{
		if (Output.size() != Input.size() * sizeof(ulong))
			Output.resize(Input.size() * sizeof(ulong), 0);
		memcpy(&Output[0], &Input[0], Output.size());
	}

	/// <summary>
	/// Convert an array of 64 bit words into a byte array
	/// </summary>
	/// 
	/// <param name="Input">The input integer array</param>
	/// <param name="InOffset">The input arrays starting offset</param>
	/// <param name="Length">The number of bytes to return</param>
	/// <param name="Output">The input integer array</param>
	static inline void BytesToWord64s(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<ulong> &Output)
	{
		if (Output.size() != (Input.size() - InOffset) * sizeof(ulong))
			Output.resize(Length / sizeof(ulong));
		memcpy(&Output[0], &Input[InOffset], Length);
	}

	// ** Block XOR ** //

	/// <summary>
	/// Block XOR 16 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Block XOR 32 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR256(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// XOR contiguous 16 byte blocks in an array.
	/// <para>The array must be aligned to 16</para>
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	/// <param name="Size">The number of (16 byte block aligned) bytes to process</param>
	static void XORBLK(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Size);
};

NAMESPACE_UTILITYEND
#endif

