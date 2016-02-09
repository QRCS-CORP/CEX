#ifndef _CEXENGINE_INTUTILS_H
#define _CEXENGINE_INTUTILS_H

#include "Common.h"
#include <sstream>

#ifdef INTEL_INTRINSICS
#include <stdlib.h>
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
	static unsigned int BitPrecision(ulong Value);

	/// <summary>
	/// Reverse a byte
	/// </summary>
	/// 
	/// <param name="Value">Initial value</param>
	/// 
	/// <returns>The revered byte</returns>
	static inline byte BitReverse(byte Value)
	{
		Value = ((Value & 0xAA) >> 1) | ((Value & 0x55) << 1);
		Value = ((Value & 0xCC) >> 2) | ((Value & 0x33) << 2);
		return (byte)RotlFixed(Value, 4);
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
	static unsigned int BytePrecision(ulong Value);

	/// <summary>
	/// Reverse a 16 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The reversed ushort</returns>
	static inline ushort ByteReverse(ushort Value)
	{
		return (ushort)RotlFixed(Value, 8U);
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
		return (RotrFixed(Value, 8U) & 0xff00ff00) | (RotlFixed(Value, 8U) & 0x00ff00ff);
#else
		// 6 instructions with rotate instruction, 8 without
		Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
		return RotlFixed(Value, 16U);
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
		return (uint)__lwbrx(&Value, 0);
#elif defined(FAST_ROTATE)
		// 5 instructions with rotate instruction, 9 without
		return (RotrFixed64(Value, 8U) & 0xff00ff00) | (RotlFixed64(Value, 8U) & 0x00ff00ff);
#else
		// 6 instructions with rotate instruction, 8 without
		Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
		return RotlFixed(Value, 16U);
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
	static inline void Be16ToBytes(const ushort Value, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset + 1] = (byte)Value;
		Output[OutOffset] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a Big Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static inline void Be32ToBytes(const uint Value, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset + 3] = (byte)Value;
		Output[OutOffset + 2] = (byte)(Value >> 8);
		Output[OutOffset + 1] = (byte)(Value >> 16);
		Output[OutOffset] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a Big Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	static inline void Be64ToBytes(const ulong Value, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset + 7] = (byte)Value;
		Output[OutOffset + 6] = (byte)(Value >> 8);
		Output[OutOffset + 5] = (byte)(Value >> 16);
		Output[OutOffset + 4] = (byte)(Value >> 24);
		Output[OutOffset + 3] = (byte)(Value >> 32);
		Output[OutOffset + 2] = (byte)(Value >> 40);
		Output[OutOffset + 1] = (byte)(Value >> 48);
		Output[OutOffset] = (byte)(Value >> 56);
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Big Endian format</returns>
	static inline ushort BytesToBe16(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ushort)Input[InOffset] << 8) |
			((ushort)Input[InOffset + 1]);
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Big Endian format</returns>
	static inline uint BytesToBe32(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((uint)Input[InOffset] << 24) |
			((uint)Input[InOffset + 1] << 16) |
			((uint)Input[InOffset + 2] << 8) |
			((uint)Input[InOffset + 3]);
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Big Endian format</returns>
	static inline ulong BytesToBe64(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ulong)Input[InOffset] << 56) |
			((ulong)Input[InOffset + 1] << 48) |
			((ulong)Input[InOffset + 2] << 40) |
			((ulong)Input[InOffset + 3] << 32) |
			((ulong)Input[InOffset + 4] << 24) |
			((ulong)Input[InOffset + 5] << 16) |
			((ulong)Input[InOffset + 6] << 8) |
			((ulong)Input[InOffset + 7]);
	}

	// ** Little Endian ** //

	/// <summary>
	/// Convert a Little Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le16ToBytes(const ushort Value, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset] = (byte)Value;
		Output[OutOffset + 1] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a Little Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le32ToBytes(const uint Value, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset] = (byte)Value;
		Output[OutOffset + 1] = (byte)(Value >> 8);
		Output[OutOffset + 2] = (byte)(Value >> 16);
		Output[OutOffset + 3] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a Little Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="DWord">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Le64ToBytes(const ulong DWord, std::vector<byte> &Output, const uint OutOffset)
	{
		Output[OutOffset] = (byte)DWord;
		Output[OutOffset + 1] = (byte)(DWord >> 8);
		Output[OutOffset + 2] = (byte)(DWord >> 16);
		Output[OutOffset + 3] = (byte)(DWord >> 24);
		Output[OutOffset + 4] = (byte)(DWord >> 32);
		Output[OutOffset + 5] = (byte)(DWord >> 40);
		Output[OutOffset + 6] = (byte)(DWord >> 48);
		Output[OutOffset + 7] = (byte)(DWord >> 56);
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Little Endian format</returns>
	static inline ushort BytesToLe16(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ushort)Input[InOffset] |
			((ushort)Input[InOffset + 1] << 8));
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Little Endian format</returns>
	static inline uint BytesToLe32(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((uint)Input[InOffset] |
			((uint)Input[InOffset + 1] << 8) |
			((uint)Input[InOffset + 2] << 16) |
			((uint)Input[InOffset + 3] << 24));
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Little Endian format</returns>
	static inline ulong BytesToLe64(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ulong)Input[InOffset] |
			((ulong)Input[InOffset + 1] << 8) |
			((ulong)Input[InOffset + 2] << 16) |
			((ulong)Input[InOffset + 3] << 24) |
			((ulong)Input[InOffset + 4] << 32) |
			((ulong)Input[InOffset + 5] << 40) |
			((ulong)Input[InOffset + 6] << 48) |
			((ulong)Input[InOffset + 7] << 56));
	}

#if defined(IS_LITTLE_ENDIAN)
	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline unsigned short BytesToWord16(const std::vector<byte> &Input)
	{
		return
			((unsigned short)Input[0] |
			((unsigned short)Input[1] << 8));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline unsigned short BytesToWord16(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((unsigned short)Input[InOffset] |
			((unsigned short)Input[InOffset + 1] << 8));
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
			((uint)Input[0] |
			((uint)Input[1] << 8) |
			((uint)Input[2] << 16) |
			((uint)Input[3] << 24));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((uint)Input[InOffset] |
			((uint)Input[InOffset + 1] << 8) |
			((uint)Input[InOffset + 2] << 16) |
			((uint)Input[InOffset + 3] << 24));
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
			((ulong)Input[0] |
			((ulong)Input[1] << 8) |
			((ulong)Input[2] << 16) |
			((ulong)Input[3] << 24) |
			((ulong)Input[4] << 32) |
			((ulong)Input[5] << 40) |
			((ulong)Input[6] << 48) |
			((ulong)Input[7] << 56));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ulong)Input[InOffset] |
			((ulong)Input[InOffset + 1] << 8) |
			((ulong)Input[InOffset + 2] << 16) |
			((ulong)Input[InOffset + 3] << 24) |
			((ulong)Input[InOffset + 4] << 32) |
			((ulong)Input[InOffset + 5] << 40) |
			((ulong)Input[InOffset + 6] << 48) |
			((ulong)Input[InOffset + 7] << 56));
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word16ToBytes(const unsigned short Value, std::vector<byte> &Output)
	{
		Output[0] = (byte)Value;
		Output[1] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word16ToBytes(const unsigned short Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset] = (byte)Value;
		Output[OutOffset + 1] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output)
	{
		Output[0] = (byte)Value;
		Output[1] = (byte)(Value >> 8);
		Output[2] = (byte)(Value >> 16);
		Output[3] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset] = (byte)Value;
		Output[OutOffset + 1] = (byte)(Value >> 8);
		Output[OutOffset + 2] = (byte)(Value >> 16);
		Output[OutOffset + 3] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output)
	{
		Output[0] = (byte)Value;
		Output[1] = (byte)(Value >> 8);
		Output[2] = (byte)(Value >> 16);
		Output[3] = (byte)(Value >> 24);
		Output[4] = (byte)(Value >> 32);
		Output[5] = (byte)(Value >> 40);
		Output[6] = (byte)(Value >> 48);
		Output[7] = (byte)(Value >> 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset] = (byte)Value;
		Output[OutOffset + 1] = (byte)(Value >> 8);
		Output[OutOffset + 2] = (byte)(Value >> 16);
		Output[OutOffset + 3] = (byte)(Value >> 24);
		Output[OutOffset + 4] = (byte)(Value >> 32);
		Output[OutOffset + 5] = (byte)(Value >> 40);
		Output[OutOffset + 6] = (byte)(Value >> 48);
		Output[OutOffset + 7] = (byte)(Value >> 56);
	}
#else
	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// 
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline unsigned short BytesToWord16(const std::vector<byte> &Input)
	{
		return
			((unsigned short)Input[1] |
			((unsigned short)Input[0] << 8));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 16 bit word in native Endian format</returns>
	static inline unsigned short BytesToWord16(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((unsigned short)Input[InOffset + 1] |
			((unsigned short)Input[InOffset] << 8));
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
			((uint)Input[3] |
			((uint)Input[2] << 8) |
			((uint)Input[1] << 16) |
			((uint)Input[0] << 24));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 32 bit word in native Endian format</returns>
	static inline uint BytesToWord32(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((uint)Input[InOffset + 3] |
			((uint)Input[InOffset + 2] << 8) |
			((uint)Input[InOffset + 1] << 16) |
			((uint)Input[InOffset] << 24));
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
			((ulong)Input[7] |
			((ulong)Input[6] << 8) |
			((ulong)Input[5] << 16) |
			((ulong)Input[4] << 24) |
			((ulong)Input[3] << 32) |
			((ulong)Input[2] << 40) |
			((ulong)Input[1] << 48) |
			((ulong)Input[0] << 56));
	}

	/// <summary>
	/// Convert a byte array to a system aligned 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">InOffset within the source array</param>
	///
	/// <returns>A 64 bit word in native Endian format</returns>
	static inline ulong BytesToWord64(const std::vector<byte> &Input, const uint InOffset)
	{
		return
			((ulong)Input[InOffset + 7] |
			((ulong)Input[InOffset + 6] << 8) |
			((ulong)Input[InOffset + 5] << 16) |
			((ulong)Input[InOffset + 4] << 24) |
			((ulong)Input[InOffset + 3] << 32) |
			((ulong)Input[InOffset + 2] << 40) |
			((ulong)Input[InOffset + 1] << 48) |
			((ulong)Input[InOffset] << 56));
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word16ToBytes(const unsigned short Value, std::vector<byte> &Output)
	{
		Output[1] = (byte)Value;
		Output[0] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word16ToBytes(const unsigned short Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset + 1] = (byte)Value;
		Output[OutOffset] = (byte)(Value >> 8);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output)
	{
		Output[3] = (byte)Value;
		Output[2] = (byte)(Value >> 8);
		Output[1] = (byte)(Value >> 16);
		Output[0] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word32ToBytes(const uint Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset + 3] = (byte)Value;
		Output[OutOffset + 2] = (byte)(Value >> 8);
		Output[OutOffset + 1] = (byte)(Value >> 16);
		Output[OutOffset] = (byte)(Value >> 24);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64 bit word</param>
	/// <param name="Output">The destination bytes</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output)
	{
		Output[7] = (byte)Value;
		Output[6] = (byte)(Value >> 8);
		Output[5] = (byte)(Value >> 16);
		Output[4] = (byte)(Value >> 24);
		Output[3] = (byte)(Value >> 32);
		Output[2] = (byte)(Value >> 40);
		Output[1] = (byte)(Value >> 48);
		Output[0] = (byte)(Value >> 56);
	}

	/// <summary>
	/// Convert a system aligned Endian 64 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	static inline void Word64ToBytes(const ulong Value, std::vector<byte> &Output, uint OutOffset)
	{
		Output[OutOffset + 7] = (byte)Value;
		Output[OutOffset + 6] = (byte)(Value >> 8);
		Output[OutOffset + 5] = (byte)(Value >> 16);
		Output[OutOffset + 4] = (byte)(Value >> 24);
		Output[OutOffset + 3] = (byte)(Value >> 32);
		Output[OutOffset + 2] = (byte)(Value >> 40);
		Output[OutOffset + 1] = (byte)(Value >> 48);
		Output[OutOffset] = (byte)(Value >> 56);
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
		for (unsigned int i = 0; i < Obj.size(); i++)
		{
			if (Obj[i].capacity() > 0)
				memset(Obj[i].data(), 0, Obj[i].capacity() * sizeof(T));
            
			Obj[i].clear();
		}
		Obj.clear();
	}
    
	template <typename T>
	/// <summary>
	/// Clear an array of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	static void ClearVector(std::vector<T> &Obj)
	{
		if (Obj.capacity() > 0)
			memset(Obj.data(), 0, Obj.capacity() * sizeof(T));
        
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
	static ulong Crop(ulong Value, unsigned int Size);

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

	/// <summary>
	/// Return the smaller of two values
	/// </summary>
	/// 
	/// <param name="A">The first comparison value</param>
	/// <param name="B">The second comparison value</param>
	/// 
	/// <returns>The smaller value</returns>
	static inline uint Min(uint A, uint B)
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
	static unsigned int Parity(ulong Value);

	// ** Rotate ** //

#if defined(INTEL_INTRINSICS)
#pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateLeft(uint Value, int Shift)
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
	static inline ulong RotateLeft(ulong Value, int Shift)
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
	static inline uint RotateRight(uint Value, int Shift)
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
	static inline ulong RotateRight(ulong Value, int Shift)
	{
		return Shift ? _rotr64(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Y">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotlFixed(uint Value, uint Shift)
	{
		return Shift ? _lrotl(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotrFixed(uint Value, uint Shift)
	{
		return Shift ? _lrotr(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotlFixed64(ulong Value, int Shift)
	{
		return Shift ? _rotl64(Value, Shift) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotrFixed64(ulong Value, int Shift)
	{
		return Shift ? _rotr64(Value, Shift) : Value;
	}

#elif defined(PPC_INTRINSICS)
	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline uint RotateLeft(uint Value, int Shift)
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
	static inline ulong RotateLeft(ulong Value, int Shift)
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
	static inline uint RotateRight(uint Value, int Shift)
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
	static inline ulong RotateRight(ulong Value, int Shift)
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
	static inline uint RotlFixed(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotrFixed(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotlFixed64(ulong Value, int Shift)
	{
		return (Value << Shift) | ((long)((ulong)Value >> -Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotrFixed64(ulong Value, int Shift)
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
	static inline uint RotateLeft(uint Value, int Shift)
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
	static inline ulong RotateLeft(ulong Value, int Shift)
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
	static inline uint RotateRight(uint Value, int Shift)
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
	static inline ulong RotateRight(ulong Value, int Shift)
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
	static inline uint RotlFixed(uint Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	static inline uint RotrFixed(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	static inline ulong RotlFixed64(ulong Value, int Shift)
	{
		return (Value << Shift) | ((long)((ulong)Value >> -Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	static inline ulong RotrFixed64(ulong Value, int Shift)
	{
		return ((Value >> Shift) | (Value << (64 - Shift)));
	}
#endif

	// ** Little Endian Aligned Conversions ** //

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns></returns>
	static inline std::vector<byte> ToBit16(unsigned short Value)
	{
		std::vector<byte> data(2);
		Le16ToBytes(Value, data, 0);
		return data;	
	}

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns></returns>
	static inline std::vector<byte> ToBit32(uint Value)
	{
		std::vector<byte> data(4);
		Le32ToBytes(Value, data, 0);
		return data;
	}

	/// <summary>
	/// 
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns></returns>
	static inline std::vector<byte> ToBit64(ulong Value)
	{
		std::vector<byte> data(8);
		Le64ToBytes(Value, data, 0);
		return data;
	}

	template<typename T>
	/// <summary>
	/// Convert an integer to a char array
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The char array</returns>
	static inline char* ToChar(const T& Value)
	{
		std::ostringstream oss;
		oss << Value;
		return oss.str().c_str();
	}

	/// <summary>
	/// Convert bytes to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static inline unsigned short ToInt16(std::vector<byte> Input)
	{
		return BytesToLe16(Input, 0);
	}

	/// <summary>
	/// Convert bytes to a Little Endian 32 bit word
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
	/// Convert bytes to a Little Endian 64 bit word
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
	/// Convert bytes to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 16 bit integer</returns>
	static inline unsigned short ToInt16(std::vector<byte> Input, uint InOffset)
	{
		return BytesToLe16(Input, InOffset);
	}

	/// <summary>
	/// Convert bytes to a Little Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 32bit integer</returns>
	static inline uint ToInt32(std::vector<byte> Input, uint InOffset)
	{
		return BytesToLe32(Input, InOffset);
	}

	/// <summary>
	/// Convert bytes to a Little Endian 64 bit word
	/// </summary>
	/// 
	/// <param name="Input">The input bytes</param>
	/// <param name="InOffset">The starting offset within the input array</param>
	/// 
	/// <returns>The 64 bit integer</returns>
	static inline ulong ToInt64(std::vector<byte> Input, uint InOffset)
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
	static inline void BytesToWord64s(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length, std::vector<ulong> &Output)
	{
		if (Output.size() != (Input.size() - InOffset) * sizeof(ulong))
			Output.resize(Length / sizeof(ulong));
		memcpy(&Output[0], &Input[InOffset], Length);
	}

	// ** Block XOR ** //

	/// <summary>
	/// Block XOR 4 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR32(const byte* &Input, byte* &Output);

	/// <summary>
	/// Block XOR 4 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR32(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Block XOR 4 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR32(const std::vector<byte> &Input, const uint InOffset, std::vector<byte> &Output, const uint OutOffset);

	/// <summary>
	/// Block XOR 8 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Block XOR 8 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR64(const byte* &Input, byte* &Output);

	/// <summary>
	/// Block XOR 8 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR64(const std::vector<byte> &Input, const uint InOffset, std::vector<byte> &Output, const uint OutOffset);

	/// <summary>
	/// Block XOR 16 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Block XOR 16 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR128(const byte* &Input, byte* &Output);

	/// <summary>
	/// Block XOR 16 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR128(const std::vector<byte> &Input, const uint InOffset, std::vector<byte> &Output, const uint OutOffset);

	/// <summary>
	/// Block XOR 32 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR256(const byte* &Input, byte* &Output);

	/// <summary>
	/// Block XOR 32 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	static void XOR256(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Block XOR 32 bytes
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">Offset within the destination array</param>
	static void XOR256(const std::vector<byte> &Input, const uint InOffset, std::vector<byte> &Output, const uint OutOffset);

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
	static void XORBLK(const std::vector<byte> &Input, const uint InOffset, std::vector<byte> &Output, const uint OutOffset, const uint Size);
};

NAMESPACE_UTILITYEND
#endif

