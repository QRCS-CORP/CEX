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
	// ** Misc Bits ** //
	static unsigned int BitPrecision(ulong Value);

	static inline byte BitReverse(byte Value)
	{
		Value = ((Value & 0xAA) >> 1) | ((Value & 0x55) << 1);
		Value = ((Value & 0xCC) >> 2) | ((Value & 0x33) << 2);
		return (byte)RotlFixed(Value, 4);
	}

	static inline ushort BitReverse(ushort Value)
	{
		Value = ((Value & 0xAAAA) >> 1) | ((Value & 0x5555) << 1);
		Value = ((Value & 0xCCCC) >> 2) | ((Value & 0x3333) << 2);
		Value = ((Value & 0xF0F0) >> 4) | ((Value & 0x0F0F) << 4);
		return ByteReverse(Value);
	}

	static inline uint BitReverse(uint Value)
	{
		Value = ((Value & 0xAAAAAAAA) >> 1) | ((Value & 0x55555555) << 1);
		Value = ((Value & 0xCCCCCCCC) >> 2) | ((Value & 0x33333333) << 2);
		Value = ((Value & 0xF0F0F0F0) >> 4) | ((Value & 0x0F0F0F0F) << 4);
		return ByteReverse(Value);
	}

#ifdef WORD64_AVAILABLE
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

	template <class T>
	static inline T BitReverse(T Value)
	{
		if (sizeof(T) == 1)
			return (T)BitReverse((byte)Value);
		else if (sizeof(T) == 2)
			return (T)BitReverse((ushort)Value);
		else if (sizeof(T) == 4)
			return (T)BitReverse((uint)Value);
		else
		{
#ifdef WORD64_AVAILABLE
			return (T)BitReverse((ulong)Value);
#else
			return 0;
#endif
		}
	}

	static inline uint BitsToBytes(uint BitCount)
	{
		return ((BitCount + 7) / (8));
	}

	static inline uint BitsToWords(uint BitCount)
	{
		return ((BitCount + WORD_BITS - 1) / (WORD_BITS));
	}

	// ** Misc Byte ** //

	static unsigned int BytePrecision(ulong Value);

	static inline byte ByteReverse(byte Value)
	{
		return Value;
	}

	static inline ushort ByteReverse(ushort Value)
	{
		return (ushort)RotlFixed(Value, 8U);
	}

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

	static inline uint ByteReverse(ulong Value)
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

	static inline uint BytesToWords(uint byteCount)
	{
		return ((byteCount + WORD_SIZE - 1) / WORD_SIZE);
	}

	// Different computer architectures store data using different byte orders. "Big-endian"
	// means the most significant byte is on the left end of a word. "Little-endian" means the 
	// most significant byte is on the right end of a word. i.e.: 
	// BE: uint(block[3]) | (uint(block[2]) << 8) | (uint(block[1]) << 16) | (uint(block[0]) << 24)
	// LE: uint(block[0]) | (uint(block[1]) << 8) | (uint(block[2]) << 16) | (uint(block[3]) << 24)

	// ** Big Endian ** //
	static inline void Be16ToBytes(const ushort Word, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset + 1] = (byte)Word;
		Block[Offset] = (byte)(Word >> 8);
	}

	/// <summary>
	/// Convert a Big Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Word">The 32 bit word</param>
	/// <param name="Block">The destination bytes</param>
	/// <param name="Offset">Offset within the destination array</param>
	static inline void Be32ToBytes(const uint Word, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset + 3] = (byte)Word;
		Block[Offset + 2] = (byte)(Word >> 8);
		Block[Offset + 1] = (byte)(Word >> 16);
		Block[Offset] = (byte)(Word >> 24);
	}

	/// <summary>
	/// Convert a Big Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Word">The 64 bit word</param>
	/// <param name="Block">The destination bytes</param>
	/// <param name="Offset">Offset within the destination array</param>
	static inline void Be64ToBytes(const ulong DWord, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset + 7] = (byte)DWord;
		Block[Offset + 6] = (byte)(DWord >> 8);
		Block[Offset + 5] = (byte)(DWord >> 16);
		Block[Offset + 4] = (byte)(DWord >> 24);
		Block[Offset + 3] = (byte)(DWord >> 32);
		Block[Offset + 2] = (byte)(DWord >> 40);
		Block[Offset + 1] = (byte)(DWord >> 48);
		Block[Offset] = (byte)(DWord >> 56);
	}

	static inline ushort BytesToBe16(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((ushort)Block[InOffset] << 8) |
			((ushort)Block[InOffset + 1]);
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Block">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Big Endian format</returns>
	static inline uint BytesToBe32(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((uint)Block[InOffset] << 24) |
			((uint)Block[InOffset + 1] << 16) |
			((uint)Block[InOffset + 2] << 8) |
			((uint)Block[InOffset + 3]);
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Block">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Big Endian format</returns>
	static inline ulong BytesToBe64(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((ulong)Block[InOffset] << 56) |
			((ulong)Block[InOffset + 1] << 48) |
			((ulong)Block[InOffset + 2] << 40) |
			((ulong)Block[InOffset + 3] << 32) |
			((ulong)Block[InOffset + 4] << 24) |
			((ulong)Block[InOffset + 5] << 16) |
			((ulong)Block[InOffset + 6] << 8) |
			((ulong)Block[InOffset + 7]);
	}

	// ** Little Endian ** //
	static inline void Le16ToBytes(const ushort Word, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset] = (byte)Word;
		Block[Offset + 1] = (byte)(Word >> 8);
	}

	/// <summary>
	/// Convert a Litthle Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Word">The 32 bit word</param>
	/// <param name="Block">The destination bytes</param>
	/// <param name="Offset">Offset within the destination block</param>
	static inline void Le32ToBytes(const uint Word, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset] = (byte)Word;
		Block[Offset + 1] = (byte)(Word >> 8);
		Block[Offset + 2] = (byte)(Word >> 16);
		Block[Offset + 3] = (byte)(Word >> 24);
	}

	/// <summary>
	/// Convert a Little Endian 64 bit dword to bytes
	/// </summary>
	/// 
	/// <param name="DWord">The 64 bit word</param>
	/// <param name="Block">The destination bytes</param>
	/// <param name="Offset">Offset within the destination block</param>
	static inline void Le64ToBytes(const ulong DWord, std::vector<byte> &Block, const uint Offset)
	{
		Block[Offset] = (byte)DWord;
		Block[Offset + 1] = (byte)(DWord >> 8);
		Block[Offset + 2] = (byte)(DWord >> 16);
		Block[Offset + 3] = (byte)(DWord >> 24);
		Block[Offset + 4] = (byte)(DWord >> 32);
		Block[Offset + 5] = (byte)(DWord >> 40);
		Block[Offset + 6] = (byte)(DWord >> 48);
		Block[Offset + 7] = (byte)(DWord >> 56);
	}

	static inline ushort BytesToLe16(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((ushort)Block[InOffset] |
			((ushort)Block[InOffset + 1] << 8));
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 32 bit word
	/// </summary>
	/// 
	/// <param name="Block">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 32 bit word in Little Endian format</returns>
	static inline uint BytesToLe32(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((uint)Block[InOffset] |
			((uint)Block[InOffset + 1] << 8) |
			((uint)Block[InOffset + 2] << 16) |
			((uint)Block[InOffset + 3] << 24));
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 64 bit dword
	/// </summary>
	/// 
	/// <param name="Block">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 64 bit word in Little Endian format</returns>
	static inline ulong BytesToLe64(const std::vector<byte> &Block, const uint InOffset)
	{
		return
			((ulong)Block[InOffset] |
			((ulong)Block[InOffset + 1] << 8) |
			((ulong)Block[InOffset + 2] << 16) |
			((ulong)Block[InOffset + 3] << 24) |
			((ulong)Block[InOffset + 4] << 32) |
			((ulong)Block[InOffset + 5] << 40) |
			((ulong)Block[InOffset + 6] << 48) |
			((ulong)Block[InOffset + 7] << 56));
	}

#if defined(IS_LITTLE_ENDIAN)
	static inline unsigned short BytesToWord16(const std::vector<byte> &Block)
	{
		return
			((unsigned short)Block[0] |
			((unsigned short)Block[1] << 8));
	}

	static inline unsigned short BytesToWord16(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((unsigned short)Block[Offset] |
			((unsigned short)Block[Offset + 1] << 8));
	}

	static inline uint BytesToWord32(const std::vector<byte> &Block)
	{
		return
			((uint)Block[0] |
			((uint)Block[1] << 8) |
			((uint)Block[2] << 16) |
			((uint)Block[3] << 24));
	}

	static inline uint BytesToWord32(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((uint)Block[Offset] |
			((uint)Block[Offset + 1] << 8) |
			((uint)Block[Offset + 2] << 16) |
			((uint)Block[Offset + 3] << 24));
	}

	static inline ulong BytesToWord64(const std::vector<byte> &Block)
	{
		return
			((ulong)Block[0] |
			((ulong)Block[1] << 8) |
			((ulong)Block[2] << 16) |
			((ulong)Block[3] << 24) |
			((ulong)Block[4] << 32) |
			((ulong)Block[5] << 40) |
			((ulong)Block[6] << 48) |
			((ulong)Block[7] << 56));
	}

	static inline ulong BytesToWord64(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((ulong)Block[Offset] |
			((ulong)Block[Offset + 1] << 8) |
			((ulong)Block[Offset + 2] << 16) |
			((ulong)Block[Offset + 3] << 24) |
			((ulong)Block[Offset + 4] << 32) |
			((ulong)Block[Offset + 5] << 40) |
			((ulong)Block[Offset + 6] << 48) |
			((ulong)Block[Offset + 7] << 56));
	}

	static inline void Word16ToBytes(const unsigned short Word, std::vector<byte> &Block)
	{
		Block[0] = (byte)Word;
		Block[1] = (byte)(Word >> 8);
	}

	static inline void Word16ToBytes(const unsigned short Word, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset] = (byte)Word;
		Block[Offset + 1] = (byte)(Word >> 8);
	}

	static inline void Word32ToBytes(const uint Word, std::vector<byte> &Block)
	{
		Block[0] = (byte)Word;
		Block[1] = (byte)(Word >> 8);
		Block[2] = (byte)(Word >> 16);
		Block[3] = (byte)(Word >> 24);
	}

	static inline void Word32ToBytes(const uint Word, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset] = (byte)Word;
		Block[Offset + 1] = (byte)(Word >> 8);
		Block[Offset + 2] = (byte)(Word >> 16);
		Block[Offset + 3] = (byte)(Word >> 24);
	}

	static inline void Word64ToBytes(const ulong DWord, std::vector<byte> &Block)
	{
		Block[0] = (byte)DWord;
		Block[1] = (byte)(DWord >> 8);
		Block[2] = (byte)(DWord >> 16);
		Block[3] = (byte)(DWord >> 24);
		Block[4] = (byte)(DWord >> 32);
		Block[5] = (byte)(DWord >> 40);
		Block[6] = (byte)(DWord >> 48);
		Block[7] = (byte)(DWord >> 56);
	}

	static inline void Word64ToBytes(const ulong DWord, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset] = (byte)DWord;
		Block[Offset + 1] = (byte)(DWord >> 8);
		Block[Offset + 2] = (byte)(DWord >> 16);
		Block[Offset + 3] = (byte)(DWord >> 24);
		Block[Offset + 4] = (byte)(DWord >> 32);
		Block[Offset + 5] = (byte)(DWord >> 40);
		Block[Offset + 6] = (byte)(DWord >> 48);
		Block[Offset + 7] = (byte)(DWord >> 56);
	}
#else
	static inline unsigned short BytesToWord16(const std::vector<byte> &Block)
	{
		return
			((unsigned short)Block[1] |
			((unsigned short)Block[0] << 8));
	}

	static inline unsigned short BytesToWord16(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((unsigned short)Block[Offset + 1] |
			((unsigned short)Block[Offset] << 8));
	}

	static inline uint BytesToWord32(const std::vector<byte> &Block)
	{
		return
			((uint)Block[3] |
			((uint)Block[2] << 8) |
			((uint)Block[1] << 16) |
			((uint)Block[0] << 24));
	}

	static inline uint BytesToWord32(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((uint)Block[Offset + 3] |
			((uint)Block[Offset + 2] << 8) |
			((uint)Block[Offset + 1] << 16) |
			((uint)Block[Offset] << 24));
	}

	static inline ulong BytesToWord64(const std::vector<byte> &Block)
	{
		return
			((ulong)Block[7] |
			((ulong)Block[6] << 8) |
			((ulong)Block[5] << 16) |
			((ulong)Block[4] << 24) |
			((ulong)Block[3] << 32) |
			((ulong)Block[2] << 40) |
			((ulong)Block[1] << 48) |
			((ulong)Block[0] << 56));
	}

	static inline ulong BytesToWord64(const std::vector<byte> &Block, const uint Offset)
	{
		return
			((ulong)Block[Offset + 7] |
			((ulong)Block[Offset + 6] << 8) |
			((ulong)Block[Offset + 5] << 16) |
			((ulong)Block[Offset + 4] << 24) |
			((ulong)Block[Offset + 3] << 32) |
			((ulong)Block[Offset + 2] << 40) |
			((ulong)Block[Offset + 1] << 48) |
			((ulong)Block[Offset] << 56));
	}

	static inline void Word16ToBytes(const unsigned short Word, std::vector<byte> &Block)
	{
		Block[1] = (byte)Word;
		Block[0] = (byte)(Word >> 8);
	}

	static inline void Word16ToBytes(const unsigned short Word, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset + 1] = (byte)Word;
		Block[Offset] = (byte)(Word >> 8);
	}

	static inline void Word32ToBytes(const uint Word, std::vector<byte> &Block)
	{
		Block[3] = (byte)Word;
		Block[2] = (byte)(Word >> 8);
		Block[1] = (byte)(Word >> 16);
		Block[0] = (byte)(Word >> 24);
	}

	static inline void Word32ToBytes(const uint Word, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset + 3] = (byte)Word;
		Block[Offset + 2] = (byte)(Word >> 8);
		Block[Offset + 1] = (byte)(Word >> 16);
		Block[Offset] = (byte)(Word >> 24);
	}

	static inline void Word64ToBytes(const ulong DWord, std::vector<byte> &Block)
	{
		Block[7] = (byte)DWord;
		Block[6] = (byte)(DWord >> 8);
		Block[5] = (byte)(DWord >> 16);
		Block[4] = (byte)(DWord >> 24);
		Block[3] = (byte)(DWord >> 32);
		Block[2] = (byte)(DWord >> 40);
		Block[1] = (byte)(DWord >> 48);
		Block[0] = (byte)(DWord >> 56);
	}

	static inline void Word64ToBytes(const ulong DWord, std::vector<byte> &Block, uint Offset)
	{
		Block[Offset + 7] = (byte)DWord;
		Block[Offset + 6] = (byte)(DWord >> 8);
		Block[Offset + 5] = (byte)(DWord >> 16);
		Block[Offset + 4] = (byte)(DWord >> 24);
		Block[Offset + 3] = (byte)(DWord >> 32);
		Block[Offset + 2] = (byte)(DWord >> 40);
		Block[Offset + 1] = (byte)(DWord >> 48);
		Block[Offset] = (byte)(DWord >> 56);
	}
#endif

	/// <summary>
	/// Clear nested arrays of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	template <typename T>
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
    
	/// <summary>
	/// Clear an array of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	template <typename T>
	static void ClearVector(std::vector<T> &Obj)
	{
		if (Obj.capacity() > 0)
			memset(Obj.data(), 0, Obj.capacity() * sizeof(T));
        
		Obj.clear();
	}

	static ulong Crop(ulong Value, unsigned int size);

// this version of the macro is fastest on Pentium 3 and Pentium 4 with MSVC 6 SP5 w/ Processor Pack
#define GETBYTE(x, y) (uint)byte((x)>>(8*(y)))
// these may be faster on other CPUs/compilers
// #define GETBYTE(x, y) (uint)(((x)>>(8*(y)))&255)
// #define GETBYTE(x, y) (((byte *)&(x))[y])

	template <class T>
	static inline uint GetByte(T Value, uint index)
	{
#ifdef IS_LITTLE_ENDIAN
		return GETBYTE(Value, index);
#else
		return GETBYTE(Value, sizeof(T) - index - 1);
#endif
	}

	template <class T>
	static inline bool IsPowerOf2(T n)
	{
		return n > 0 && (n & (n - 1)) == 0;
	}

	static inline uint Min(uint A, uint B)
	{
		return ((A) < (B) ? (A) : (B));
	}

	template <class T1, class T2>
	static inline T2 ModPowerOf2(T1 a, T2 b)
	{
		assert(IsPowerOf2(b));
		return T2(a) & (b - 1);
	}

	static unsigned int Parity(ulong Value);

	// ** Rotate ** //

	static inline ulong RotlFixed64(ulong x, int Bits)
	{
		return (x << Bits) | ((long)((ulong)x >> -Bits));
	}

	static inline ulong RotrFixed64(ulong x, int Bits)
	{
		return ((x >> Bits) | (x << (64 - Bits)));
	}

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

	static inline unsigned long RotateLeft(unsigned long Value, int Shift)
	{
		return Shift ? _lrotl(Value, Shift) : Value;
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

	static inline unsigned long RotateRight(unsigned long Value, int Shift)
	{
		return Shift ? _lrotr(Value, Shift) : Value;
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

	static inline uint RotlFixed(uint x, uint y)
	{
		return y ? _lrotl(x, y) : x;
	}
	static inline uint RotrFixed(uint x, uint y)
	{
		return y ? _lrotr(x, y) : x;
	}
#elif defined(PPC_INTRINSICS)
	static inline uint RotateLeft(uint Value, int Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
	}
	static inline unsigned long RotateLeft(unsigned long Value, int Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
	}
	static inline ulong RotateLeft(ulong Value, int Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 63) : Value;
	}

	static inline uint RotateRight(uint Value, int Shift)
	{
		return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
	}
	static inline unsigned long RotateRight(unsigned long Value, int Shift)
	{
		return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
	}
	static inline ulong RotateRight(ulong Value, int Shift)
	{
		return Shift ? __rlwinm(Value, 64 - Shift, 0, 63) : Value;
	}

	static inline uint RotlFixed(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
	}
	static inline uint RotrFixed(uint Value, uint Shift)
	{
		return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
	}
#else
	static inline uint RotateLeft(uint Value, int Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
	}
	static inline unsigned long RotateLeft(unsigned long Value, int Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(unsigned long) * 8 - Shift));
	}
	static inline ulong RotateLeft(ulong Value, int Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(ulong) * 8 - Shift));
	}

	static inline uint RotateRight(uint Value, int Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
	}
	static inline unsigned long RotateRight(unsigned long Value, int Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(unsigned long) * 8 - Shift));
	}
	static inline ulong RotateRight(ulong Value, int Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(ulong) * 8 - Shift));
	}

	static inline uint RotlFixed(uint Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
	}
	static inline uint RotrFixed(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
	}
#endif

	// ** Little Endian Aligned Conversions ** //

	static inline std::vector<byte> ToBit16(unsigned short Word)
	{
		std::vector<byte> data(2);
		Le16ToBytes(Word, data, 0);
		return data;	
	}

	static inline std::vector<byte> ToBit32(uint Word)
	{
		std::vector<byte> data(4);
		Le32ToBytes(Word, data, 0);
		return data;
	}

	static inline std::vector<byte> ToBit64(ulong QWord)
	{
		std::vector<byte> data(8);
		Le64ToBytes(QWord, data, 0);
		return data;
	}

	template<typename T>
	static inline char* ToChar(const T& Value)
	{
		std::ostringstream oss;
		oss << Value;
		return oss.str().c_str();
	}

	static inline unsigned short ToInt16(std::vector<byte> Block)
	{
		return BytesToLe16(Block, 0);
	}

	static inline uint ToInt32(std::vector<byte> Block)
	{
		return BytesToLe32(Block, 0);
	}

	static inline ulong ToInt64(std::vector<byte> Block)
	{
		return BytesToLe64(Block, 0);
	}

	static inline unsigned short ToInt16(std::vector<byte> Block, uint Offset)
	{
		return BytesToLe16(Block, Offset);
	}

	static inline uint ToInt32(std::vector<byte> Block, uint Offset)
	{
		return BytesToLe32(Block, Offset);
	}

	static inline ulong ToInt64(std::vector<byte> Block, uint Offset)
	{
		return BytesToLe64(Block, Offset);
	}

	template<typename T>
	static inline std::string ToString(const T& Value)
	{
		std::ostringstream oss;
		oss << Value;
		return oss.str();
	}

	// ** Block XOR ** //

	static void XOR32(const byte* &Input, byte* &Output);

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

	static void XOR64(const std::vector<byte> &Input, std::vector<byte> &Output);

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

	static void XOR128(const std::vector<byte> &Input, std::vector<byte> &Output);

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

	static void XOR256(const byte* &Input, byte* &Output);

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

