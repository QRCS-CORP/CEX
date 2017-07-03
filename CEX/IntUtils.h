#ifndef _CEX_INTUTILS_H
#define _CEX_INTUTILS_H

#include "CexDomain.h"
#include "MemUtils.h"

// Note: hides functions not currently used by the library
#define CEX_INTUTILS_FULLSCOPE

NAMESPACE_UTILITY

/// <summary>
/// An integer utility functions class
/// </summary>
class IntUtils
{
public:

	//~~~Misc~~~//

#if defined(CEX_INTUTILS_FULLSCOPE)

	/// <summary>
	/// Return the absolute positive value difference between two integers
	/// </summary>
	/// 
	/// <param name="A">The first integer for comparison</param>
	/// <param name="B">The second integer for comparison</param>
	/// 
	/// <returns>The difference between integers</returns>
	template <typename T>
	inline static T Abs(T A, T B)
	{
		return A > B ? A - B : B - A;
	}

	/*! \cond PRIVATE */
	CEX_OPTIMIZE_IGNORE
	/*! \endcond */
	/// <summary>
	/// Clear nested arrays of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	template <typename T>
	inline static void ClearArray(std::vector<std::vector<T>> &Obj)
	{
		if (Obj.size() == 0)
			return;

		for (size_t i = 0; i < Obj.size(); i++)
			ClearVector(Obj[i]);

		Obj.clear();
	}
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_RESUME
	/*! \endcond */

	/// <summary>
	/// Crop a 64 bit integer value
	/// </summary>
	///
	/// <param name="Value">The initial value</param>
	/// <param name="Length">The number of bits in the new integer</param>
	/// 
	/// <returns>The cropped integer</returns>
	inline static ulong Crop(ulong Value, size_t Length)
	{
		if (Length < 8 * sizeof(Value))
			return (Value & ((1L << Length) - 1));
		else
			return Value;
	}

	/// <summary>
	/// Test for power of 2
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>True if the value is a power of 2</returns>
	template <typename T>
	inline static bool IsPowerOf2(T Value)
	{
		return Value > 0 && (Value & (Value - 1)) == 0;
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
	inline static T2 ModPowerOf2(T1 A, T2 B)
	{
		CEXASSERT(IsPowerOf2(B), "Not a power of two");

		return T2(A) & (B - 1);
	}

	/// <summary>
	/// Get the parity bit from a 64 bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The parity value</returns>
	inline static uint Parity(ulong Value)
	{
		for (size_t i = 8 * sizeof(Value) / 2; i > 0; i /= 2)
			Value ^= Value >> i;

		return (uint)Value & 1;
	}

#endif

	/// <summary>
	/// Clear an array of objects
	/// </summary>
	///
	/// <param name="Obj">A byte vector array</param>
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_IGNORE
	/*! \endcond */
	template <typename T>
	inline static void ClearVector(std::vector<T> &Obj)
	{
		if (Obj.capacity() == 0)
			return;

		if (Obj.size() != 0)
		{
			static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
			memset_v(Obj.data(), 0, Obj.size() * sizeof(T));
		}

		Obj.clear();
	}
	/*! \cond PRIVATE */
	CEX_OPTIMIZE_RESUME
	/*! \endcond */

	/// <summary>
	/// Return the larger of two values
	/// </summary>
	/// 
	/// <param name="A">The first comparison value</param>
	/// <param name="B">The second comparison value</param>
	/// 
	/// <returns>The larger value</returns>
	template <typename T>
	inline static T Max(T A, T B)
	{
		return ((A) > (B) ? (A) : (B));
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
	inline static T Min(T A, T B)
	{
		return ((A) < (B) ? (A) : (B));
	}

	/// <summary>
	/// Convert an integer to a string
	/// </summary>
	/// 
	/// <param name="Value">The integer to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	static std::string ToString(T Value)
	{
		return std::to_string(Value);
	}

	// Different computer architectures store data using different byte orders. "Big-endian"
	// means the most significant byte is on the left end of a word. "Little-endian" means the 
	// most significant byte is on the right end of a word. i.e.: 
	// BE: uint(block[3]) | (uint(block[2]) << 8) | (uint(block[1]) << 16) | (uint(block[0]) << 24)
	// LE: uint(block[0]) | (uint(block[1]) << 8) | (uint(block[2]) << 16) | (uint(block[3]) << 24)

	//~~~Big Endian~~~//

	/// <summary>
	/// Run time check for Little Endian byte order
	/// </summary>
	inline static bool IsBigEndian()
	{
		int num = 1;
		return (*(byte*)&num != 1);
	}

	/// <summary>
	/// Convert 8bit byte array to a Big Endian T sized array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Output">The destination T array</param>
	/// <param name="OutOffset">The starting offset within the destination T array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template<typename T>
	static void BlockToBe(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= Length, "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::Copy<byte, T>(Input, InOffset, Output, OutOffset, Length);
#else
		for (size_t i = 0; i < Length; i += sizeof(T))
		{
			for (size_t j = 0; j < sizeof(T); ++j)
				Output[OutOffset + i] |= static_cast<T>(Input[InOffset + j] >> (8 * j));
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian T sized word array to a byte array.
	/// <para>The entire input array is copied to bytes, must be 32bit aligned.</para>
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word input array</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">The starting offset within the destination array</param>
	/// <param name="Length">The number of bytes to convert</param>
	template<typename T>
	static void BeToBlock(std::vector<T> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= Length, "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::Copy<T, byte>(Input, InOffset, Output, OutOffset, Length);
#else
		for (size_t i = 0; i < Length; i += sizeof(T))
		{
			for (size_t j = 0; j < sizeof(T); ++j)
				Output[OutOffset + j] = static_cast<byte>(Input[InOffset + i] << (j * 8));
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination array</param>
	inline static void Be16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(ushort), "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::Copy<ushort, byte>(Value, Output, OutOffset, sizeof(ushort));
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
	inline static void Be32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(uint), "Length is larger than output capacity");

#if defined IS_BIG_ENDIAN
		Utility::Utility::MemUtils::Copy<uint, byte>(Value, Output, OutOffset, sizeof(uint));
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
	inline static void Be64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(ulong), "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::Copy<ulong, byte>(Value, Output, OutOffset, sizeof(ulong));
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
	/// Convert a Big Endian 8 * 32bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void BeUL256ToBlock(std::vector<uint> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 32 / sizeof(uint), "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 32, "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::COPY256<uint, byte>(Input, InOffset, Output, OutOffset);
#else
		Be32ToBytes(Input[0], Output, OutOffset);
		Be32ToBytes(Input[1], Output, OutOffset + 4);
		Be32ToBytes(Input[2], Output, OutOffset + 8);
		Be32ToBytes(Input[3], Output, OutOffset + 12);
		Be32ToBytes(Input[4], Output, OutOffset + 16);
		Be32ToBytes(Input[5], Output, OutOffset + 20);
		Be32ToBytes(Input[6], Output, OutOffset + 24);
		Be32ToBytes(Input[7], Output, OutOffset + 28);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 8 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void BeULL512ToBlock(std::vector<ulong> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 64 / sizeof(ulong), "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 64, "Length is larger than output capacity");

#if defined(IS_BIG_ENDIAN)
		Utility::Utility::MemUtils::COPY512<ulong, byte>(Input, InOffset, Output, OutOffset);
#else
		Be64ToBytes(Input[0], Output, OutOffset);
		Be64ToBytes(Input[1], Output, OutOffset + 8);
		Be64ToBytes(Input[2], Output, OutOffset + 16);
		Be64ToBytes(Input[3], Output, OutOffset + 24);
		Be64ToBytes(Input[4], Output, OutOffset + 32);
		Be64ToBytes(Input[5], Output, OutOffset + 40);
		Be64ToBytes(Input[6], Output, OutOffset + 48);
		Be64ToBytes(Input[7], Output, OutOffset + 56);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Big Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Big Endian format</returns>
	inline static ushort BeBytesTo16(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(ushort), "Length is larger than input capacity");

#if defined(IS_BIG_ENDIAN)
		ushort value = 0;
		Utility::Utility::MemUtils::Copy<byte, ushort>(Input, InOffset, value, sizeof(ushort));
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
	inline static uint BeBytesTo32(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(uint), "Length is larger than input capacity");

#if defined(IS_BIG_ENDIAN)
		uint value = 0;
		Utility::Utility::MemUtils::Copy<byte, uint>(Input, InOffset, value, sizeof(uint));
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
	inline static ulong BeBytesTo64(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(ulong), "Length is larger than input capacity");

#if defined(IS_BIG_ENDIAN)
		ulong value = 0;
		Utility::Utility::MemUtils::Copy<byte, ulong>(Input, InOffset, value, sizeof(ulong));
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

	/// <summary>
	/// Treats a byte array as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	inline static void BeIncrement8(std::vector<byte> &Counter)
	{
		size_t i = Counter.size();
		while (--i >= 0 && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats an 8bit integer array as a large Big Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	inline static void BeIncrease8(const std::vector<byte> &Input, std::vector<byte> &Output, const size_t Length)
	{
		const size_t CTRSZE = Output.size() - 1;
		uint ctrLen = static_cast<uint>(Length);
		std::vector<byte> ctrInc(sizeof(ctrLen));
		memcpy(&ctrInc[0], &ctrLen, ctrInc.size());
		memcpy(&Output[0], &Input[0], Input.size());
		byte carry = 0;

		for (size_t i = CTRSZE; i > 0; --i)
		{
			byte odst = Output[i];
			byte osrc = CTRSZE - i < ctrInc.size() ? ctrInc[CTRSZE - i] : (byte)0;
			byte ndst = (byte)(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[i] = ndst;
		}
	}

	//~~~Little Endian~~~//

	/// <summary>
	/// Run time check for Little Endian byte order
	/// </summary>
	inline static bool IsLittleEndian()
	{
		int num = 1;
		return (*(byte *)&num == 1);
	}

	/// <summary>
	/// Convert a Little Endian N * 8bit word array to a uint32 array.
	/// <para>The entire input array is copied to 32bit uints, input must be 32bit aligned.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="OutOffset">The starting offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template<typename T>
	static void BlockToLe(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= Length, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::Copy<byte, T>(Input, InOffset, Output, OutOffset, Length);
#else
		for (size_t i = 0; i < Length; i += sizeof(T))
		{
			for (size_t j = 0; j < sizeof(T); ++j)
				Output[OutOffset + i] |= static_cast<T>(Input[InOffset + j] << (8 * j));
		}
#endif
	}

	/// <summary>
	/// Convert a Little Endian N * 32bit word array to a byte array.
	/// <para>The entire input array is copied to bytes, must be 32bit aligned.</para>
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">The starting offset within the destination array</param>
	/// <param name="Length">The number of bytes to convert</param>
	template<typename T>
	static void LeToBlock(std::vector<T> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= Length, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::Copy<T, byte>(Input, InOffset, Output, OutOffset, Length);
#else
		for (size_t i = 0; i < Length; i += sizeof(T))
		{
			for (size_t j = 0; j < sizeof(T); ++j)
				Output[OutOffset + j] = static_cast<byte>(Input[InOffset + i] >> (j * 8));
		}
#endif
	}

	/// <summary>
	/// Convert a Little Endian 16 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void Le16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(ushort), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::Copy<ushort, byte>(Value, Output, OutOffset, sizeof(ushort));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 32 bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32 bit word</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void Le32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(uint), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::Copy<uint, byte>(Value, Output, OutOffset, sizeof(uint));
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
	inline static void Le64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Output.size() - OutOffset) >= sizeof(ulong), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::Copy<ulong, byte>(Value, Output, OutOffset, sizeof(ulong));
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

	/// <summary>
	/// Convert a Little Endian 8 * 32bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void LeUL256ToBlock(std::vector<uint> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(uint) >= 32, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 32, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY256<uint, byte>(Input, InOffset, Output, OutOffset);
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

	/// <summary>
	/// Convert a Little Endian 4 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 32bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void LeULL256ToBlock(std::vector<ulong> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 32, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 32, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY256<ulong, byte>(Input, InOffset, Output, OutOffset);
#else
		Le64ToBytes(Input[0], Output, OutOffset);
		Le64ToBytes(Input[1], Output, OutOffset + 8);
		Le64ToBytes(Input[2], Output, OutOffset + 16);
		Le64ToBytes(Input[3], Output, OutOffset + 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 8 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void LeULL512ToBlock(std::vector<ulong> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 64, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 64, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY512<ulong, byte>(Input, InOffset, Output, OutOffset);
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
	/// Convert a Little Endian 16 * 64bit word array to a byte array
	/// </summary>
	/// 
	/// <param name="Input">The 64bit word array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The destination bytes</param>
	/// <param name="OutOffset">OutOffset within the destination block</param>
	inline static void LeULL1024ToBlock(std::vector<ulong> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 128, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) >= 128, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY512<ulong, byte>(Input, InOffset, Output, OutOffset);
		Utility::MemUtils::COPY512<ulong, byte>(Input, InOffset + 8, Output, OutOffset + 64);
#else
		LeULL512ToBlock(Input, InOffset, Output, OutOffset);
		LeULL512ToBlock(Input, InOffset + 8, Output, OutOffset + 64);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 16 bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <returns>A 16 bit word in Little Endian format</returns>
	inline static ushort LeBytesTo16(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(ushort), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		ushort value = 0;
		Utility::MemUtils::Copy<byte, ushort>(Input, InOffset, value, sizeof(ushort));
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
	inline static uint LeBytesTo32(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(uint), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		uint value = 0;
		Utility::MemUtils::Copy<byte, uint>(Input, InOffset, value, sizeof(uint));
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
	inline static ulong LeBytesTo64(const std::vector<byte> &Input, size_t InOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= sizeof(ulong), "Length is larger than input capacity");

#if defined(IS_LITTLE_ENDIAN)
		ulong value = 0;
		Utility::MemUtils::Copy<byte, ulong>(Input, InOffset, value, sizeof(ulong));
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
	/// Convert a byte array to a Little Endian 16 * 32bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	inline static void LeBytesToUL512(const std::vector<byte> &Input, size_t InOffset, std::vector<uint> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 64, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint) >= 64, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY512<byte, uint>(Input, InOffset, Output, OutOffset);
#else
		Output[OutOffset] = LeBytesTo32(Input, InOffset);
		Output[OutOffset + 1] = LeBytesTo32(Input, InOffset + 4);
		Output[OutOffset + 2] = LeBytesTo32(Input, InOffset + 8);
		Output[OutOffset + 3] = LeBytesTo32(Input, InOffset + 12);
		Output[OutOffset + 4] = LeBytesTo32(Input, InOffset + 16);
		Output[OutOffset + 5] = LeBytesTo32(Input, InOffset + 20);
		Output[OutOffset + 6] = LeBytesTo32(Input, InOffset + 24);
		Output[OutOffset + 7] = LeBytesTo32(Input, InOffset + 28);
		Output[OutOffset + 8] = LeBytesTo32(Input, InOffset + 32);
		Output[OutOffset + 9] = LeBytesTo32(Input, InOffset + 36);
		Output[OutOffset + 10] = LeBytesTo32(Input, InOffset + 40);
		Output[OutOffset + 11] = LeBytesTo32(Input, InOffset + 44);
		Output[OutOffset + 12] = LeBytesTo32(Input, InOffset + 48);
		Output[OutOffset + 13] = LeBytesTo32(Input, InOffset + 52);
		Output[OutOffset + 14] = LeBytesTo32(Input, InOffset + 56);
		Output[OutOffset + 15] = LeBytesTo32(Input, InOffset + 60);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 4 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	inline static void LeBytesToULL256(const std::vector<byte> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 32, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 32, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY256<byte, ulong>(Input, InOffset, Output, OutOffset);
#else
		Output[OutOffset] = LeBytesTo64(Input, InOffset);
		Output[OutOffset + 1] = LeBytesTo64(Input, InOffset + 8);
		Output[OutOffset + 2] = LeBytesTo64(Input, InOffset + 16);
		Output[OutOffset + 3] = LeBytesTo64(Input, InOffset + 24);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 8 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 64 bit dwords in Little Endian format</returns>
	inline static void LeBytesToULL512(const std::vector<byte> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 64, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 64, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY512<byte, ulong>(Input, InOffset, Output, OutOffset);
#else
		Output[OutOffset] = LeBytesTo64(Input, InOffset);
		Output[OutOffset + 1] = LeBytesTo64(Input, InOffset + 8);
		Output[OutOffset + 2] = LeBytesTo64(Input, InOffset + 16);
		Output[OutOffset + 3] = LeBytesTo64(Input, InOffset + 24);
		Output[OutOffset + 4] = LeBytesTo64(Input, InOffset + 32);
		Output[OutOffset + 5] = LeBytesTo64(Input, InOffset + 40);
		Output[OutOffset + 6] = LeBytesTo64(Input, InOffset + 48);
		Output[OutOffset + 7] = LeBytesTo64(Input, InOffset + 56);
#endif
	}

	/// <summary>
	/// Convert a byte array to a Little Endian 16 * 64bit word array
	/// </summary>
	/// 
	/// <param name="Input">The source byte array</param>
	/// <param name="InOffset">Offset within the source array</param>
	/// <param name="Output">The output integer array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// <returns>An array of 32 bit words in Little Endian format</returns>
	inline static void LeBytesToULL1024(const std::vector<byte> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) >= 128, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 128, "Length is larger than output capacity");

#if defined(IS_LITTLE_ENDIAN)
		Utility::MemUtils::COPY512<byte, ulong>(Input, InOffset, Output, OutOffset);
		Utility::MemUtils::COPY512<byte, ulong>(Input, InOffset + 64, Output, OutOffset + 8);
#else
		LeBytesToULL512(Input, InOffset, Output, OutOffset);
		LeBytesToULL512(Input, InOffset + 64, Output, OutOffset + 64);
#endif
	}

	/// <summary>
	/// Treats a byte array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	inline static void LeIncrement8(std::vector<byte> &Counter)
	{
		int i = -1;
		while (++i < static_cast<int>(Counter.size()) && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats the array as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The vector array of values</param>
	template <typename T>
	static void LeIncrement(std::vector<T> &Counter)
	{
		size_t i = Counter.size();
		while (--i >= 0 && ++Counter[i] == 0) {}
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The counter array to increment</param>
	inline static void LeIncrement32(std::vector<uint> &Counter)
	{
		if (++Counter[0] == 0)
			++Counter[1];
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Counter">The counter array to increment</param>
	inline static void LeIncrement64(std::vector<ulong> &Counter)
	{
		if (++Counter[0] == 0)
			++Counter[1];
	}

	/// <summary>
	/// Treats a 2x 32bit integer array as a large Little Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	inline static void LeIncrease32(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length)
	{
		memcpy(&Output[0], &Input[0], Input.size() * sizeof(uint));
		Output[0] += static_cast<uint>(Length);
		if (Output[0] < Input[0])
			++Output[1];
	}

	/// <summary>
	/// Treats a 2x 64bit integer array as a large Little Endian integer, incrementing the total value by a defined length
	/// </summary>
	/// 
	/// <param name="Input">The initial array of bytes</param>
	/// <param name="Output">The modified output array</param>
	/// <param name="Length">The number to increase by</param>
	inline static void LeIncrease64(const std::vector<ulong> &Input, std::vector<ulong> &Output, const size_t Length)
	{
		memcpy(&Output[0], &Input[0], Input.size() * sizeof(ulong));
		Output[0] += static_cast<uint>(Length);
		if (Output[0] < Input[0])
			++Output[1];
	}

	//~~~Constant Time~~~//

	/// <summary>
	/// Constant time comparison of two arrays segments with offset and length parameters
	/// </summary>
	/// 
	/// <param name="A">The first array to compare</param>
	/// <param name="AOffset">The starting offset within the 'A' array</param>
	/// <param name="B">The second array to compare</param>
	/// <param name="BOffset">The starting offset within the 'B' array</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>True if arrays are equivalant</returns>
	template <typename T>
	static bool Compare(const std::vector<T> &A, size_t AOffset, const std::vector<T> &B, size_t BOffset, size_t Length)
	{
		size_t delta = 0;

		for (size_t i = 0; i < Length; ++i)
			delta |= (A[AOffset + i] ^ B[BOffset + i]);

		return (delta == 0);
	}

	/// <summary>
	/// Expand an integer mask in constant time
	/// </summary>
	/// 
	/// <param name="X">The N bit word</param>
	/// 
	/// <returns>A N bit expanded word</returns>
	template<typename T>
	inline static T ExpandMask(T X)
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
	/// Combine the bits from two integers filtered by a mask value
	/// </summary>
	/// 
	/// <param name="Mask">The mask value</param>
	/// <param name="A">The first value</param>
	/// <param name="B">The second value</param>
	/// 
	/// <returns>A combined N bit integer</returns>
	template<typename T>
	inline static T Select(T Mask, T A, T B)
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
	inline static V ValueOrZero(P Pred, V Value)
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
	inline static T IsZero(T X)
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
	inline static T IsEqual(T X, T Y)
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
	inline static T IsLess(T X, T Y)
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
	inline static T IsLte(T X, T Y)
	{
		return ExpandMask<T>(X <= Y);
	}

	/// <summary>
	/// Constant time conditional bit copy
	/// </summary>
	/// 
	/// <param name="Value">The destination mask</param>
	/// <param name="To">The destination array</param>
	/// <param name="From0">The first value to copy</param>
	/// <param name="From1">The second value to copy</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	inline static void ConditionalCopy(T Value, T* To, const T* From0, const T* From1, size_t Length)
	{
		const T MASK = ExpandMask<T>(Value);

		for (size_t i = 0; i != Length; ++i)
			To[i] = Select<T>(MASK, From0[i], From1[i]);
	}

	/// <summary>
	/// Constant time conditional bit erase
	/// </summary>
	/// 
	/// <param name="Condition">The condition</param>
	/// <param name="Array">The array to wipe</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	inline static void ConditionalZeroMem(T Condition, T* Array, size_t Length)
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
	inline static T ExpandTopBit(T A)
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
	inline static T CMax(T A, T B)
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
	inline static T CMin(T A, T B)
	{
		return Select<T>(ExpandTopBit<T>(B), B, A);
	}

	/// <summary>
	/// Left shift an array of integers (OCB mode)
	/// </summary>
	/// 
	/// <param name="Input">The value array to shift</param>
	/// <param name="Output">The output integer array</param>
	/// 
	/// <returns>The bit count</returns>
	static uint ShiftLeft(const std::vector<byte> &Input, std::vector<byte> &Output)
	{
		size_t ctr = Input.size();
		uint bit = 0;

		do
		{
			--ctr;
			uint b = Input[ctr];
			Output[ctr] = (byte)((b << 1) | bit);
			bit = (b >> 7) & 1;
		} while (ctr > 0);

		return bit;
	}

	//~~~Rotate~~~//

#if defined(CEX_HAS_MINSSE) && defined(CEX_FASTROTATE_ENABLED)
#	pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotFL32(uint Value, uint Shift)
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
	inline static ulong RotFL64(ulong Value, uint Shift)
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
	inline static uint RotFR32(uint Value, uint Shift)
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
	inline static ulong RotFR64(ulong Value, uint Shift)
	{
		return _rotr64(Value, Shift);
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotL32(uint Value, uint Shift)
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
	inline static ulong RotL64(ulong Value, uint Shift)
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
	inline static uint RotR32(uint Value, uint Shift)
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
	inline static ulong RotR64(ulong Value, uint Shift)
	{
		return Shift ? _rotr64(Value, Shift) : Value;
	}

#else

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotFL32(uint Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static ulong RotFL64(ulong Value, uint Shift)
	{
		return (Value << Shift) | (Value >> (64 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint RotFR32(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64 bit integer</returns>
	inline static ulong RotFR64(ulong Value, uint Shift)
	{
		return ((Value >> Shift) | (Value << (64 - Shift)));
	}

	/// <summary>
	/// Rotate shift an unsigned 32 bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotL32(uint Value, uint Shift)
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
	inline static ulong RotL64(ulong Value, uint Shift)
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
	inline static uint RotR32(uint Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64 bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static ulong RotR64(ulong Value, uint Shift)
	{
		return (Value >> Shift) | (Value << (sizeof(ulong) * 8 - Shift));
	}

#endif
};

NAMESPACE_UTILITYEND
#endif

