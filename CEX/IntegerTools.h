// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_INTUTILS_H
#define CEX_INTUTILS_H

#include "CexDomain.h"
#include "MemoryTools.h"
#include <iomanip>
#include <sstream>

NAMESPACE_UTILITY

using Utility::MemoryTools;

/// <summary>
/// An integer utility functions class
/// </summary>
class IntegerTools
{
public:

	//~~~Misc~~~//

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Clear nested vectors of objects
	/// </summary>
	///
	/// <param name="Input">A nested vector integer vector</param>
	template <typename Array>
	inline static void Clear(Array &Input)
	{
		if (Input.size() != 0)
		{
			static void* (*const volatile pmemset)(void*, int, size_t) = std::memset;
			(pmemset)(Input.data(), 0x00, Input.size() * sizeof(Array::value_type));
		}
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Clear nested arrays of objects
	/// </summary>
	///
	/// <param name="Input">A nested integer vector</param>
	template <typename T, size_t Dimensions, size_t Length>
	inline static void ClearArray(std::array<std::array<T, Length>, Dimensions> &Input)
	{
		size_t i;

		if (Input.size() != 0)
		{
			for (i = 0; i < Input.size(); ++i)
			{
				Clear(Input[i]);
			}
		}
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// <summary>
	/// Fills a vector of any type with random elements.
	/// <para>The random source can be any of the Prngs, Drbgs, or entropy Providers.
	/// The vector must be pre-sized to fit the new pseudo-random output.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output vector receiving random integers</param>
	/// <param name="Offset">The starting position within the output vector</param>
	/// <param name="Elements">The number of elements to generate</param>
	/// <param name="Rng">The random provider source</param>
	template <typename Array, typename Random>
	inline static void Fill(Array &Output, size_t Offset, size_t Elements, Random &Rng)
	{
		CEXASSERT(Output.size() - Offset <= Elements, "The output vector is too short");

		const size_t BUFLEN = Elements * sizeof(Array::value_type);
		std::vector<byte> buf(BUFLEN);
		Rng.Generate(buf);
		MemoryTools::Copy(buf, 0, Output, Offset, BUFLEN);
	}

	/// <summary>
	/// Fills a vector of any type with random elements.
	/// <para>The random source can be any of the Prngs, Drbgs, or entropy Providers.
	/// The vector must be pre-sized to fit the new pseudo-random output.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output vector receiving random integers</param>
	/// <param name="Offset">The starting position within the output vector</param>
	/// <param name="Elements">The number of elements to generate</param>
	/// <param name="Rng">A pointer to the random provider source</param>
	template <typename Array, typename Random>
	inline static void Fill(Array &Output, size_t Offset, size_t Elements, Random* Rng)
	{
		CEXASSERT(Output.size() - Offset <= Elements, "The output vector is too short");

		const size_t BUFLEN = Elements * sizeof(Array::value_type);
		std::vector<byte> buf(BUFLEN);
		Rng->Generate(buf);
		MemoryTools::Copy(buf, 0, Output, Offset, BUFLEN);
	}

	/// <summary>
	/// Extract an 8-bit integer from a larger integer
	/// </summary>
	/// 
	/// <param name="Value">The integer value to extract from</param>
	/// <param name="Index">The index position within the value</param>
	/// 
	/// <returns>The extracted byte</returns>
	template<typename T> 
	inline static byte GetByte(T Value, size_t Index)
	{
		return static_cast<byte>(Value >> (((~Index)&(sizeof(T) - 1)) << 3));
	}

	/// <summary>
	/// Return the absolute value difference between two integers
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

	/// <summary>
	/// Crop a 64-bit integer value
	/// </summary>
	///
	/// <param name="Value">The base value</param>
	/// <param name="Length">The number of bits in the new integer</param>
	/// 
	/// <returns>The cropped integer</returns>
	inline static ulong Crop(ulong Value, size_t Length)
	{
		if (Length < 8 * sizeof(Value))
		{
			return (Value & ((1ULL << Length) - 1ULL));
		}
		else
		{
			return Value;
		}
	}

	/// <summary>
	/// Copies a string to a byte vector.
	/// <para>The output from this function is endian dependant.</para>
	/// </summary>
	/// 
	/// <param name="Input">The string to copy</param>
	/// 
	/// <returns>The byte vector containing the string values</returns>
	inline static std::vector<byte> FromString(std::string &Input)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");

		std::vector<byte> otp(Input.size());
		std::memcpy(otp.data(), Input.data(), Input.size());

		return otp;
	}

	/// <summary>
	/// Copies a hex formatted string to a vector of bytes
	/// </summary>
	/// 
	/// <param name="Input">The string to convert</param>
	/// <param name="Length">The number of bytes to convert</param>
	/// 
	/// <returns>The hex string copied to a vector of bytes</returns>
	inline static std::vector<byte> FromHex(std::string &Input, size_t Length)
	{
		CEXASSERT(Length <= Input.size(), "Length can not be longer than input");

		std::vector<byte> otp;
		std::string nhex;
		size_t i;
		byte num;

		for (i = 0; i < Length; i += 2)
		{
			nhex = Input.substr(i, 2);
			num = static_cast<byte>(strtol(nhex.c_str(), NULL, 16));
			otp.push_back(num);
		}

		return otp;
	}

	/// <summary>
	/// Test for power of 2
	/// </summary>
	/// 
	/// <param name="Value">The base value</param>
	/// 
	/// <returns>Returns true if the value is a power of 2</returns>
	template <typename T>
	inline static bool IsPowerOf2(T Value)
	{
		return Value > 0 && (Value & (Value - 1)) == 0;
	}

	/// <summary>
	/// Mod a power of two integer
	/// </summary>
	/// 
	/// <param name="A">The base value</param>
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
	/// Return the larger of two integer values
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
	/// Return the smaller of two integer values
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
	/// Get the parity bit from a 64-bit integer
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// 
	/// <returns>The parity 32-bit value</returns>
	inline static ulong Parity(ulong Value)
	{
		size_t i;

		for (i = (8 * sizeof(Value)) / 2; i > 0; i /= 2)
		{
			Value ^= Value >> i;
		}

		return Value & 1;
	}

	/// <summary>
	/// Convert an array or vector of T to a hexadecimal string
	/// </summary>
	/// 
	/// <param name="Input">The array of T to convert</param>
	/// <param name="Offset">The initial input offset</param>
	/// <param name="Length">The number of T values to convert</param>
	/// 
	/// <returns>The hex string representation</returns>
	template <typename Array>
	inline static std::string ToHex(Array &Input, size_t Offset, size_t Length)
	{
		CEXASSERT(Length <= Input.size() - Offset, "Length can not be longer than input");

		std::stringstream ss;
		size_t i;

		ss << std::hex << std::uppercase << std::setfill('0');

		for (i = 0; i < Length; ++i)
		{
			ss << std::setw(2) << static_cast<unsigned>(Input[Offset + i]);
		}

		return ss.str();
	}

	/// <summary>
	/// Convert a value of T to a hexadecimal string
	/// </summary>
	/// 
	/// <param name="Value">The value of T to convert</param>
	/// 
	/// <returns>The hex string representation</returns>
	template <typename T>
	inline static std::string ToHex(T Value)
	{
		std::stringstream ss;
		ss << std::hex << std::uppercase;
		ss << Value;

		return ss.str();
	}

	/// <summary>
	/// Convert an integer to a string
	/// </summary>
	/// 
	/// <param name="Value">The integer to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	inline static std::string ToString(T Value)
	{
		return std::to_string(Value);
	}

	/// <summary>
	/// Convert a vector or vector of T to a string
	/// </summary>
	/// 
	/// <param name="Input">The integer vector to convert</param>
	/// <param name="Offset">The initial input offset</param>
	/// <param name="Length">The number of T values to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename Array>
	inline static std::string ToString(Array &Input, size_t Offset, size_t Length)
	{
		CEXASSERT(Length <= Input.size() - Offset, "Length can not be longer than input");

		std::stringstream ss;
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			ss << Input[Offset + i];
		}

		return ss.str();
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
	/// Convert 8-bit byte vector to a Big Endian integer vector
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination integer vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	/// <param name="Length">The number of bytes to copy</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BlockToBe(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT(Input.size() - InOffset >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ArrayB::value_type) >= Length, "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, Length);
#else

		const size_t VARLEN = sizeof(ArrayB::value_type);
		size_t i;
		size_t j;

		for (i = 0; i < Length / VARLEN; ++i)
		{
			for (j = VARLEN; j > 0; --j)
			{
				Output[OutOffset + i] |= static_cast<ArrayB::value_type>(Input[InOffset + (i * VARLEN) + (VARLEN - j)]) << (8 * (j - 1));
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian integer vector to a byte vector.
	/// </summary>
	/// 
	/// <param name="Input">The integer input vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	/// <param name="Length">The number of bytes to convert</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BeToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ArrayA::value_type) >= Length, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= Length, "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, Length);
#else
		const size_t VARLEN = sizeof(ArrayA::value_type);
		size_t i;
		size_t j;

		for (i = 0; i < Length / VARLEN; ++i)
		{
			for (j = VARLEN; j > 0; --j)
			{
				Output[OutOffset + (i * VARLEN) + (j - 1)] = static_cast<ArrayB::value_type>(Input[InOffset + i] >> ((VARLEN - j) * 8));
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian 16-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be16ToBytes(ushort Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(ushort), "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(ushort));
#else
		Output[OutOffset + 1] = static_cast<byte>(Value);
		Output[OutOffset] = static_cast<byte>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 32-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be32ToBytes(uint Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint), "Length is larger than output size");

#if defined IS_BIG_ENDIAN
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint));
#else
		Output[OutOffset + 3] = static_cast<byte>(Value);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
		Output[OutOffset] = static_cast<byte>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 64-bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit word</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be64ToBytes(ulong Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(ulong), "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(ulong));
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
	/// Convert a Big Endian 8 * 32bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 32bit integer source vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BeUL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint), "Input must be a 32bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT(Input.size() - InOffset >= 32 / sizeof(uint), "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 32, "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 32);
#else
		Be32ToBytes(Input[InOffset], Output, OutOffset);
		Be32ToBytes(Input[InOffset + 1], Output, OutOffset + 4);
		Be32ToBytes(Input[InOffset + 2], Output, OutOffset + 8);
		Be32ToBytes(Input[InOffset + 3], Output, OutOffset + 12);
		Be32ToBytes(Input[InOffset + 4], Output, OutOffset + 16);
		Be32ToBytes(Input[InOffset + 5], Output, OutOffset + 20);
		Be32ToBytes(Input[InOffset + 6], Output, OutOffset + 24);
		Be32ToBytes(Input[InOffset + 7], Output, OutOffset + 28);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 8 * 64bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer source vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BeULL512ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(ulong), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT(Input.size() - InOffset >= 64 / sizeof(ulong), "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 64, "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
#else
		Be64ToBytes(Input[InOffset], Output, OutOffset);
		Be64ToBytes(Input[InOffset + 1], Output, OutOffset + 8);
		Be64ToBytes(Input[InOffset + 2], Output, OutOffset + 16);
		Be64ToBytes(Input[InOffset + 3], Output, OutOffset + 24);
		Be64ToBytes(Input[InOffset + 4], Output, OutOffset + 32);
		Be64ToBytes(Input[InOffset + 5], Output, OutOffset + 40);
		Be64ToBytes(Input[InOffset + 6], Output, OutOffset + 48);
		Be64ToBytes(Input[InOffset + 7], Output, OutOffset + 56);
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Big Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 16-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static ushort BeBytesTo16(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(ushort), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		ushort value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(ushort));
		return value;
#else
		return
			(static_cast<ushort>(Input[InOffset]) << 8) |
			(static_cast<ushort>(Input[InOffset + 1]));
#endif
	}

	/// <summary>
	/// Convert a Big Endian 16-bit word to byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be16ToBytes(ushort Value)
	{
		Array otp(sizeof(ushort));

		Be16ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a byte vector to a Big Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 32-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static uint BeBytesTo32(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		uint value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(uint));

		return value;
#else
		return
			(static_cast<uint>(Input[InOffset]) << 24) |
			(static_cast<uint>(Input[InOffset + 1]) << 16) |
			(static_cast<uint>(Input[InOffset + 2]) << 8) |
			(static_cast<uint>(Input[InOffset + 3]));
#endif
	}

	/// <summary>
	/// Convert a Big Endian 32-bit word to byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be32ToBytes(uint Value)
	{
		Array otp(sizeof(uint));

		Be32ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a byte vector to a Big Endian 64-bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 64-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static ulong BeBytesTo64(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(ulong), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		ulong value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(ulong));
		return value;
#else
		return
			(static_cast<ulong>(Input[InOffset]) << 56) |
			(static_cast<ulong>(Input[InOffset + 1]) << 48) |
			(static_cast<ulong>(Input[InOffset + 2]) << 40) |
			(static_cast<ulong>(Input[InOffset + 3]) << 32) |
			(static_cast<ulong>(Input[InOffset + 4]) << 24) |
			(static_cast<ulong>(Input[InOffset + 5]) << 16) |
			(static_cast<ulong>(Input[InOffset + 6]) << 8) |
			(static_cast<ulong>(Input[InOffset + 7]));
#endif
	}

	/// <summary>
	/// Convert a Big Endian 64-bit dword to byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be64ToBytes(ulong Value)
	{
		Array otp(sizeof(ulong));

		Be64ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Treats a byte vector as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter byte vector</param>
	template<typename Array>
	inline static void BeIncrement8(Array &Output)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		size_t i;

		i = Output.size();

		do
		{
			--i;
			++Output[i];

			if (Output[i] != 0)
			{
				break;
			}
		} 
		while (i > 0);
	}

	/// <summary>
	/// Treats a byte vector as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter byte vector</param>
	/// <param name="Offset">The starting offset withing the vector</param>
	/// <param name="Length">The number of byte vector elements to process</param>
	template<typename Array>
	inline static void BeIncrement8(Array &Output, size_t Offset, size_t Length)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(byte), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT((Output.size() - Offset) >= Length, "Length is larger than output size");

		size_t i;

		i = Offset + Length;

		do
		{
			--i;
			++Output[i];

			if (Output[i] != 0)
			{
				break;
			}
		} 
		while (i > Offset);
	}

	/// <summary>
	/// Increment an 8-bit integer vector by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename Array, typename T>
	inline static void BeIncrease8(Array &Output, T Value)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		const size_t MAXPOS = Output.size() - 1;
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte ndst;
		byte odst;
		byte osrc;
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = Output.size();

		while (lctr != 0)
		{
			--lctr;
			odst = Output[lctr];
			osrc = ((MAXPOS - lctr) < cinc.size()) ? cinc[MAXPOS - lctr] : 0x00;
			ndst = odst + osrc + carry;
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void BeIncrease8(const ArrayA &Input, ArrayB &Output, T Value)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = Input.size() - 1;
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte ndst;
		byte odst;
		byte osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		MemoryTools::Copy(Input, 0, Output, 0, Input.size());
		carry = 0;
		lctr = Input.size();

		while (lctr != 0)
		{
			--lctr;
			odst = Output[lctr];
			osrc = ((MAXPOS - lctr) < cinc.size()) ? cinc[MAXPOS - lctr] : 0x00;
			ndst = static_cast<byte>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output byte vector</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void BeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, T Value)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() - OutOffset >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Input.size() - 1;
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte ndst;
		byte odst;
		byte osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		carry = 0;
		lctr = MAXPOS + 1;

		while (lctr != OutOffset)
		{
			--lctr;
			odst = Output[lctr];
			osrc = ((MAXPOS - lctr) < cinc.size()) ? cinc[MAXPOS - lctr] : 0x00;
			ndst = static_cast<byte>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output byte vector</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Length">The number of bytes within the vector to treat as a segmented counter</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void BeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, size_t Length, T Value)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() - OutOffset >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Length - 1;
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte ndst;
		byte odst;
		byte osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		carry = 0;
		lctr = MAXPOS + 1;

		while (lctr != OutOffset)
		{
			--lctr;
			odst = Output[lctr];
			osrc = ((MAXPOS - lctr) < cinc.size()) ? cinc[MAXPOS - lctr] : 0x00;
			ndst = static_cast<byte>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	//~~~Little Endian~~~//

	/// <summary>
	/// Run time check for Little Endian byte order
	/// </summary>
	inline static bool IsLittleEndian()
	{
		int num = 1;
		return (*(byte*)&num == 1);
	}

	/// <summary>
	/// Convert a Little Endian N * 8-bit word vector to an unsigned integer vector.
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination integer vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	/// <param name="Length">The number of bytes to process</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BlockToLe(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT(Input.size() - InOffset >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ArrayB::value_type) >= Length, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, Length);
#else
		const size_t VARLEN = sizeof(ArrayB::value_type);
		size_t i;
		size_t j;

		for (i = 0; i < Length / VARLEN; ++i)
		{
			for (j = 0; j < VARLEN; ++j)
			{
				Output[OutOffset + i] |= static_cast<ArrayB::value_type>(Input[InOffset + (i * VARLEN) + j]) << (8 * j);
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Little Endian unsigned integer vector to a byte vector.
	/// </summary>
	/// 
	/// <param name="Input">The source integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	/// <param name="Length">The number of bytes to convert</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ArrayA::value_type) >= Length, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= Length, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, Length);
#else
		const size_t VARLEN = sizeof(ArrayA::value_type);
		size_t i;
		size_t j;

		for (i = 0; i < Length / VARLEN; ++i)
		{
			for (j = 0; j < VARLEN; ++j)
			{
				Output[OutOffset + (i * VARLEN) + j] = static_cast<ArrayB::value_type>(Input[InOffset + i] >> (8 * j));
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Little Endian 16-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16bit integer</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le16ToBytes(ushort Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(ushort), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(ushort));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 16-bit word to a byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le16ToBytes(ushort Value)
	{
		Array otp(sizeof(ushort));

		Le16ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 32-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le32ToBytes(uint Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint));
#else
		Output[OutOffset] = static_cast<byte>(Value);
		Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
		Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
		Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 32-bit word to a byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le32ToBytes(uint Value)
	{
		Array otp(sizeof(uint));

		Le32ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 64-bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le64ToBytes(ulong Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(ulong), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(ulong));
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
	/// Convert a Little Endian 64-bit dword to byte vector
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le64ToBytes(ulong Value)
	{
		Array otp(sizeof(ulong));

		Le64ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 8 * 32bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 32bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeUL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint), "Input must be a 32bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(uint) >= 32, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 32, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 32);
#else
		Le32ToBytes(Input[InOffset], Output, OutOffset);
		Le32ToBytes(Input[InOffset + 1], Output, OutOffset + 4);
		Le32ToBytes(Input[InOffset + 2], Output, OutOffset + 8);
		Le32ToBytes(Input[InOffset + 3], Output, OutOffset + 12);
		Le32ToBytes(Input[InOffset + 4], Output, OutOffset + 16);
		Le32ToBytes(Input[InOffset + 5], Output, OutOffset + 20);
		Le32ToBytes(Input[InOffset + 6], Output, OutOffset + 24);
		Le32ToBytes(Input[InOffset + 7], Output, OutOffset + 28);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 4 * 64bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(ulong), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 32, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 32, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 32);
#else
		Le64ToBytes(Input[InOffset], Output, OutOffset);
		Le64ToBytes(Input[InOffset + 1], Output, OutOffset + 8);
		Le64ToBytes(Input[InOffset + 2], Output, OutOffset + 16);
		Le64ToBytes(Input[InOffset + 3], Output, OutOffset + 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 8 * 64bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL512ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(ulong), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 64, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 64, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
#else
		Le64ToBytes(Input[InOffset], Output, OutOffset);
		Le64ToBytes(Input[InOffset + 1], Output, OutOffset + 8);
		Le64ToBytes(Input[InOffset + 2], Output, OutOffset + 16);
		Le64ToBytes(Input[InOffset + 3], Output, OutOffset + 24);
		Le64ToBytes(Input[InOffset + 4], Output, OutOffset + 32);
		Le64ToBytes(Input[InOffset + 5], Output, OutOffset + 40);
		Le64ToBytes(Input[InOffset + 6], Output, OutOffset + 48);
		Le64ToBytes(Input[InOffset + 7], Output, OutOffset + 56);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 16 * 64bit word vector to a byte vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination byte vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL1024ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(ulong), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a byte vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(ulong) >= 128, "Length is larger than input size");
		CEXASSERT(Output.size() - OutOffset >= 128, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
		MemoryTools::Copy(Input, InOffset + 8, Output, OutOffset + 64, 64);
#else
		LeULL512ToBlock(Input, InOffset, Output, OutOffset);
		LeULL512ToBlock(Input, InOffset + 8, Output, OutOffset + 64);
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 16-bit integer in Little Endian format</returns>
	template<typename Array>
	inline static ushort LeBytesTo16(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(ushort), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		ushort val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(ushort));

		return val;
#else
		return
			(static_cast<ushort>(Input[InOffset]) |
			(static_cast<ushort>(Input[InOffset + 1]) << 8));
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 32-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint LeBytesTo32(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		uint val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint));

		return val;
#else
		return
			(static_cast<uint>(Input[InOffset]) |
			(static_cast<uint>(Input[InOffset + 1]) << 8) |
			(static_cast<uint>(Input[InOffset + 2]) << 16) |
			(static_cast<uint>(Input[InOffset + 3]) << 24));
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Length">The number of input bytes to use</param>
	///
	/// <returns>A 32-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint LeBytesTo32(const Array &Input, size_t InOffset, size_t Length)
	{
		size_t i;
		uint r;

		r = Input[InOffset];

		for (i = 1; i < Length; ++i)
		{
			r |= static_cast<uint>(Input[InOffset + i]) << (8 * i);
		}

		return r;
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 64-bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 64-bit word in Little Endian format</returns>
	template<typename Array>
	inline static ulong LeBytesTo64(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(ulong), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		ulong val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(ulong));

		return val;
#else
		return
			(static_cast<ulong>(Input[InOffset])) |
			(static_cast<ulong>(Input[InOffset + 1]) << 8) |
			(static_cast<ulong>(Input[InOffset + 2]) << 16) |
			(static_cast<ulong>(Input[InOffset + 3]) << 24) |
			(static_cast<ulong>(Input[InOffset + 4]) << 32) |
			(static_cast<ulong>(Input[InOffset + 5]) << 40) |
			(static_cast<ulong>(Input[InOffset + 6]) << 48) |
			(static_cast<ulong>(Input[InOffset + 7]) << 56);
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 64-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Length">The number of input bytes to use</param>
	///
	/// <returns>A 64-bit word in Little Endian format</returns>
	template<typename Array>
	inline static ulong LeBytesTo64(const Array &Input, size_t InOffset, size_t Length)
	{
		size_t i;
		ulong r;

		r = Input[InOffset];

		for (i = 1; i < Length; ++i)
		{
			r |= static_cast<ulong>(Input[InOffset + i]) << (8 * i);
		}

		return r;
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 16 * 32bit word vector
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 32bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToUL512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a byte vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint), "Output must be a 32bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint) >= 64, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
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
	/// Convert a byte vector to a Little Endian 4 * 64bit word vector
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a byte vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(ulong), "Output must be a 64bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 32, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 32, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 32);
#else
		Output[OutOffset] = LeBytesTo64(Input, InOffset);
		Output[OutOffset + 1] = LeBytesTo64(Input, InOffset + 8);
		Output[OutOffset + 2] = LeBytesTo64(Input, InOffset + 16);
		Output[OutOffset + 3] = LeBytesTo64(Input, InOffset + 24);
#endif
	}

	/// <summary>
	/// Convert a byte vector to a Little Endian 8 * 64bit word vector
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a byte vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(ulong), "Output must be a 64bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 64, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
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
	/// Convert a byte vector to a Little Endian 16 * 64bit word vector
	/// </summary>
	/// 
	/// <param name="Input">The source byte vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL1024(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a byte vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(ulong), "Output must be a 64bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 128, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ulong) >= 128, "Length is larger than output size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, 64);
		MemoryTools::Copy(Input, InOffset + 64, Output, OutOffset + 8, 64);
#else
		LeBytesToULL512(Input, InOffset, Output, OutOffset);
		LeBytesToULL512(Input, InOffset + 64, Output, OutOffset + 64);
#endif
	}

	/// <summary>
	/// Treats a vector as a segmented Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter vector</param>
	template <typename Array>
	inline static void LeIncrement(Array &Output)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(byte), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		size_t i;

		i = 0;

		while (i < Output.size())
		{
			++Output[i];

			if (Output[i] != 0)
			{
				break;
			}

			++i;
		}
	}

	/// <summary>
	/// Treats a byte vector as a segmented Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter byte vector</param>
	/// <param name="Length">The number of bytes to treat as a counter</param>
	template<typename Array>
	inline static void LeIncrement(Array &Output, size_t Length)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(byte), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Length != 0, "Length can not be zero");

		size_t i;

		i = 0;

		while (i < Length)
		{
			++Output[i];

			if (Output[i] != 0)
			{
				break;
			}

			++i;
		}
	}

	/// <summary>
	/// Increment an 8-bit integer vector by the value, treating the vector as a segmented large Little Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename Array, typename T>
	inline static void LeIncrease8(Array &Output, T Value)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte odst;
		byte osrc;
		byte ndst;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = 0;

		while (lctr != Output.size())
		{
			odst = Output[lctr];
			osrc = (lctr < cinc.size() ? cinc[lctr] : 0x00);
			ndst = static_cast<byte>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
			++lctr;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Little Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, T Value)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(byte), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(byte), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte odst;
		byte osrc;
		byte ndst;

		MemoryTools::Copy(Input, 0, Output, 0, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = 0;

		while (lctr != Input.size())
		{
			odst = Output[lctr];
			osrc = (lctr < cinc.size() ? cinc[lctr] : 0x00);
			ndst = static_cast<byte>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
			++lctr;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Little Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output byte vector</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, T Value)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Input.size();
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte odst;
		byte osrc;
		byte ndst;

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = OutOffset;

		while (lctr != MAXPOS)
		{
			odst = Output[lctr];
			osrc = ((lctr - OutOffset < cinc.size()) ? cinc[lctr - OutOffset] : 0x00);
			ndst = odst + osrc + carry;
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
			++lctr;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Little Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output byte vector</param>
	/// <param name="Output">The target output byte vector</param>
	/// <param name="Length">The number of bytes within the vector to treat as a segmented counter</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, size_t Length, const T Value)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Length;
		std::array<byte, sizeof(T)> cinc;
		size_t lctr;
		byte carry;
		byte ndst;
		byte odst;
		byte osrc;

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<byte>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = OutOffset;

		while (lctr != MAXPOS)
		{
			odst = Output[lctr];
			osrc = ((lctr - OutOffset < cinc.size()) ? cinc[lctr - OutOffset] : 0x00);
			ndst = odst + osrc + carry;
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
			++lctr;
		}
	}

	/// <summary>
	/// Treats an integer vector as a large Little Endian integer, incrementing the total value by one.
	/// <para>Uses only the first two elements of the Output vector; used by 32 or 64-bit integer types.
	/// Uses only unsigned integer types; signed types are UB.</para>
	/// </summary>
	/// 
	/// <param name="Output">The counter vector to increment</param>
	template <typename Array>
	inline static void LeIncrementW(Array &Output)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		++Output[0];

		if (Output[0] == 0)
		{
			++Output[1];
		}
	}

	/// <summary>
	/// Treats an integer vector as a large Little Endian integer, increasing the total value by a defined length.
	/// <para>Uses only unsigned integer types; signed types are UB.</para>
	/// </summary>
	/// 
	/// <param name="Output">The counter vector to increment</param>
	/// <param name="Length">The number to increase by</param>
	template <typename Array>
	inline static void LeIncreaseW(Array &Output, size_t Length)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		Output[0] += Length;

		if (Output[0] < Length)
		{
			Output[1] += 1;
		}
	}

	/// <summary>
	/// Treats an integer vector as a large Little Endian integer, increasing the total value by a defined length.
	/// <para>Uses only unsigned integer types; signed types are UB.</para>
	/// </summary>
	/// 
	/// <param name="Input">The initial vector to clone</param>
	/// <param name="Output">The incremented output vector</param>
	/// <param name="Length">The number to increase by</param>
	template <typename Array>
	inline static void LeIncreaseW(const Array &Input, Array &Output, size_t Length)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		MemoryTools::Copy(Input, 0, Output, 0, Input.size() * sizeof(Array::value_type));
		Output[0] += static_cast<Array::value_type>(Length);

		if (Output[0] < Input[0])
		{
			++Output[1];
		}
	}

	//~~~Constant Time~~~//

	/// <summary>
	/// Constant time: return the larger value of the two integers
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
	/// Constant time: conditional move
	/// </summary>
	/// 
	/// <param name="Input">The source vector</param>
	/// <param name="InOffset">The starting index in the source vector</param>
	/// <param name="Output">The destination vector</param>
	/// <param name="OutOffset">The starting index in the destination vector</param>
	/// <param name="Length">The number of elements to copy</param>
	/// <param name="Condition">The condition</param>
	template <typename Array>
	inline static void CMov(const Array &Input, size_t InOffset, Array &Output, size_t OutOffset, size_t Length, byte Condition)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(Input.size() >= Length, "Input size can not be zero");
		CEXASSERT(Output.size() >= Length, "Output size is too small");

		size_t i;

		Condition = ~Condition + 1;

		for (i = 0; i < Length; i++)
		{
			Output[OutOffset + i] ^= Condition & (Input[InOffset + i] ^ Output[OutOffset + i]);
		}
	}

	/// <summary>
	/// Constant time: return the lesser value of the two integers
	/// </summary>
	/// 
	/// <param name="A">The first value to compare</param>
	/// <param name="B">The second value to compare</param>
	/// 
	/// <returns>The lesser value</returns>
	template<typename T>
	inline static T CMin(T A, T B)
	{
		// TODO: test this..
		return Select<T>(ExpandTopBit<T>(B), B, A);
	}

	/// <summary>
	/// Constant time: value comparison between two arrays with offset and length parameters.
	/// <para>Array container types can vary (standard vector, vector, or SecureVector), but vector elements must be of equal size.</para>
	/// </summary>
	/// 
	/// <param name="A">The first vector to compare</param>
	/// <param name="AOffset">The starting offset within the 'A' vector</param>
	/// <param name="B">The second vector to compare</param>
	/// <param name="BOffset">The starting offset within the 'B' vector</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>True if arrays are equivalant</returns>
	template <typename ArrayA, typename ArrayB>
	inline static bool Compare(const ArrayA &A, size_t AOffset, const ArrayB &B, size_t BOffset, size_t Length)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(A.size() - AOffset >= Length, "Input size can not be less than length");
		CEXASSERT(B.size() - BOffset >= Length, "Output size can not be less than length");

		ArrayA::value_type delta;
		size_t i;

		delta = 0;

		for (i = 0; i < Length; ++i)
		{
			delta |= (A[AOffset + i] ^ B[BOffset + i]);
		}

		return static_cast<bool>(delta == 0);
	}

	/// <summary>
	/// Constant time: conditional bit copy
	/// </summary>
	/// 
	/// <param name="Value">The destination mask</param>
	/// <param name="To">The destination vector</param>
	/// <param name="From0">The first value to copy</param>
	/// <param name="From1">The second value to copy</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	inline static void ConditionalCopy(T Value, T* To, const T* From0, const T* From1, size_t Length)
	{
		const T MASK = ExpandMask<T>(Value);
		size_t i;

		for (i = 0; i != Length; ++i)
		{
			To[i] = Select<T>(MASK, From0[i], From1[i]);
		}
	}

	/// <summary>
	/// Constant time: conditional bit erase
	/// </summary>
	/// 
	/// <param name="Condition">The condition</param>
	/// <param name="Array">The vector to wipe</param>
	/// <param name="Length">The number of bits to copy</param>
	template<typename T>
	inline static void ConditionalZeroMem(T Condition, T* Array, size_t Length)
	{
		const T MASK = ExpandMask<T>(Condition);
		const T ZERO(0);
		size_t i;

		for (i = 0; i != Length; ++i)
		{
			Array[i] = Select<T>(MASK, ZERO, Array[i]);
		}
	}

	/// <summary>
	/// Constant time: expand an integer mask in constant time
	/// </summary>
	/// 
	/// <param name="X">The N bit word</param>
	/// 
	/// <returns>A N bit expanded word</returns>
	template<typename T>
	inline static T ExpandMask(T X)
	{
		T r;
		size_t i;

		r = X;

		// fold r down to a single bit
		for (i = 1; i != sizeof(T) * 8; i *= 2)
		{
			r |= r >> i;
		}

		r &= 1;
		r = ~(r - 1);

		return r;
	}

	/// <summary>
	/// Constant time: last bit expansion
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
	/// Constant time: comparison of two integers for equality
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
	/// Constant time: test if X is less than Y
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
	/// Constant time: test if X is less or equal to Y
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
	/// Constant time: zero value check
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
	/// Constant time: combine the bits from two integers filtered by a mask value
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
	/// Constant time: left shift a vector of integers
	/// </summary>
	/// 
	/// <param name="Input">The value vector to shift</param>
	/// <param name="Output">The output integer vector</param>
	/// 
	/// <returns>The bit count</returns>
	template <typename Array>
	inline static uint ShiftLeft(const Array &Input, Array &Output)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(byte), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		size_t ctr;
		uint bit;
		uint b;

		ctr = Input.size();
		bit = 0;

		do
		{
			--ctr;
			b = Input[ctr];
			Output[ctr] = static_cast<byte>(((b << 1) | bit));
			bit = (b >> 7) & 1;
		} 
		while (ctr > 0);

		return bit;
	}

	/// <summary>
	/// Constant time: select an integer based on a mask
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
	/// Constant time: value comparison between two arrays with offset and length parameters.
	/// <para>Array container types can vary (standard vector, vector, or SecureVector), but vector elements must be of equal size.</para>
	/// </summary>
	/// 
	/// <param name="A">The first vector to compare</param>
	/// <param name="B">The second vector to compare</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>A positive integer for each different value, or zero if the arrays are identical</returns>
	template <typename ArrayA, typename ArrayB>
	inline static size_t Verify(const ArrayA &A, const ArrayB &B, size_t Length)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(A.size() >= Length, "Input size can not be less than length");
		CEXASSERT(B.size() >= Length, "Output size can not be less than length");

		size_t delta;
		size_t i;

		delta = 0;

		for (i = 0; i < Length; ++i)
		{
			delta |= (A[i] ^ B[i]);
		}

		return delta;
	}

	//~~~Rotate~~~//

#if defined(CEX_HAS_MINSSE) && defined(CEX_FASTROTATE_ENABLED)
#	pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotFL32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return _lrotl(Value, static_cast<int>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static ulong RotFL64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return _rotl64(Value, static_cast<int>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint RotFR32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return _lrotr(Value, static_cast<int>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64-bit integer</returns>
	inline static ulong RotFR64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return _rotr64(Value, static_cast<int>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotL32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return Shift ? _rotl(Value, static_cast<int>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static ulong RotL64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return Shift ? _rotl64(Value, static_cast<int>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift a 32-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint RotR32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return Shift ? _rotr(Value, static_cast<int>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static ulong RotR64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return Shift ? _rotr64(Value, static_cast<int>(Shift)) : Value;
	}

#else

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotFL32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static ulong RotFL64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> (64 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint RotFR32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return (Value >> Shift) | (Value << (32 - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64-bit integer</returns>
	inline static ulong RotFR64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return ((Value >> Shift) | (Value << (64 - Shift)));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint RotL32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> ((sizeof(uint) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static ulong RotL64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> ((sizeof(ulong) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift a 32-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint RotR32(uint Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(uint) * 8, "Shift size is too large");

		return (Value >> Shift) | (Value << ((sizeof(uint) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static ulong RotR64(ulong Value, uint Shift)
	{
		CEXASSERT(Shift <= sizeof(ulong) * 8, "Shift size is too large");

		return (Value >> Shift) | (Value << ((sizeof(ulong) * 8) - Shift));
	}

#endif
};

NAMESPACE_UTILITYEND
#endif

