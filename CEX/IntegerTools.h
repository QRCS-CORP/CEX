// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

NAMESPACE_TOOLS

using Tools::MemoryTools;

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
			static void* (*const volatile pmemset)(void*, int32_t, size_t) = std::memset;
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
		CEXASSERT(Output.size() - Offset <= Elements, "The output vector is too int16_t");

		const size_t BUFLEN = Elements * sizeof(Array::value_type);
		std::vector<uint8_t> buf(BUFLEN);
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
		CEXASSERT(Output.size() - Offset <= Elements, "The output vector is too int16_t");

		const size_t BUFLEN = Elements * sizeof(Array::value_type);
		std::vector<uint8_t> buf(BUFLEN);
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
	/// <returns>The extracted uint8_t</returns>
	template<typename T> 
	inline static uint8_t GetByte(T Value, size_t Index)
	{
		return static_cast<uint8_t>(Value >> (((~Index)&(sizeof(T) - 1)) << 3));
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
	inline static uint64_t Crop(uint64_t Value, size_t Length)
	{
		uint64_t ret;

		if (Length < 8 * sizeof(Value))
		{
			ret = (Value & ((1ULL << Length) - 1ULL));
		}
		else
		{
			ret = Value;
		}

		return ret;
	}

	/// <summary>
	/// Copies a string to a uint8_t vector.
	/// <para>The output from this function is endian dependant.</para>
	/// </summary>
	/// 
	/// <param name="Input">The string to copy</param>
	/// 
	/// <returns>The uint8_t vector containing the string values</returns>
	inline static std::vector<uint8_t> FromString(std::string &Input)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");

		std::vector<uint8_t> otp(Input.size());
		std::memcpy(otp.data(), Input.data(), Input.size());

		return otp;
	}

	/// <summary>
	/// Convert a string to a value of T
	/// </summary>
	/// 
	/// <param name="Input">The value string</param>
	/// <param name="Offset">The starting offset within the string</param>
	/// <param name="Length">The number of string characters to read</param>
	/// 
	/// <returns>The integer value</returns>
	template <typename T>
	static T FromString(std::string &Input, size_t Offset, size_t Length)
	{
		CEXASSERT(Input.size() - Offset > 0, "Input size can not be zero");

		std::string sval;
		T num;

		sval = Input.substr(Offset, Length);
		num = static_cast<T>(strtol(sval.c_str(), NULL, 10));

		return num;
	}

	/// <summary>
	/// Copies a hex formatted string to a vector of bytes
	/// </summary>
	/// 
	/// <param name="Input">The string to convert</param>
	/// <param name="Length">The number of bytes to convert</param>
	/// 
	/// <returns>The hex string copied to a vector of bytes</returns>
	inline static std::vector<uint8_t> FromHex(std::string &Input, size_t Length)
	{
		CEXASSERT(Length <= Input.size(), "Length can not be longer than input");

		std::vector<uint8_t> otp;
		std::string nhex;
		size_t i;
		uint8_t num;

		for (i = 0; i < Length; i += 2)
		{
			nhex = Input.substr(i, 2);
			num = static_cast<uint8_t>(strtol(nhex.c_str(), NULL, 16));
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
	static uint64_t Parity(uint64_t Value)
	{
		size_t i;

		for (i = (8 * sizeof(Value)) / 2; i > 0; i /= 2)
		{
			Value ^= Value >> i;
		}

		return Value & 1;
	}

	template <class T1, class T2>
	inline static T1 SaturatingSubtract(const T1 &A, const T2 &B)
	{
		return T1((A > B) ? (A - B) : 0);
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
	static std::string ToHex(Array &Input, size_t Offset, size_t Length)
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
	static std::string ToHex(T Value)
	{
		std::stringstream ss;
		ss << std::hex << std::uppercase;
		ss << Value;

		return ss.str();
	}

	/// <summary>
	/// Convert a hexadecimal string to a value of T
	/// </summary>
	/// 
	/// <param name="Input">The hexadecimal string</param>
	/// <param name="Offset">The starting offset within the hexadecimal string</param>
	/// 
	/// <returns>The integer value</returns>
	template <typename T>
	static T HexToInt(std::string &Input, size_t Offset)
	{
		CEXASSERT(Input.size() - Offset >= sizeof(T), "Length can not be longer than input");

		const size_t INTLEN = sizeof(T) * 2;
		std::string nhex;
		T num;

		nhex = Input.substr(Offset, INTLEN);
		num = static_cast<T>(strtol(nhex.c_str(), NULL, 16));

		return num;
	}

	/// <summary>
	/// Convert an integer of type T to a hexadecimal string
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	/// 
	/// <returns>The hexidecimal string</returns>
	template <typename T>
	static std::string IntToHex(T Value)
	{
		const char* digits = "0123456789ABCDEF";
		const size_t HEXLEN = sizeof(T) << 1;
		size_t idx;
		size_t i;
		size_t j;

		std::string rc(HEXLEN, '0');

		for (i = 0, j = (HEXLEN - 1) * 4; i < HEXLEN; ++i, j -= 4)
		{
			idx = (Value >> j) & 0x0F;
			rc[i] = digits[idx];
		}

		return rc;
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

	// Different computer architectures store data using different uint8_t orders. "Big-endian"
	// means the most significant uint8_t is on the left end of a word. "Little-endian" means the 
	// most significant uint8_t is on the right end of a word. i.e.: 
	// BE: uint32_t(block[3]) | (uint32_t(block[2]) << 8) | (uint32_t(block[1]) << 16) | (uint32_t(block[0]) << 24)
	// LE: uint32_t(block[0]) | (uint32_t(block[1]) << 8) | (uint32_t(block[2]) << 16) | (uint32_t(block[3]) << 24)

	//~~~Big Endian~~~//

	/// <summary>
	/// Run time check for Little Endian uint8_t order
	/// </summary>
	inline static bool IsBigEndian()
	{
		int32_t num;
		bool ret;

		num = 1;
		ret = (num >> 24) == 1;

		return ret;
	}

	/// <summary>
	/// Convert 8-bit uint8_t vector to a Big Endian integer vector
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
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
				Output[OutOffset + i] |= static_cast<typename ArrayB::value_type>(Input[InOffset + (i * VARLEN) + (VARLEN - j)]) << (8 * (j - 1));
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian integer vector to a uint8_t vector.
	/// </summary>
	/// 
	/// <param name="Input">The integer input vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
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
				Output[OutOffset + (i * VARLEN) + (j - 1)] = static_cast<typename ArrayB::value_type>(Input[InOffset + i] >> ((VARLEN - j) * 8));
			}
		}
#endif
	}

	/// <summary>
	/// Convert a Big Endian 16-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be16ToBytes(uint16_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint16_t), "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint16_t));
#else
		Output[OutOffset + 1] = static_cast<uint8_t>(Value);
		Output[OutOffset] = static_cast<uint8_t>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 16-bit word to uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be16ToBytes(uint16_t Value)
	{
		Array otp(sizeof(uint16_t));

		Be16ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Big Endian 16-bit word to uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Be16ToBytesRaw(uint16_t Value, uint8_t* Output)
	{
#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint16_t));
#else
		Output[1] = static_cast<uint8_t>(Value);
		Output[0] = static_cast<uint8_t>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 32-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be32ToBytes(uint32_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint32_t), "Length is larger than output size");

#if defined IS_BIG_ENDIAN
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint32_t));
#else
		Output[OutOffset + 3] = static_cast<uint8_t>(Value);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset] = static_cast<uint8_t>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 32-bit word to uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be32ToBytes(uint32_t Value)
	{
		Array otp(sizeof(uint32_t));

		Be32ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Big Endian 32-bit word to uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Be32ToBytesRaw(uint32_t Value, uint8_t* Output)
	{
#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint32_t));
#else
		Output[3] = static_cast<uint8_t>(Value);
		Output[2] = static_cast<uint8_t>(Value >> 8);
		Output[1] = static_cast<uint8_t>(Value >> 16);
		Output[0] = static_cast<uint8_t>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 64-bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit word</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Be64ToBytes(uint64_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint64_t), "Length is larger than output size");

#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint64_t));
#else
		Output[OutOffset + 7] = static_cast<uint8_t>(Value);
		Output[OutOffset + 6] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 5] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset + 4] = static_cast<uint8_t>(Value >> 24);
		Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 32);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 40);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 48);
		Output[OutOffset] = static_cast<uint8_t>(Value >> 56);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 64-bit dword to uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	///
	/// <returns>A vector of bytes in Big Endian order</returns>
	template<typename Array>
	inline static Array Be64ToBytes(uint64_t Value)
	{
		Array otp(sizeof(uint64_t));

		Be64ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Big Endian 64-bit word to uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Be64ToBytesRaw(uint64_t Value, uint8_t* Output)
	{
#if defined(IS_BIG_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint64_t));
#else
		Output[7] = static_cast<uint8_t>(Value);
		Output[6] = static_cast<uint8_t>(Value >> 8);
		Output[5] = static_cast<uint8_t>(Value >> 16);
		Output[4] = static_cast<uint8_t>(Value >> 24);
		Output[3] = static_cast<uint8_t>(Value >> 32);
		Output[2] = static_cast<uint8_t>(Value >> 40);
		Output[1] = static_cast<uint8_t>(Value >> 48);
		Output[0] = static_cast<uint8_t>(Value >> 56);
#endif
	}

	/// <summary>
	/// Convert a Big Endian 8 * 32bit word vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 32bit integer source vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BeUL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(Input.size() - InOffset >= 32 / sizeof(uint32_t), "Length is larger than input size");
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
	/// Convert a Big Endian 8 * 64bit word vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer source vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void BeULL512ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(Input.size() - InOffset >= 64 / sizeof(uint64_t), "Length is larger than input size");
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
	/// Convert a uint8_t vector to a Big Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 16-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static uint16_t BeBytesTo16(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint16_t), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		uint16_t value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(uint16_t));
		return value;
#else
		return
			(static_cast<uint16_t>(Input[InOffset]) << 8) |
			(static_cast<uint16_t>(Input[InOffset + 1]));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Big Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 16-bit integer in Big Endian format</returns>
	inline static uint16_t BeBytesTo16Raw(const uint8_t* Input)
	{
#if defined(IS_BIG_ENDIAN)
		uint16_t value = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&Value, sizeof(uint16_t));
		return value;
#else
		return
			(static_cast<uint16_t>(Input[0]) << 8) |
			(static_cast<uint16_t>(Input[1]));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Big Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 32-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static uint32_t BeBytesTo32(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint32_t), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		uint32_t value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(uint32_t));

		return value;
#else
		return
			(static_cast<uint32_t>(Input[InOffset]) << 24) |
			(static_cast<uint32_t>(Input[InOffset + 1]) << 16) |
			(static_cast<uint32_t>(Input[InOffset + 2]) << 8) |
			(static_cast<uint32_t>(Input[InOffset + 3]));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Big Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 32-bit integer in Big Endian format</returns>
	inline static uint32_t BeBytesTo32Raw(const uint8_t* Input)
	{
#if defined(IS_BIG_ENDIAN)
		uint32_t value = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&Value, sizeof(uint32_t));
		return value;
#else
		return
			(static_cast<uint32_t>(Input[0]) << 24) |
			(static_cast<uint32_t>(Input[1]) << 16) |
			(static_cast<uint32_t>(Input[2]) << 8) |
			(static_cast<uint32_t>(Input[3]));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Big Endian 64-bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 64-bit integer in Big Endian format</returns>
	template<typename Array>
	inline static uint64_t BeBytesTo64(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint64_t), "Length is larger than input size");

#if defined(IS_BIG_ENDIAN)
		uint64_t value = 0;
		MemoryTools::CopyToValue(Input, InOffset, value, sizeof(uint64_t));
		return value;
#else
		return
			(static_cast<uint64_t>(Input[InOffset]) << 56) |
			(static_cast<uint64_t>(Input[InOffset + 1]) << 48) |
			(static_cast<uint64_t>(Input[InOffset + 2]) << 40) |
			(static_cast<uint64_t>(Input[InOffset + 3]) << 32) |
			(static_cast<uint64_t>(Input[InOffset + 4]) << 24) |
			(static_cast<uint64_t>(Input[InOffset + 5]) << 16) |
			(static_cast<uint64_t>(Input[InOffset + 6]) << 8) |
			(static_cast<uint64_t>(Input[InOffset + 7]));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Big Endian 64-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 64-bit integer in Big Endian format</returns>
	inline static uint64_t BeBytesTo64Raw(const uint8_t* Input)
	{
#if defined(IS_BIG_ENDIAN)
		uint64_t value = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&Value, sizeof(uint64_t));
		return value;
#else
		return
			(static_cast<uint64_t>(Input[0]) << 56) |
			(static_cast<uint64_t>(Input[1]) << 48) |
			(static_cast<uint64_t>(Input[2]) << 40) |
			(static_cast<uint64_t>(Input[3]) << 32) |
			(static_cast<uint64_t>(Input[4]) << 24) |
			(static_cast<uint64_t>(Input[5]) << 16) |
			(static_cast<uint64_t>(Input[6]) << 8) |
			(static_cast<uint64_t>(Input[7]));
#endif
	}

	/// <summary>
	/// Treats a uint8_t vector as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter uint8_t vector</param>
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
	/// Treats a uint8_t vector as a large Big Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter uint8_t vector</param>
	/// <param name="Offset">The starting offset withing the vector</param>
	/// <param name="Length">The number of uint8_t vector elements to process</param>
	template<typename Array>
	inline static void BeIncrement8(Array &Output, size_t Offset, size_t Length)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(uint8_t), "Output must be a vector of 8-bit integers");
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
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename Array, typename T>
	inline static void BeIncrease8(Array &Output, T Value)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		const size_t MAXPOS = Output.size() - 1;
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t ndst;
		uint8_t odst;
		uint8_t osrc;
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void BeIncrease8(const ArrayA &Input, ArrayB &Output, T Value)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint8_t), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = Input.size() - 1;
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t ndst;
		uint8_t odst;
		uint8_t osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
			ndst = static_cast<uint8_t>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output uint8_t vector</param>
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void BeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, T Value)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() - OutOffset >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Input.size() - 1;
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t ndst;
		uint8_t odst;
		uint8_t osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
			ndst = static_cast<uint8_t>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	/// <summary>
	/// Copy an 8-bit integer vector, and then increment it by the value, treating the vector as a segmented large Big Endian integer counter.
	/// <para>The value type can be a 16, 32, or 64-bit integer.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output uint8_t vector</param>
	/// <param name="Output">The target output uint8_t vector</param>
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
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t ndst;
		uint8_t odst;
		uint8_t osrc;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
			ndst = static_cast<uint8_t>(odst + osrc + carry);
			carry = ndst < odst ? 1 : 0;
			Output[lctr] = ndst;
		}
	}

	//~~~Little Endian~~~//

	/// <summary>
	/// Run time check for Little Endian uint8_t order
	/// </summary>
	inline static bool IsLittleEndian()
	{
		int32_t num;
		bool ret;

		num = 1;
		ret = (num >> 24) != 1;

		return ret;
	}

	/// <summary>
	/// Convert a Little Endian N * 8-bit word vector to an unsigned integer vector.
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
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
	/// Convert a Little Endian unsigned integer vector to a uint8_t vector.
	/// </summary>
	/// 
	/// <param name="Input">The source integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
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
	/// <param name="Value">The 16-bit integer</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le16ToBytes(uint16_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint16_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint16_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 16-bit word to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le16ToBytes(uint16_t Value)
	{
		Array otp(sizeof(uint16_t));

		Le16ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 16-bit word to a uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 16-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Le16ToBytesRaw(uint16_t Value, uint8_t* Output)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint16_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 32-bit word to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le32ToBytes(uint32_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint32_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint32_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 32-bit word to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le32ToBytes(uint32_t Value)
	{
		Array otp(sizeof(uint32_t));

		Le32ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 32-bit word to a uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 32-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Le32ToBytesRaw(uint32_t Value, uint8_t* Output)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint32_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 64-bit dword to bytes
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename Array>
	inline static void Le64ToBytes(uint64_t Value, Array &Output, size_t OutOffset)
	{
		CEXASSERT(Output.size() - OutOffset >= sizeof(uint64_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyFromValue(Value, Output, OutOffset, sizeof(uint64_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
		Output[OutOffset + 4] = static_cast<uint8_t>(Value >> 32);
		Output[OutOffset + 5] = static_cast<uint8_t>(Value >> 40);
		Output[OutOffset + 6] = static_cast<uint8_t>(Value >> 48);
		Output[OutOffset + 7] = static_cast<uint8_t>(Value >> 56);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 64-bit dword to uint8_t vector
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	///
	/// <returns>A vector of bytes in Little Endian order</returns>
	template<typename Array>
	inline static Array Le64ToBytes(uint64_t Value)
	{
		Array otp(sizeof(uint64_t));

		Le64ToBytes(Value, otp, 0);

		return otp;
	}

	/// <summary>
	/// Convert a Little Endian 64-bit word to a uint8_t array
	/// </summary>
	/// 
	/// <param name="Value">The 64-bit integer</param>
	/// <param name="Output">The output array</param>
	inline static void Le64ToBytesRaw(uint64_t Value, uint8_t* Output)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::CopyRaw((uint8_t*)&Value, Output, sizeof(uint64_t));
#else
		Output[OutOffset] = static_cast<uint8_t>(Value);
		Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
		Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
		Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
#endif
	}

	/// <summary>
	/// Convert a Little Endian 8 * 32bit word vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 32bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeUL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint32_t), "Input must be a 32bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a uint8_t vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(uint32_t) >= 32, "Length is larger than input size");
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
	/// Convert a Little Endian 4 * 64bit dword vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL256ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint64_t), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a uint8_t vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(uint64_t) >= 32, "Length is larger than input size");
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
	/// Convert a Little Endian 8 * 64bit dword vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL512ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint64_t), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a uint8_t vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(uint64_t) >= 64, "Length is larger than input size");
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
	/// Convert a Little Endian 16 * 64bit dword vector to a uint8_t vector
	/// </summary>
	/// 
	/// <param name="Input">The 64bit integer vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination uint8_t vector</param>
	/// <param name="OutOffset">The starting offset within the destination vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeULL1024ToBlock(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint64_t), "Input must be a 64bit integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a uint8_t vector");
		CEXASSERT((Input.size() - InOffset) * sizeof(uint64_t) >= 128, "Length is larger than input size");
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
	/// Convert a uint8_t vector to a Little Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 16-bit integer in Little Endian format</returns>
	template<typename Array>
	inline static uint16_t LeBytesTo16(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint16_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		uint16_t val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint16_t));

		return val;
#else
		return
			(static_cast<uint16_t>(Input[InOffset]) |
			(static_cast<uint16_t>(Input[InOffset + 1]) << 8));
#endif
	}

	/// <summary>
	/// Convert a uint8_t array to a Little Endian 16-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 16-bit integer in Little Endian format</returns>
	inline static uint16_t LeBytesTo16Raw(const uint8_t* Input)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		uint16_t val;

		val = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&val, sizeof(uint16_t));

		return val;
#else
		return
			(static_cast<uint16_t>(Input[InOffset]) |
			(static_cast<uint16_t>(Input[InOffset + 1]) << 8));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Little Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 32-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint32_t LeBytesTo32(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint32_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		uint32_t val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint32_t));

		return val;
#else
		return
			(static_cast<uint32_t>(Input[InOffset]) |
			(static_cast<uint32_t>(Input[InOffset + 1]) << 8) |
			(static_cast<uint32_t>(Input[InOffset + 2]) << 16) |
			(static_cast<uint32_t>(Input[InOffset + 3]) << 24));
#endif
	}

	/// <summary>
	/// Convert a uint8_t array to a Little Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 32-bit integer in Little Endian format</returns>
	inline static uint32_t LeBytesTo32Raw(const uint8_t* Input)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		uint32_t val;

		val = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&val, sizeof(uint32_t));

		return val;
#else
		return
			(static_cast<uint32_t>(Input[InOffset]) |
			(static_cast<uint32_t>(Input[InOffset + 1]) << 8) |
			(static_cast<uint32_t>(Input[InOffset + 2]) << 16) |
			(static_cast<uint32_t>(Input[InOffset + 3]) << 24));
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Little Endian 32-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Length">The number of input bytes to use</param>
	///
	/// <returns>A 32-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint32_t LeBytesTo32(const Array &Input, size_t InOffset, size_t Length)
	{
		size_t i;
		uint32_t r;

		r = Input[InOffset];

		for (i = 1; i < Length; ++i)
		{
			r |= static_cast<uint32_t>(Input[InOffset + i]) << (8 * i);
		}

		return r;
	}

	/// <summary>
	/// Convert a uint8_t vector to a Little Endian 64-bit dword
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	///
	/// <returns>A 64-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint64_t LeBytesTo64(const Array &Input, size_t InOffset)
	{
		CEXASSERT(Input.size() - InOffset >= sizeof(uint64_t), "Length is larger than input size");

#if defined(CEX_IS_LITTLE_ENDIAN)
		uint64_t val;

		val = 0;
		MemoryTools::CopyToValue(Input, InOffset, val, sizeof(uint64_t));

		return val;
#else
		return
			(static_cast<uint64_t>(Input[InOffset])) |
			(static_cast<uint64_t>(Input[InOffset + 1]) << 8) |
			(static_cast<uint64_t>(Input[InOffset + 2]) << 16) |
			(static_cast<uint64_t>(Input[InOffset + 3]) << 24) |
			(static_cast<uint64_t>(Input[InOffset + 4]) << 32) |
			(static_cast<uint64_t>(Input[InOffset + 5]) << 40) |
			(static_cast<uint64_t>(Input[InOffset + 6]) << 48) |
			(static_cast<uint64_t>(Input[InOffset + 7]) << 56);
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Little Endian 64-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Length">The number of input bytes to use</param>
	///
	/// <returns>A 64-bit word in Little Endian format</returns>
	template<typename Array>
	inline static uint64_t LeBytesTo64(const Array &Input, size_t InOffset, size_t Length)
	{
		size_t i;
		uint64_t r;

		r = Input[InOffset];

		for (i = 1; i < Length; ++i)
		{
			r |= static_cast<uint64_t>(Input[InOffset + i]) << (8 * i);
		}

		return r;
	}

	/// <summary>
	/// Convert a uint8_t array to a Little Endian 64-bit word
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t array</param>
	///
	/// <returns>A 64-bit integer in Little Endian format</returns>
	inline static uint64_t LeBytesTo64Raw(const uint8_t* Input)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		uint64_t val;

		val = 0;
		MemoryTools::CopyRaw(Input, (uint8_t*)&val, sizeof(uint64_t));
		return val;
#else
		return
			(static_cast<uint64_t>(Input[InOffset])) |
			(static_cast<uint64_t>(Input[InOffset + 1]) << 8) |
			(static_cast<uint64_t>(Input[InOffset + 2]) << 16) |
			(static_cast<uint64_t>(Input[InOffset + 3]) << 24) |
			(static_cast<uint64_t>(Input[InOffset + 4]) << 32) |
			(static_cast<uint64_t>(Input[InOffset + 5]) << 40) |
			(static_cast<uint64_t>(Input[InOffset + 6]) << 48) |
			(static_cast<uint64_t>(Input[InOffset + 7]) << 56);
#endif
	}

	/// <summary>
	/// Convert a uint8_t vector to a Little Endian 16 * 32bit word vector
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 32bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToUL512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(Input.size() - InOffset >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint32_t) >= 64, "Length is larger than output size");

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
	/// Convert a uint8_t vector to a Little Endian 4 * 64bit dword vector
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint8_t), "Input must be a uint8_t vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint64_t), "Output must be a 64bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 32, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint64_t) >= 32, "Length is larger than output size");

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
	/// Convert a uint8_t vector to a Little Endian 8 * 64bit dword vector
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint8_t), "Input must be a uint8_t vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint64_t), "Output must be a 64bit integer vector");
		CEXASSERT(Input.size() - InOffset >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint64_t) >= 64, "Length is larger than output size");

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
	/// Convert a uint8_t vector to a Little Endian 16 * 64bit dword vector
	/// </summary>
	/// 
	/// <param name="Input">The source uint8_t vector</param>
	/// <param name="InOffset">The starting offset within the source vector</param>
	/// <param name="Output">The destination 64bit integer vector</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	template<typename ArrayA, typename ArrayB>
	inline static void LeBytesToULL1024(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		CEXASSERT(Input.size() - InOffset >= 128, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(uint64_t) >= 128, "Length is larger than output size");

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
		CEXASSERT(sizeof(Array::value_type) == sizeof(uint8_t), "Output must be a vector of 8-bit integers");
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
	/// Treats a uint8_t vector as a segmented Little Endian integer, incrementing the total value by one
	/// </summary>
	/// 
	/// <param name="Output">The counter uint8_t vector</param>
	/// <param name="Length">The number of bytes to treat as a counter</param>
	template<typename Array>
	inline static void LeIncrement(Array &Output, size_t Length)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(uint8_t), "Output must be a vector of 8-bit integers");
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
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename Array, typename T>
	inline static void LeIncrease8(Array &Output, T Value)
	{
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Output.size() != 0, "Output size can not be zero");

		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t odst;
		uint8_t osrc;
		uint8_t ndst;

		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = 0;

		while (lctr != Output.size())
		{
			odst = Output[lctr];
			osrc = (lctr < cinc.size() ? cinc[lctr] : 0x00);
			ndst = static_cast<uint8_t>(odst + osrc + carry);
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
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, T Value)
	{
		CEXASSERT(sizeof(ArrayA::value_type) == sizeof(uint8_t), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(sizeof(ArrayB::value_type) == sizeof(uint8_t), "Output must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<ArrayB::value_type>::value, "Output must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t odst;
		uint8_t osrc;
		uint8_t ndst;

		MemoryTools::Copy(Input, 0, Output, 0, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
			++lctr;
		}

		carry = 0;
		lctr = 0;

		while (lctr != Input.size())
		{
			odst = Output[lctr];
			osrc = (lctr < cinc.size() ? cinc[lctr] : 0x00);
			ndst = static_cast<uint8_t>(odst + osrc + carry);
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
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output uint8_t vector</param>
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, T Value)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Input.size();
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t odst;
		uint8_t osrc;
		uint8_t ndst;

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
	/// <param name="Input">The input uint8_t vector to copy</param>
	/// <param name="OutOffset">The starting offset within the output uint8_t vector</param>
	/// <param name="Output">The target output uint8_t vector</param>
	/// <param name="Length">The number of bytes within the vector to treat as a segmented counter</param>
	/// <param name="Value">The T value number to increase by</param>
	template <typename ArrayA, typename ArrayB, typename T>
	inline static void LeIncrease8(const ArrayA &Input, ArrayB &Output, size_t OutOffset, size_t Length, const T Value)
	{
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		const size_t MAXPOS = OutOffset + Length;
		std::array<uint8_t, sizeof(T)> cinc = { 0 };
		size_t lctr;
		uint8_t carry;
		uint8_t ndst;
		uint8_t odst;
		uint8_t osrc;

		MemoryTools::Copy(Input, 0, Output, OutOffset, Input.size());
		lctr = 0;

		while (lctr != sizeof(T))
		{
			cinc[lctr] = static_cast<uint8_t>(Value >> (lctr * 8));
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
			++Output[1];
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
	template <typename ArrayA, typename ArrayB>
	inline static void LeIncreaseW(const ArrayA &Input, ArrayB &Output, size_t Length)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		MemoryTools::Copy(Input, 0, Output, 0, Input.size() * sizeof(ArrayA::value_type));
		Output[0] += static_cast<typename ArrayA::value_type>(Length);

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
	inline static void CMov(const Array &Input, size_t InOffset, Array &Output, size_t OutOffset, size_t Length, uint8_t Condition)
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
	/// Constant time: conditional move on a raw uint8_t array
	/// </summary>
	/// 
	/// <param name="Input">The source array</param>
	/// <param name="Output">The destination array</param>
	/// <param name="Length">The number of elements to copy</param>
	/// <param name="Condition">The condition</param>
	inline static void CMovRaw(const uint8_t* Input, uint8_t* Output, size_t Length, uint8_t Condition)
	{
		size_t i;

		Condition = ~Condition + 1;

		for (i = 0; i < Length; i++)
		{
			Output[i] ^= Condition & (Input[i] ^ Output[i]);
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

		typename ArrayA::value_type delta;
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
	inline static void ConditionalZeroMem(T Condition, std::vector<T> &Array, size_t Length)
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
	/// Constant time: compare two integer arrays for equality in constant time
	/// </summary>
	/// 
	/// <param name="A">The base array</param>
	/// <param name="B">The comparison array</param>
	/// <param name="Length">The number of integers to compare</param>
	/// 
	/// <returns>Returns zero if the arrays match, else -1</returns>
	template<typename T>
	inline static int32_t DiffMask(const std::vector<T> &A, const std::vector<T> &B, size_t Length)
	{
		// 
		size_t i;
		uint16_t diff;

		diff = 0;

		for (i = 0; i < Length; ++i)
		{
			diff |= A[i] ^ B[i];
		}

		return (1 & ((diff - 1) >> 8)) - 1;
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
	inline static uint32_t ShiftLeft(const Array &Input, Array &Output)
	{
		CEXASSERT(sizeof(Array::value_type) == sizeof(uint8_t), "Input must be a vector of 8-bit integers");
		CEXASSERT(!std::is_signed<Array::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(Input.size() != 0, "Input size can not be zero");
		CEXASSERT(Output.size() >= Input.size(), "Output size is too small");

		size_t ctr;
		uint32_t bit;
		uint32_t b;

		ctr = Input.size();
		bit = 0;

		do
		{
			--ctr;
			b = Input[ctr];
			Output[ctr] = static_cast<uint8_t>(((b << 1) | bit));
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
	/// Constant time: value comparison between two arrays with a length parameter.
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

	/// <summary>
	/// Constant time: value comparison between two arrays with offset and length parameters.
	/// <para>Array container types can vary (standard vector, vector, or SecureVector), but vector elements must be of equal size.</para>
	/// </summary>
	/// 
	/// <param name="A">The first vector to compare</param>
	/// <param name="AOffset">The starting offset in the first vector</param>
	/// <param name="B">The second vector to compare</param>
	/// <param name="BOffset">The starting offset in the second vector</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>A positive integer for each different value, or zero if the arrays are identical</returns>
	template <typename ArrayA, typename ArrayB>
	inline static size_t Verify(const ArrayA &A, size_t AOffset, const ArrayB &B, size_t BOffset, size_t Length)
	{
		CEXASSERT(!std::is_signed<ArrayA::value_type>::value, "Input must be an unsigned integer vector");
		CEXASSERT(A.size() >= Length, "Input size can not be less than length");
		CEXASSERT(B.size() >= Length, "Output size can not be less than length");

		size_t delta;
		size_t i;

		delta = 0;

		for (i = 0; i < Length; ++i)
		{
			delta |= (A[AOffset + i] ^ B[BOffset + i]);
		}

		return delta;
	}

	/// <summary>
	/// Constant time: value comparison between two uint8_t arrays with a length parameter.
	/// <para>Array container types can vary (standard vector, vector, or SecureVector), but vector elements must be of equal size.</para>
	/// </summary>
	/// 
	/// <param name="A">The first vector to compare</param>
	/// <param name="B">The second vector to compare</param>
	/// <param name="Length">The number of elements to compare</param>
	/// 
	/// <returns>A positive integer for each different value, or zero if the arrays are identical</returns>
	inline static size_t VerifyRaw(const uint8_t* A, const uint8_t* B, size_t Length)
	{
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
	inline static uint32_t RotFL32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return _lrotl(Value, static_cast<int32_t>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint64_t RotFL64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return _rotl64(Value, static_cast<int32_t>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint32_t RotFR32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return _lrotr(Value, static_cast<int32_t>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right by a positive fixed non-zero increment
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
	/// 
	/// <returns>The right shifted 64-bit integer</returns>
	inline static uint64_t RotFR64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return _rotr64(Value, static_cast<int32_t>(Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 32-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint32_t RotL32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return (Shift != 0) ? _rotl(Value, static_cast<int32_t>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint64_t RotL64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return (Shift != 0) ? _rotl64(Value, static_cast<int32_t>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift a 32-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint32_t RotR32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return (Shift != 0) ? _rotr(Value, static_cast<int32_t>(Shift)) : Value;
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint64_t RotR64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return (Shift != 0) ? _rotr64(Value, static_cast<int32_t>(Shift)) : Value;
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
	inline static uint32_t RotFL32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

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
	inline static uint64_t RotFL64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

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
	inline static uint32_t RotFR32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

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
	inline static uint64_t RotFR64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

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
	inline static uint32_t RotL32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> ((sizeof(uint32_t) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the left
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The left shifted integer</returns>
	inline static uint64_t RotL64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return (Value << Shift) | (Value >> ((sizeof(uint64_t) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift a 32-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint32_t RotR32(uint32_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint32_t) * 8, "Shift size is too large");

		return (Value >> Shift) | (Value << ((sizeof(uint32_t) * 8) - Shift));
	}

	/// <summary>
	/// Rotate shift an unsigned 64-bit integer to the right
	/// </summary>
	/// 
	/// <param name="Value">The initial value</param>
	/// <param name="Shift">The number of bits to shift</param>
	/// 
	/// <returns>The right shifted integer</returns>
	inline static uint64_t RotR64(uint64_t Value, uint32_t Shift)
	{
		CEXASSERT(Shift <= sizeof(uint64_t) * 8, "Shift size is too large");

		return (Value >> Shift) | (Value << ((sizeof(uint64_t) * 8) - Shift));
	}

#endif
};

NAMESPACE_TOOLSEND
#endif

