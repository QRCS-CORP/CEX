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

#ifndef CEX_ARRAYUTILS_H
#define CEX_ARRAYUTILS_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "SecureRandom.h"
#include <algorithm>
#include <iterator>

NAMESPACE_UTILITY

using Utility::IntegerTools;
using Utility::MemoryTools;

/// <summary>
/// Array functions class
/// </summary>
class ArrayTools
{
public:

	/// <summary>
	/// Absorb a block of 8 bit bytes into a uint64 Little Endian integer array
	/// </summary>
	/// 
	/// <param name="Input">The input 8bit integer array</param>
	/// <param name="InOffset">The input arrays starting offset</param>
	/// <param name="Output">The output uint64 state array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template<typename ArrayA, typename ArrayB>
	static void AbsorbBlock8to64(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t Length)
	{
#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(Input, InOffset, Output, 0, Length);
#else
		for (size_t i = 0; i < Length / sizeof(ulong); ++i)
		{
			Output[i] ^= IntegerTools::LeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
		}
#endif
	}

	/// <summary>
	/// Append an objects memory array to an integer array
	/// </summary>
	///
	/// <param name="Input">The pointer to the object in memory</param>
	/// <param name="Output">The destination byte array</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename Pointer, typename Array>
	static size_t AppendObject(const Pointer* Input, Array &Output, size_t Length)
	{
		const size_t OTPLEN = sizeof(Array::value_type) * Output.size();

		Output.resize(OTPLEN + Length);
		MemoryTools::CopyFromObject(Input, Output, OTPLEN, Length);

		return Length;
	}

	/// <summary>
	/// Append a string to an integer array
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename Array>
	static size_t AppendString(const std::string &Value, Array &Output)
	{
		const size_t STRLEN = Value.size();
		const size_t ELMLEN = sizeof(Array::value_type);
		const size_t OTPLEN = Output.size();

		Output.resize(OTPLEN + (STRLEN / ELMLEN));

		if (STRLEN != 0)
		{
			std::memcpy(&Output[OTPLEN], Value.c_str(), STRLEN);
		}

		return STRLEN;
	}

	/// <summary>
	/// Append an integer value to an 8-bit integer array
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename T, typename Array>
	static size_t AppendValue(T Value, Array &Output)
	{
		const size_t VARLEN = sizeof(T);
		const size_t ARRLEN = Output.size() * sizeof(Array::value_type);
		const size_t OTPELM = Output.size();

		Output.resize(OTPELM + VARLEN);
		MemoryTools::CopyFromValue(Value, Output, ARRLEN, VARLEN);

		return VARLEN;
	}

	/// <summary>
	/// Append an integer array to another integer array
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename ArrayA, typename ArrayB>
	static size_t AppendVector(const ArrayA &Input, ArrayB &Output)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type) * Input.size();
		const size_t OTPLEN = sizeof(ArrayB::value_type) * Output.size();

		Output.resize(INPLEN + OTPLEN);
		MemoryTools::Copy(Input, 0, Output, OTPLEN, INPLEN);

		return 0;
	}

	/// <summary>
	/// Return true if the char array contains the value
	/// </summary>
	/// 
	/// <param name="Container">The vector array of values</param>
	/// <param name="Value">The value to find</param>
	/// 
	/// <returns>True if the value exists</returns>
	static bool Contains(const char* Container, char Value);

	/// <summary>
	/// Return true if the vector array contains the value
	/// </summary>
	/// 
	/// <param name="Container">The vector array of values</param>
	/// <param name="Value">The value to find</param>
	/// 
	/// <returns>True if the value exists</returns>
	template <typename Array, typename T>
	static bool Contains(const Array &Container, T Value)
	{
		return std::find(Container.begin(), Container.end(), Value) != Container.end();
	}

	/// <summary>
	/// Keccak common function: Left encode a value onto an array
	/// </summary>
	/// 
	/// <param name="Output">The output integer array</param>
	/// <param name="Offset">The output array starting offest</param>
	/// <param name="Value">The value to remove</param>
	/// 
	/// <returns>The number of encoded bits</returns>
	template<typename Array>
	static ulong LeftEncode(Array &Output, size_t Offset, ulong Value)
	{
		ulong i;
		ulong n;
		ulong v;

		for (v = Value, n = 0; v && (n < sizeof(ulong)); ++n, v >>= 8)
		{
		}

		if (n == 0)
		{
			n = 1;
		}

		for (i = 1; i <= n; ++i)
		{
			Output[Offset + i] = static_cast<uint8_t>(Value >> (8 * (n - i)));
		}

		Output[Offset] = static_cast<uint8_t>(n);

		return (n + 1);
	}

	/// <summary>
	/// Shuffle array values to randomly chosen positions
	/// </summary>
	/// 
	/// <param name="Output">The integer array to shuffle</param>
	template <typename Array>
	static void RandomShuffle(Array &Output)
	{
		Prng::SecureRandom rnd;
		const size_t CEIL = Output.size() - 1;

		for (size_t i = 0; i != CEIL; ++i)
		{
			uint pos = rnd.NextUInt32(0, CEIL);

			if (i != pos)
			{
				std::swap(Output[i], Output[pos]);
			}
		}
	}

	/// <summary>
	/// Remove all instances of an integer value from an array
	/// </summary>
	/// 
	/// <param name="Value">The value to remove</param>
	/// <param name="Output">The output integer array</param>
	/// 
	/// <returns>The number of integers in the new array</returns>
	template <typename T, typename Array>
	static size_t Remove(T Value, Array &Output)
	{
		std::vector<T> tmp;

		for (size_t i = 0; i < Output.size(); ++i)
		{
			if (Output[i] != Value)
			{
				tmp.push_back(Output[i]);
			}
		}

		Output = tmp;

		return tmp.size();
	}

	/// <summary>
	/// Keccak common function: Right encode a value onto an array
	/// </summary>
	/// 
	/// <param name="Output">The output integer array</param>
	/// <param name="Offset">The output array starting offest</param>
	/// <param name="Value">The value to remove</param>
	/// 
	/// <returns>The number of encoded bits</returns>
	template<typename Array>
	static ulong RightEncode(Array &Output, size_t Offset, ulong Value)
	{
		ulong i;
		ulong n;
		ulong v;

		for (v = Value, n = 0; v && (n < sizeof(ulong)); ++n, v >>= 8)
		{
		}

		if (n == 0)
		{
			n = 1;
		}

		for (i = 1; i <= n; ++i)
		{
			Output[Offset + (i - 1)] = static_cast<uint8_t>(Value >> (8 * (n - i)));
		}

		Output[Offset + n] = static_cast<uint8_t>(n);

		return n + 1;
	}

	/// <summary>
	/// Split a string into a vector of strings
	/// </summary>
	/// 
	/// <param name="Input">The string to split</param>
	/// <param name="Delimiter">The delimiting character</param>
	/// <param name="Output">The array of split strings</param>
	static void Split(const std::string &Input, char Delimiter, std::vector<std::string> &Output);

	/// <summary>
	/// Split a string into a vector of strings
	/// </summary>
	/// 
	/// <param name="Input">The string to split</param>
	/// <param name="Delimiter">The delimiting character</param>
	/// 
	/// <returns>The vector array of split strings</returns>
	static std::vector<std::string> Split(const std::string &Input, char Delimiter);

	/// <summary>
	/// Convert an integer array (C style) to an 8bit byte array
	/// </summary>
	/// 
	/// <param name="Input">The array to convert</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <returns>The vector array of bytes</returns>
	template <typename T>
	static std::vector<byte> ToByteArray(T* Input, size_t Length)
	{
		const size_t ELMLEN = sizeof(Input[0]);
		const size_t RETLEN = Length * ELMLEN;
		std::vector<byte> elems(RETLEN);

		if (Length != 0)
		{
			std::memcpy(&elems[0], &Input[0], RETLEN);
		}

		return elems;
	}

	/// <summary>
	/// Convert an integer array to a string
	/// </summary>
	/// 
	/// <param name="Input">The array to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	static std::string ToString(T* Input)
	{
		std::string ret;

		if (sizeof(T) == 1)
		{
			size_t len = strlen(reinterpret_cast<char*>(Input));
			ret = std::string(reinterpret_cast<char*>(Input), len);
		}
		else
		{
			size_t len = wcslen(reinterpret_cast<wchar_t*>(Input));
			std::wstring tmp(reinterpret_cast<wchar_t*>(Input), len);
			ret.assign(tmp.begin(), tmp.end());
		}

		return ret;
	}

	/// <summary>
	/// Convert an integer vector array to a string
	/// </summary>
	/// 
	/// <param name="Input">The vector array to convert</param>
	/// 
	/// <returns>The string representation</returns>
	template <typename T>
	static std::string ToString(const std::vector<T> &Input)
	{
		std::string ret(Input.begin(), Input.end());

		return ret;
	}
};

NAMESPACE_UTILITYEND
#endif
