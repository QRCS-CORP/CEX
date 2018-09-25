// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
#include "SecureRandom.h"
#include <algorithm>
#include <iterator>

NAMESPACE_UTILITY

/// <summary>
/// Array functions class
/// </summary>
class ArrayUtils
{
public:

	/// <summary>
	/// Append an integer value to an 8bit integer array
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination byte array</param>
	/// 
	/// <returns>The number of bytes added</returns>
	template <typename T>
	static size_t Append(T Value, std::vector<byte> &Output)
	{
		const size_t VARLEN = sizeof(T);
		const size_t ARRLEN = Output.size();

		Output.resize(Output.size() + VARLEN);
		std::memcpy(&Output[ARRLEN], &Value, VARLEN);

		return VARLEN;
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
	static size_t AppendString(std::string &Value, Array &Output)
	{
		const size_t STRLEN = Value.size();
		const size_t ELMLEN = sizeof(Array::value_type);

		std::vector<byte> tmp(0);
		std::transform(std::begin(Value), std::end(Value), std::back_inserter(tmp), [](char c)
		{
			return c - '0';
		});

		size_t pos = Output.size();
		Output.resize(pos + (tmp.size() / ELMLEN));

		if (tmp.size() != 0)
		{
			std::memcpy(&Output[pos], &tmp[0], tmp.size());
		}

		return STRLEN;
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
	static size_t Append(const ArrayA &Input, ArrayB &Output)
	{
		const size_t VARLEN = sizeof(ArrayA::value_type) * Input.size();
		const size_t ARRLEN = sizeof(ArrayB::value_type) * Output.size();

		if (Input.size() != 0)
		{
			Output.resize(VARLEN + ARRLEN);
			std::memcpy(&Output[ARRLEN], &Input[0], VARLEN);
		}

		return VARLEN;
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
		size_t len = strlen(reinterpret_cast<char*>(Input));
		std::string ret(reinterpret_cast<char*>(Input), len);

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
